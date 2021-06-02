/* MQTT Mutual Authentication Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include "esp_log.h"
#include "mqtt_client.h"

// OTA
#include "freertos/event_groups.h"

#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "nvs.h"

#include "owntest.h"
#include "MFRC522.h"

static const char *TAG = "MQTTS_EXAMPLE with OTA";
static const char *CONFIG_FIRMWARE_UPGRADE_URL =
    "https://192.168.178.123:8080/hello-world.bin.signed";

// MQTT Client Cert
extern const uint8_t client_cert_pem_start[] asm("_binary_client_crt_start");
extern const uint8_t client_cert_pem_end[] asm("_binary_client_crt_end");
// MQTT Client Key
extern const uint8_t client_key_pem_start[] asm("_binary_client_key_start");
extern const uint8_t client_key_pem_end[] asm("_binary_client_key_end");
// CA PEM
extern const uint8_t ca_cert_pem_start[] asm("_binary_ca_pem_start");
extern const uint8_t ca_cert_pem_end[] asm("_binary_ca_pem_end");
// Update Server PEM
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");
// Compiled Binary Public Key
extern const uint8_t sign_key_pem_start[] asm("_binary_sign_key_pem_start");
extern const uint8_t sign_key_pem_end[] asm("_binary_sign_key_pem_end");

static bool maybe_condition = 0;
static SemaphoreHandle_t xSemaphore = NULL;
static esp_mqtt_client_handle_t client;
static TaskHandle_t xHandle = NULL;

esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key,
                 evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;
    }
    return ESP_OK;
}

void say_hello_task(void *pvParameter) {
    ESP_LOGI(TAG, "Starting Say Hello task ...");
    ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
    int count = 0;
    char msg_buf[10];
    int msg_id;
    while (1) {
        snprintf(msg_buf, 10, "data %04d", count++);
        msg_id = esp_mqtt_client_publish(client, "/topic/qos0", msg_buf, 0, 0, 0); 
        ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
        vTaskDelay(3000 / portTICK_PERIOD_MS);
    }
}

void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    printf("%d", buffer[i]);
  }
  printf("\n");
}

void read_from_rfid(void *pvParameter) {
    ESP_LOGI(TAG, "Read from RFID task ...");
    ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
    MFRC522 mfrc;
    PCD_Init(&mfrc);

    byte RST_PIN = 3;
    byte SS_PIN = 4;

    mfrc._chipSelectPin = SS_PIN;
    mfrc._resetPowerDownPin = RST_PIN;

    while (1) {
        ESP_LOGI(TAG, "Starting Self Test");
        if (!PCD_PerformSelfTest(&mfrc)) {
            ESP_LOGI(TAG, "Self Test Failed");
        }
        if (PICC_IsNewCardPresent(&mfrc)) {
            if (PICC_ReadCardSerial(&mfrc)) {
                dump_byte_array(mfrc.uid.uidByte, mfrc.uid.size);
            }
        }
        ESP_LOGI(TAG, "read from rfid task going to sleep ");
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

void kill_and_ota_task(void *pvParameter) {
    ESP_LOGI(TAG, "Starting Kill task ...");
    ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
    TaskHandle_t* xHandle = (TaskHandle_t*) pvParameter;
    bool running = true;
    ESP_LOGI(TAG, "Maybe Condition should be 0  and is currently %d",
             maybe_condition);
    if (xSemaphore == NULL) {
        ESP_LOGI(TAG, "ERROR: Semaphore in kill task was NULL");
    } else {
        while (running) {
            if (xSemaphoreTake(xSemaphore, (TickType_t)5) == pdTRUE) {

                if (maybe_condition == 1) {
                    ESP_LOGI(TAG, "Maybe condition was 1 killing client");
                    vTaskDelete(*xHandle);
                    esp_mqtt_client_disconnect(client);
                    esp_mqtt_client_destroy(client);
                    maybe_condition = 0;
                    running = false;
                }
                if (xSemaphoreGive(xSemaphore) != pdTRUE) {
                    ESP_LOGI(TAG, "ERROR: Tried to return the Semaphore but "
                                  "couldn't this should not be possible");
                }
            }
            ESP_LOGI(TAG, "kill task going to sleep ");
            vTaskDelay(3000 / portTICK_PERIOD_MS);
        }

        ESP_LOGI(TAG, "Starting OTA example...");
        ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());

        esp_http_client_config_t config = {
            .url = CONFIG_FIRMWARE_UPGRADE_URL,
            .cert_pem = (char *)server_cert_pem_start,
            .event_handler = _http_event_handler,
            .transport_type = HTTP_TRANSPORT_OVER_SSL};

        esp_err_t ret = esp_https_ota(&config, (char *)sign_key_pem_start);
        if (ret == ESP_OK) {
            esp_restart();
        } else {
            // free(config);
            ESP_LOGE(TAG, "Firmware Upgrades Failed");
            esp_restart();
        }
        while (1) {
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
    }
}

static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event) {
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    // your_context_t *context = event->context;
    switch (event->event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        msg_id = esp_mqtt_client_subscribe(client, "/topic/qos0", 0);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);

        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        break;

    case MQTT_EVENT_SUBSCRIBED:
        /*
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        msg_id = esp_mqtt_client_publish(client, "/topic/qos0", "data", 0, 0, 0); 
        ESP_LOGI(TAG, "sent publish successful, msg_id=%d", msg_id);
        */
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        ESP_LOGI(TAG, "Maybe_Condition %d", maybe_condition);
        printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
        printf("DATA=%.*s\r\n", event->data_len, event->data);

        if (strncmp("update_now", event->data, event->data_len) == 0) {
            // simple_ota_example_task(NULL);
            // xTaskCreate(&simple_ota_example_task, "ota_example_task", 4096,
            // NULL, 5, NULL);
            while (xSemaphoreTake(xSemaphore, (TickType_t)10) != pdTRUE) {
                ESP_LOGI(TAG, "Would like to update but can't because the "
                              "semaphore isn't free");
                vTaskDelay(700 / portTICK_PERIOD_MS);
            }
            maybe_condition = 1;
            if (xSemaphoreGive(xSemaphore) != pdTRUE) {
                ESP_LOGI(TAG,
                         "ERROR in SUB HANDLER: Tried to return the Semaphore "
                         "but couldn't this should not be possible");
            }
            ESP_LOGI(TAG, "Set the condition to 1");
        }
        ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());

        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
    return ESP_OK;
}

static void mqtt_app_start(void) {

    const esp_mqtt_client_config_t mqtt_cfg = {
        .uri = "mqtts://192.168.178.123:8883",
        .event_handle = mqtt_event_handler,
        .client_cert_pem = (const char *)client_cert_pem_start,
        .client_key_pem = (const char *)client_key_pem_start,
        .cert_pem = (const char *)ca_cert_pem_start,
        .task_stack = 4096,
        .buffer_size = 256,
    };

    ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
    client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_start(client);
}

void app_main(void) {
    xSemaphore = xSemaphoreCreateBinary();
    if (xSemaphoreGive(xSemaphore) != pdTRUE) {
        ESP_LOGI(TAG, "ERROR: Tried to return the Semaphore but couldn't this "
                      "should not be possible");
    }
    ESP_LOGI(TAG, "[APP] Startup..");
    ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "[APP] IDF version: %s", esp_get_idf_version());

    esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set("MQTT_CLIENT", ESP_LOG_VERBOSE);
    esp_log_level_set("TRANSPORT_TCP", ESP_LOG_VERBOSE);
    esp_log_level_set("TRANSPORT_SSL", ESP_LOG_VERBOSE);
    esp_log_level_set("TRANSPORT", ESP_LOG_VERBOSE);
    esp_log_level_set("OUTBOX", ESP_LOG_VERBOSE);

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in
     * menuconfig. Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    owntest("bonjour");
    mqtt_app_start();
    // xTaskCreate(&simple_ota_example_task, "ota_example_task", 8192, NULL, 5,
    // NULL);
    xTaskCreate(&say_hello_task, "say_hello_task", 4096, NULL, 5, &xHandle);
    xTaskCreate(&read_from_rfid, "read_from_rfid", 4096, NULL, 5, &xHandle);
    xTaskCreate(&kill_and_ota_task, "kill_task", 8192, (void*) &xHandle, 5, NULL);
}
