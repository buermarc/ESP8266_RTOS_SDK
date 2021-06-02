// Copyright 2017-2018 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_https_ota.h>
#include <esp_ota_ops.h>
#include <esp_log.h>
#include "sdkconfig.h"

/*
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
*/

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
//#include "mbedtls/config.h"
#include "mbedtls/cipher.h"
#include "mbedtls/asn1.h"

#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"

#define OTA_BUF_SIZE    CONFIG_OTA_BUF_SIZE
#define SIGNATURE_SIZE    256
static const char *TAG = "esp_https_ota";

/*
// mbed TLS feature support 
#define MBEDTLS_PKCS1_V15

// mbed TLS modules 
#define MBEDTLS_MPI_MAX_SIZE 256
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C
*/

static void http_cleanup(esp_http_client_handle_t client)
{
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

esp_err_t esp_https_ota(const esp_http_client_config_t *config, const char* sign_key)
{
    if (!config) {
        ESP_LOGE(TAG, "esp_http_client config not found");
        return ESP_ERR_INVALID_ARG;
    }

#if !CONFIG_OTA_ALLOW_HTTP
    if (!config->cert_pem) {
        ESP_LOGE(TAG, "Server certificate not found in esp_http_client config");
        return ESP_FAIL;
    }
#endif

    esp_http_client_handle_t client = esp_http_client_init(config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialise HTTP connection");
        return ESP_FAIL;
    }

    bool _success;
    _success = (
        (esp_http_client_set_header(client, "x-ESP8266-sketch-md5", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == ESP_OK) &&
        (esp_http_client_set_header(client, "x-ESP8266-version", "VERSION_0.0.1") == ESP_OK)
    );

    if (!_success) {
        ESP_LOGE(TAG, "Error while setting advanced header configurations");
    }
    ESP_LOGE(TAG, "Sucessfully set advanced header configurations");


#if !CONFIG_OTA_ALLOW_HTTP
    if (esp_http_client_get_transport_type(client) != HTTP_TRANSPORT_OVER_SSL) {
        ESP_LOGE(TAG, "Transport is not over HTTPS");
        return ESP_FAIL;
    }
#endif

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        esp_http_client_cleanup(client);
        ESP_LOGE(TAG, "Failed to open HTTP connection: %d", err);
        return err;
    }
    esp_http_client_fetch_headers(client);

    esp_ota_handle_t update_handle = 0;
    const esp_partition_t *update_partition = NULL;
    ESP_LOGI(TAG, "Starting OTA...");
    update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "Passive OTA partition not found");
        http_cleanup(client);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
             update_partition->subtype, update_partition->address);

    err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed, error=%d", err);
        http_cleanup(client);
        return err;
    }
    ESP_LOGI(TAG, "esp_ota_begin succeeded");
    ESP_LOGI(TAG, "Please Wait. This may take time");

    esp_err_t ota_write_err = ESP_OK;
    char *upgrade_data_buf = (char *)malloc(OTA_BUF_SIZE);
    if (!upgrade_data_buf) {
        ESP_LOGE(TAG, "Couldn't allocate memory to upgrade data buffer");
        return ESP_ERR_NO_MEM;
    }
    // OTA BUF SIZE 256
    int binary_file_len = 0;

    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    unsigned char* signature = (unsigned char*) malloc(SIGNATURE_SIZE);
    if (!signature) {
        ESP_LOGE(TAG, "Couldn't allocate memory to save the signature");
        return ESP_ERR_NO_MEM;
    }

    mbedtls_md_context_t ctx;// = (mbedtls_md_context_t*) malloc(sizeof(mbedtls_md_context_t));
    //ESP_LOGI(TAG, "Before md init");
    /*
    if (!ctx) {
        ESP_LOGE(TAG, "Couldn't allocate memory for md_context");
        return ESP_ERR_NO_MEM;
    }
    */
    mbedtls_md_init(&ctx);
    //ESP_LOGI(TAG, "After md init");
    int rt = mbedtls_md_setup(&ctx, mdinfo, 0);
    if (rt != 0) {
        ESP_LOGI(TAG, "failed to setup message digest err: %d", rt);
    }
    rt = mbedtls_md_starts(&ctx);
    if (rt != 0) {
        ESP_LOGI(TAG, "failed to start message digest err: %d", rt);
    }

    while (1) {
        int data_read = esp_http_client_read(client, upgrade_data_buf, OTA_BUF_SIZE);
        if (data_read == 0) {
            ESP_LOGI(TAG, "Connection closed,all data received");
            break;
        }
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: SSL data read error");
            break;
        }
        if (data_read > 0) {
            // The first 512 bytes should be the signature
            if (binary_file_len < SIGNATURE_SIZE) {
                if (binary_file_len + data_read > SIGNATURE_SIZE) {
                    // Copy before 512 to signature
                    memcpy(signature + binary_file_len, upgrade_data_buf, SIGNATURE_SIZE - binary_file_len);
                    // Write after 512 to flash for update
                    ota_write_err = esp_ota_write( 
                            update_handle, 
                            (const void *)upgrade_data_buf + (SIGNATURE_SIZE - binary_file_len), 
                            (binary_file_len + data_read) - SIGNATURE_SIZE);
                    if (ota_write_err != ESP_OK) {
                        break;
                    }
                    //ESP_LOGI(TAG, "Written image length %d", binary_file_len - SIGNATURE_SIZE);
                    rt = mbedtls_md_update(
                            &ctx, 
                            (const unsigned char*)upgrade_data_buf + (SIGNATURE_SIZE - binary_file_len), 
                            (binary_file_len + data_read) - SIGNATURE_SIZE);
                    if (rt != 0) {
                        ESP_LOGI(TAG, "failed to update message digest err: %d", rt);
                    }
                } else {
                    memcpy(signature + binary_file_len, upgrade_data_buf, data_read);
                }
            } else  {
                ota_write_err = esp_ota_write( update_handle, (const void *)upgrade_data_buf, data_read);
                if (ota_write_err != ESP_OK) {
                    break;
                }
                //ESP_LOGI(TAG, "Written image length %d", binary_file_len - SIGNATURE_SIZE);
                rt = mbedtls_md_update(&ctx, (const unsigned char*)upgrade_data_buf, data_read);
                if (rt != 0) {
                    ESP_LOGD(TAG, "failed to update message digest err: %d", rt);
                }
            }
            binary_file_len += data_read;
        }
    }
    /* Unnecessary
    uint32_t* signed_hash_len = (uint32_t*) malloc(sizeof(uint32_t));
    spi_flash_read(update_partition->address + binary_file_len - sizeof(uint32_t), signed_hash_len, sizeof(uint32_t));
    free(signed_hash_len);
    */

    http_cleanup(client); 

    /*
    for (int i = 0; i < binary_file_len; i += OTA_BUF_SIZE) {
        if (i + OTA_BUF_SIZE <= binary_file_len) {
            spi_flash_read(update_partition->address + i , upgrade_data_buf , OTA_BUF_SIZE);
            rt = mbedtls_md_update(ctx, (const unsigned char*)upgrade_data_buf, OTA_BUF_SIZE);
            if (rt != 0) {
                ESP_LOGI(TAG, "failed to update message digest err: %d", rt);
            }
        } else if ( i + OTA_BUF_SIZE > binary_file_len && i < binary_file_len) {
            spi_flash_read(update_partition->address + i , upgrade_data_buf , binary_file_len - i);
            rt = mbedtls_md_update(ctx, (const unsigned char*)upgrade_data_buf, binary_file_len -i);
            if (rt != 0) {
                ESP_LOGI(TAG, "failed to update message digest err: %d", rt);
            }
        } else {
            ESP_LOGI(TAG, "How did we end up here");
        }
    }
    */
    free(upgrade_data_buf);
    // Let's assume that the signed hash is at the first 512 byte
    // We can just save it while reading the first 512 byte instead of reading again from the flash
    //spi_flash_read(update_partition->address , signature , SIGNATURE_SIZE);

    ESP_LOGI(TAG, "mdinfo->size should be 512 and is: %d", mdinfo->size);
    mbedtls_pk_context pk_ctx;// = (mbedtls_pk_context*) malloc(sizeof(mbedtls_pk_context));
    /*
    if (!pk_ctx) {
        ESP_LOGE(TAG, "Couldn't allocate memory for the pk contexnt");
        return ESP_ERR_NO_MEM;
    }
    */
    mbedtls_pk_init(&pk_ctx);
    //const mbedtls_pk_info_t* pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    ESP_LOGI(TAG, "strlen: %d", strlen(sign_key));
    rt = mbedtls_pk_parse_public_key(&pk_ctx, (const unsigned char*)sign_key, strlen(sign_key)+1);
    if (rt != 0) {
        ESP_LOGI(TAG, " failed\n  ! mbedtls_pk_parse_keyfile returned %d\n", rt);
    }

    unsigned char* md_output = (unsigned char*) malloc(mdinfo->size);
    if (!md_output) {
        ESP_LOGE(TAG, "Couldn't allocate memory for the digest buffer");
        return ESP_ERR_NO_MEM;
    }
    rt = mbedtls_md_finish(&ctx, md_output);
    if (rt != 0) {
        ESP_LOGI(TAG, "failed to finish message digest err: %d", rt);
    }

    
    /*
    rt = mbedtls_pk_setup(pk_ctx, pk_info);
    if (rt != 0) {
        ESP_LOGI(TAG, "failed to setup public key err: %d", rt);
    }
    */
    rt = mbedtls_pk_verify(&pk_ctx, 
                           mdinfo->type, (const unsigned char*)md_output, mdinfo->size,
                           (const unsigned char*)signature, SIGNATURE_SIZE);
    mbedtls_md_free(&ctx);
    //free(ctx);
    mbedtls_pk_free(&pk_ctx);
    //free(pk_ctx);
    free(signature);

    if (rt != 0) {
        ESP_LOGE(TAG, "Signature is INVALID");
        return ESP_ERR_OTA_VALIDATE_FAILED;
    } else {
        ESP_LOGI(TAG, "Signature is VALID");
    }

    ESP_LOGI(TAG, "Total binary data length writen: %d", binary_file_len);
    
    esp_err_t ota_end_err = esp_ota_end(update_handle);
    if (ota_write_err != ESP_OK) {
        ESP_LOGE(TAG, "Error: esp_ota_write failed! err=0x%d", err);
        return ota_write_err;
    } else if (ota_end_err != ESP_OK) {
        ESP_LOGE(TAG, "Error: esp_ota_end failed! err=0x%d. Image is invalid", ota_end_err);
        return ota_end_err;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed! err=0x%d", err);
        return err;
    }
    ESP_LOGI(TAG, "esp_ota_set_boot_partition succeeded"); 

    return ESP_OK;
}
