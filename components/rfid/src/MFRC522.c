/*
* MFRC522.cpp - Library to use ARDUINO RFID MODULE KIT 13.56 MHZ WITH TAGS SPI W AND R BY COOQROBOT.
* NOTE: Please also check the comments in MFRC522.h - they provide useful hints and background information.
* Released into the public domain.
*/
// TODO 
// need differnte functions
// gpio_set_level -> gpio_set_level
// gpio_get_level -> gpio_get_level ! Needs init
// delayMicroseconds -> Some form of wait -> vTaskDelay
// gpio_set_direction -> gpio_set_direction
// Need SPI class functions
// Serial.print -> printf or something like that PDFI
// SS -> in pins_arduino.h
// SPISettings
// typedef uint8_t byte;
//
// arduino.h
// #define LSBFIRST 0 
//38:const uint8_t SPI_MODE0 = 0x00; ///<  CPOL: 0  CPHA: 0 // arduino SPI.h maybe in rtos spi.h the same
//
// CLOCK Devide see available values in ${REPO} `${IDF_PATH}/ components/esp8266/include/driver/spi.h`.  SPI_2MHz_DIV
// 
// We are master reader is slave

#define MSBFIRST 1
#define PIN_SPI_SS   (12)
#define HIGH   1
#define LOW   0
#define INPUT GPIO_MODE_INPUT
#define OUTPUT GPIO_MODE_OUTPUT
#define ESP8266_SPI_MAX_DATA_LENGTH 64 // in bytes

#define GPIO_OUTPUT_IO_0    15
#define GPIO_OUTPUT_IO_1    16
#define GPIO_OUTPUT_PIN_SEL  ((1ULL<<GPIO_OUTPUT_IO_0) | (1ULL<<GPIO_OUTPUT_IO_1))

//static const uint8_t SS   = PIN_SPI_SS;
//const uint8_t SPI_MODE0 = 0x00;


//#include <Arduino.h>
#include "MFRC522.h"

const byte MFRC522_firmware_referenceV0_0[] = {
	0x00, 0x87, 0x98, 0x0f, 0x49, 0xFF, 0x07, 0x19,
	0xBF, 0x22, 0x30, 0x49, 0x59, 0x63, 0xAD, 0xCA,
	0x7F, 0xE3, 0x4E, 0x03, 0x5C, 0x4E, 0x49, 0x50,
	0x47, 0x9A, 0x37, 0x61, 0xE7, 0xE2, 0xC6, 0x2E,
	0x75, 0x5A, 0xED, 0x04, 0x3D, 0x02, 0x4B, 0x78,
	0x32, 0xFF, 0x58, 0x3B, 0x7C, 0xE9, 0x00, 0x94,
	0xB4, 0x4A, 0x59, 0x5B, 0xFD, 0xC9, 0x29, 0xDF,
	0x35, 0x96, 0x98, 0x9E, 0x4F, 0x30, 0x32, 0x8D
};
// Version 1.0 (0x91)
// NXP Semiconductors; Rev. 3.8 - 17 September 2014; 16.1.1 self-test
const byte MFRC522_firmware_referenceV1_0[] = {
	0x00, 0xC6, 0x37, 0xD5, 0x32, 0xB7, 0x57, 0x5C,
	0xC2, 0xD8, 0x7C, 0x4D, 0xD9, 0x70, 0xC7, 0x73,
	0x10, 0xE6, 0xD2, 0xAA, 0x5E, 0xA1, 0x3E, 0x5A,
	0x14, 0xAF, 0x30, 0x61, 0xC9, 0x70, 0xDB, 0x2E,
	0x64, 0x22, 0x72, 0xB5, 0xBD, 0x65, 0xF4, 0xEC,
	0x22, 0xBC, 0xD3, 0x72, 0x35, 0xCD, 0xAA, 0x41,
	0x1F, 0xA7, 0xF3, 0x53, 0x14, 0xDE, 0x7E, 0x02,
	0xD9, 0x0F, 0xB5, 0x5E, 0x25, 0x1D, 0x29, 0x79
};
// Version 2.0 (0x92)
// NXP Semiconductors; Rev. 3.8 - 17 September 2014; 16.1.1 self-test
const byte MFRC522_firmware_referenceV2_0[] = {
	0x00, 0xEB, 0x66, 0xBA, 0x57, 0xBF, 0x23, 0x95,
	0xD0, 0xE3, 0x0D, 0x3D, 0x27, 0x89, 0x5C, 0xDE,
	0x9D, 0x3B, 0xA7, 0x00, 0x21, 0x5B, 0x89, 0x82,
	0x51, 0x3A, 0xEB, 0x02, 0x0C, 0xA5, 0x00, 0x49,
	0x7C, 0x84, 0x4D, 0xB3, 0xCC, 0xD2, 0x1B, 0x81,
	0x5D, 0x48, 0x76, 0xD5, 0x71, 0x61, 0x21, 0xA9,
	0x86, 0x96, 0x83, 0x38, 0xCF, 0x9D, 0x5B, 0x6D,
	0xDC, 0x15, 0xBA, 0x3E, 0x7D, 0x95, 0x3B, 0x2F
};
// Clone
// Fudan Semiconductor FM17522 (0x88)
const byte FM17522_firmware_reference[] = {
	0x00, 0xD6, 0x78, 0x8C, 0xE2, 0xAA, 0x0C, 0x18,
	0x2A, 0xB8, 0x7A, 0x7F, 0xD3, 0x6A, 0xCF, 0x0B,
	0xB1, 0x37, 0x63, 0x4B, 0x69, 0xAE, 0x91, 0xC7,
	0xC3, 0x97, 0xAE, 0x77, 0xF4, 0x37, 0xD7, 0x9B,
	0x7C, 0xF5, 0x3C, 0x11, 0x8F, 0x15, 0xC3, 0xD7,
	0xC1, 0x5B, 0x00, 0x2A, 0xD0, 0x75, 0xDE, 0x9E,
	0x51, 0x64, 0xAB, 0x3E, 0xE9, 0x15, 0xB5, 0xAB,
	0x56, 0x9A, 0x98, 0x82, 0x26, 0xEA, 0x2A, 0x62
};

static const char *TAG = "MFRC522";

// Default Constructo will take SS and UINT8_MAX

/////////////////////////////////////////////////////////////////////////////////////
// Functions for setting up the Arduino
/////////////////////////////////////////////////////////////////////////////////////
/**
 * Constructor.
 */
//MFRC522(): MFRC522(SS, UINT8_MAX) { // SS is defined in pins_arduino.h, UINT8_MAX means there is no connection from Arduino to MFRC522's reset and power down input
//} // End constructor

/**
 * Constructor.
 * Prepares the output pins.
 */
//MFRC522(	byte resetPowerDownPin	///< Arduino pin connected to MFRC522's reset and power down input (Pin 6, NRSTPD, active low). If there is no connection from the CPU to NRSTPD, set this to UINT8_MAX. In this case, only soft reset will be used in PCD_Init().
//				): MFRC522(SS, resetPowerDownPin) { // SS is defined in pins_arduino.h
//} // End constructor

/**
 * Constructor.
 * Prepares the output pins.
 */
//MFRC522(	byte chipSelectPin, ///< Arduino pin connected to MFRC522's SPI slave select input (Pin 24, NSS, active low)
//					byte resetPowerDownPin	///< Arduino pin connected to MFRC522's reset and power down input (Pin 6, NRSTPD, active low). If there is no connection from the CPU to NRSTPD, set this to UINT8_MAX. In this case, only soft reset will be used in PCD_Init().
//				) {
//	mfrc->_chipSelectPin = chipSelectPin;
//	mfrc->_resetPowerDownPin = resetPowerDownPin;
//} // End constructor

/////////////////////////////////////////////////////////////////////////////////////
// Basic interface functions for communicating with the MFRC522
/////////////////////////////////////////////////////////////////////////////////////

/**
 * Writes a byte to the specified register in the MFRC522 chip.
 * The interface is described in the datasheet section 8.1.2.
 */
void PCD_WriteRegister(MFRC522* mfrc, PCD_Register reg, ///< The register to write to. One of the PCD_Register enums.
									byte value			///< The value to write.
								) {
	//SPI.beginTransaction(SPISettings(MFRC522_SPICLOCK, MSBFIRST, SPI_MODE0));	// Set the settings to work with SPI bus
        esp_err_t err;
        portENTER_CRITICAL();
	if ((err = gpio_set_level(mfrc->_chipSelectPin, LOW)) != ESP_OK)		// Select slav) != ESP_OK) {
        {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	spi_master_send_byte(reg);						// MSB == 0 is for writing. LSB is not used in address. Datasheet section 8.1.2.3.
	spi_master_send_byte(value);
	if ((err = gpio_set_level(mfrc->_chipSelectPin, HIGH)) != ESP_OK)		// Release slave agai) != ESP_OK) {
        {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	//SPI.endTransaction(); // Stop using the SPI bus
        portEXIT_CRITICAL();
} // End PCD_WriteRegister()

/**
 * Writes a number of bytes to the specified register in the MFRC522 chip.
 * The interface is described in the datasheet section 8.1.2.
 */
void PCD_WriteRegisterMult(MFRC522* mfrc, PCD_Register reg, ///< The register to write to. One of the PCD_Register enums.
									byte count, 		///< The number of bytes to write to the register
									byte *values		///< The values to write. Byte array.
								) {
	//SPI.beginTransaction(SPISettings(MFRC522_SPICLOCK, MSBFIRST, SPI_MODE0));	// Set the settings to work with SPI bus
        esp_err_t err;
        portENTER_CRITICAL();
	if ((err = gpio_set_level(mfrc->_chipSelectPin, LOW)) != ESP_OK)		// Select slav) != ESP_OK) {
        {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	spi_master_send_byte(reg);
	for (byte index = 0; index < count; index++) {
                spi_master_send_byte(values[index]);
	}
	if ((err = gpio_set_level(mfrc->_chipSelectPin, HIGH)) != ESP_OK)		// Release slave agai) != ESP_OK) {
        {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	//SPI.endTransaction(); // Stop using the SPI bus
} // End PCD_WriteRegister()

/**
 * Reads a byte from the specified register in the MFRC522 chip.
 * The interface is described in the datasheet section 8.1.2.
 */
byte PCD_ReadRegister(MFRC522* mfrc, PCD_Register reg	///< The register to read from. One of the PCD_Register enums.
								) {
        esp_err_t err;
	byte value;
        // TODO disabel interrupt
	//SPI.beginTransaction(SPISettings(MFRC522_SPICLOCK, MSBFIRST, SPI_MODE0));	// Set the settings to work with SPI bus
        portENTER_CRITICAL();
	if ((err = gpio_set_level(mfrc->_chipSelectPin, LOW)) != ESP_OK)			// Select slav) != ESP_OK) {
        {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	spi_master_send_byte(0x80 | reg);					// MSB == 1 is for reading. LSB is not used in address. Datasheet section 8.1.2.3.
	value = spi_master_get_byte_and_send_byte(0);					// Read the value back. Send 0 to stop reading.
	if ((err = gpio_set_level(mfrc->_chipSelectPin, HIGH)) != ESP_OK)			// Release slave agai) != ESP_OK) {
        {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	//SPI.endTransaction(); // Stop using the SPI bus
        portEXIT_CRITICAL();
	return value;
} // End PCD_ReadRegister()

/**
 * Reads a number of bytes from the specified register in the MFRC522 chip.
 * The interface is described in the datasheet section 8.1.2.
 */
void PCD_ReadRegisterMult(MFRC522* mfrc, PCD_Register reg, ///< The register to read from. One of the PCD_Register enums.
								byte count, 		///< The number of bytes to read
								byte *values, 	///< Byte array to store the values in.
								byte rxAlign		///< Only bit positions rxAlign..7 in values[0] are updated.
								) {
	if (count == 0) {
		return;
	}
	//printf("Reading "); 	Serial.print(count); printf(" bytes from register.\n");
        esp_err_t err;
	byte address = 0x80 | reg;				// MSB == 1 is for reading. LSB is not used in address. Datasheet section 8.1.2.3.
	byte index = 0;							// Index in values array.
	//SPI.beginTransaction(SPISettings(MFRC522_SPICLOCK, MSBFIRST, SPI_MODE0));	// Set the settings to work with SPI bus
        portENTER_CRITICAL();
	if ((err = gpio_set_level(mfrc->_chipSelectPin, LOW)) != ESP_OK)		// Select slav) != ESP_OK) {
        {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	count--;								// One read is performed outside of the loop
	spi_master_send_byte(address);					// Tell MFRC522 which address we want to read
	if (rxAlign) {		// Only update bit positions rxAlign..7 in values[0]
		// Create bit mask for bit positions rxAlign..7
		byte mask = (0xFF << rxAlign) & 0xFF;
		// Read value and tell that we want to read the same address again.
		byte value = spi_master_get_byte_and_send_byte(address);
		// Apply mask to both current value of values[0] and the new data in value.
		values[0] = (values[0] & ~mask) | (value & mask);
		index++;
	}
	while (index < count) {
		values[index] = spi_master_get_byte_and_send_byte(address);	// Read value and tell that we want to read the same address again.
		index++;
	}
	values[index] = spi_master_get_byte_and_send_byte(0);			// Read the final byte. Send 0 to stop reading.
	if ((err = gpio_set_level(mfrc->_chipSelectPin, HIGH)) != ESP_OK)			// Release slave agai) != ESP_OK) {
        {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	//SPI.endTransaction(); // Stop using the SPI bus
        portEXIT_CRITICAL();
} // End PCD_ReadRegister()

/**
 * Sets the bits given in mask in register reg.
 */
void PCD_SetRegisterBitMask(MFRC522* mfrc, PCD_Register reg, ///< The register to update. One of the PCD_Register enums.
										byte mask			///< The bits to set.
									) { 
	byte tmp;
	tmp = PCD_ReadRegister(mfrc, reg);
	PCD_WriteRegister(mfrc, reg, tmp | mask);			// set bit mask
} // End PCD_SetRegisterBitMask()

/**
 * Clears the bits given in mask from register reg.
 */
void PCD_ClearRegisterBitMask(MFRC522* mfrc, PCD_Register reg, ///< The register to update. One of the PCD_Register enums.
										byte mask			///< The bits to clear.
									  ) {
	byte tmp;
	tmp = PCD_ReadRegister(mfrc, reg);
	PCD_WriteRegister(mfrc, reg, tmp & (~mask));		// clear bit mask
} // End PCD_ClearRegisterBitMask()


/**
 * Use the CRC coprocessor in the MFRC522 to calculate a CRC_A.
 * 
 * @return STATUS_OK on success, STATUS_??? otherwise.
 */
StatusCode PCD_CalculateCRC(MFRC522* mfrc, byte *data, 	///< In: Pointer to the data to transfer to the FIFO for CRC calculation.
												byte length, ///< In: The number of bytes to transfer.
												byte *result	///< Out: Pointer to result buffer. Result is written to result[0..1], low byte first.
					 ) {
	PCD_WriteRegister(mfrc, CommandReg, PCD_Idle);		// Stop any active command.
	PCD_WriteRegister(mfrc, DivIrqReg, 0x04);				// Clear the CRCIRq interrupt request bit
	PCD_WriteRegister(mfrc, FIFOLevelReg, 0x80);			// FlushBuffer = 1, FIFO initialization
	PCD_WriteRegisterMult(mfrc, FIFODataReg, length, data);	// Write data to the FIFO
	PCD_WriteRegister(mfrc, CommandReg, PCD_CalcCRC);		// Start the calculation
	
	// Wait for the CRC calculation to complete. Each iteration of the while-loop takes 17.73μs.
	// TODO check/modify for other architectures than Arduino Uno 16bit

	// Wait for the CRC calculation to complete. Each iteration of the while-loop takes 17.73us.
	for (uint16_t i = 5000; i > 0; i--) {
		// DivIrqReg[7..0] bits are: Set2 reserved reserved MfinActIRq reserved CRCIRq reserved reserved
		byte n = PCD_ReadRegister(mfrc, DivIrqReg);
		if (n & 0x04) {									// CRCIRq bit set - calculation done
			PCD_WriteRegister(mfrc, CommandReg, PCD_Idle);	// Stop calculating CRC for new content in the FIFO.
			// Transfer the result from the registers to the result buffer
			result[0] = PCD_ReadRegister(mfrc, CRCResultRegL);
			result[1] = PCD_ReadRegister(mfrc, CRCResultRegH);
			return STATUS_OK;
		}
	}
	// 89ms passed and nothing happend. Communication with the MFRC522 might be down.
	return STATUS_TIMEOUT;
} // End PCD_CalculateCRC()


/////////////////////////////////////////////////////////////////////////////////////
// Functions for manipulating the MFRC522
/////////////////////////////////////////////////////////////////////////////////////

/**
 * Initializes the MFRC522 chip.
 * Assumes that the mfrc points to an existing structure
 */
esp_err_t PCD_Init(MFRC522* mfrc) {
        // Need to setup
	bool hardReset = false;
        esp_err_t err;

        gpio_config_t io_conf;
        //disable interrupt
        io_conf.intr_type = GPIO_INTR_DISABLE;
        //set as output mode
        io_conf.mode = GPIO_MODE_OUTPUT;
        //bit mask of the pins that you want to set,e.g.GPIO15/16 or here _chipSelectPin and _resetPowerDownPin
        io_conf.pin_bit_mask = ((1ULL<<mfrc->_chipSelectPin)  | (1ULL<<mfrc->_resetPowerDownPin));
        //disable pull-down mode
        io_conf.pull_down_en = 0;
        //disable pull-up mode
        io_conf.pull_up_en = 0;
        //configure GPIO with the given settings
        if ((err = gpio_config(&io_conf))  != ESP_OK) {
            printf("%s: gpio_config(): %s", TAG, esp_err_to_name(err));
            return err;
        }

        /*
        //interrupt of rising edge
        io_conf.intr_type = GPIO_INTR_POSEDGE;
        //bit mask of the pins, use GPIO4/5 here
        io_conf.pin_bit_mask = GPIO_INPUT_PIN_SEL;
        //set as input mode
        io_conf.mode = GPIO_MODE_INPUT;
        //enable pull-up mode
        io_conf.pull_up_en = 1;
        gpio_config(&io_conf);
        */


        spi_config_t spi_config;

        // Default with hopefully no interrupt
        spi_config.interface.val = SPI_DEFAULT_INTERFACE;
        // TRANS_DONE: true, WRITE_STATUS: false, READ_STATUS: false, WRITE_BUFFER: false, READ_BUFFER: false
        spi_config.intr_enable.val = SPI_MASTER_DEFAULT_INTR_ENABLE;
        spi_config.intr_enable.trans_done = 0;


        // TODO What are the right configurations
        /*
        spi_interface_t interface_config = {

            // SPI mode 3, CPOL = 1, CPHA = 1 
            .cpol = 0,  // Arduino Lib uses SPI_MODE0 which means cpol = 0 and cpha = 0 
            .cpha = 0,  // https://www.arduino.cc/en/Reference/SPI output edge and datacapture is hopefully automatically set with configure call
            .bit_tx_order = 0,
            .bit_rx_order = 0,
            .byte_tx_order = 1,
            .byte_rx_order = 1,
            .mosi_en = 1,
            .miso_en = 1,
            .cs_en = 1,
            .reserved9 = 23,
        };
        */

        /*
        if (xSemaphoreTake(mutex, MUTEX_TIMEOUT) != pdTRUE) {
            err = ESP_FAIL;
            ESP_LOGE(TAG, "xSemaphoreTake(): timeout");
            goto fail_without_give;
        }
        */

        /*
        strip->buf = malloc(LED_STRIP_SPI_BUFFER_SIZE(strip->length));
        if (strip->buf == NULL) {
            ESP_LOGE(TAG, "malloc()");
            err = ESP_ERR_NO_MEM;
            goto fail;
        }
        memset(strip->buf, 0, LED_STRIP_SPI_BUFFER_SIZE(strip->length));
        */

        printf("%s: %s\n", TAG, "SPI buffer initialized");
        //spi_config.interface  interface_config;
        spi_config.mode = SPI_MASTER_MODE;
        spi_config.clk_div = SPI_4MHz_DIV;
        spi_config.event_cb = NULL;

        err = spi_init(HSPI_HOST, &spi_config);
        if (err != ESP_OK) {
            printf("%s: spi_init(): %s", TAG, esp_err_to_name(err));
            return err;
            // TODO goto fail;
        }
        printf("%s: %s", TAG, "SPI bus initialized");

	// Set the chipSelectPin as digital output, do not select the slave yet
	if ((err = gpio_set_direction(mfrc->_chipSelectPin, OUTPUT)) != ESP_OK) {
            printf("%s: gpio_set_direction err %s\n", TAG, esp_err_to_name(err));
            return err;
        }
	if ((err = gpio_set_level(mfrc->_chipSelectPin, HIGH)) != ESP_OK) {
            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
        }
	
	// If a valid pin number has been set, pull device out of power down / reset state.
	if (mfrc->_resetPowerDownPin != UNUSED_PIN) {
		// First set the resetPowerDownPin as digital input, to check the MFRC522 power down mode.
		gpio_set_direction(mfrc->_resetPowerDownPin, INPUT);
	
		if (gpio_get_level(mfrc->_resetPowerDownPin) == LOW) {	// The MFRC522 chip is in power down mode.
			if ((err = gpio_set_direction(mfrc->_resetPowerDownPin, OUTPUT)) != ESP_OK)		// Now set the resetPowerDownPin as digital output) != ESP_OK) 
                        {
                            printf("%s: gpio_set_direction err %s\n", TAG, esp_err_to_name(err));
                        }
			if ((err = gpio_set_level(mfrc->_resetPowerDownPin, LOW)) != ESP_OK)		// Make sure we have a clean LOW state) != ESP_OK) {
                        {
                            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
                        }
			vTaskDelay(1 / portTICK_PERIOD_MS);				// 8.8.1 Reset timing requirements says about 100ns. Let us be generous: 2μsl
			if ((err = gpio_set_level(mfrc->_resetPowerDownPin, HIGH)) != ESP_OK)		// Exit power down mode. This triggers a hard reset) != ESP_OK) {
                        {
                            printf("%s: gpio_set_level err %s\n", TAG, esp_err_to_name(err));
                        }
			// Section 8.8.2 in the datasheet says the oscillator start-up time is the start up time of the crystal + 37,74μs. Let us be generous: 50ms.
			vTaskDelay(50 / portTICK_PERIOD_MS);
			hardReset = true;
		}
	}

	if (!hardReset) { // Perform a soft reset if we haven't triggered a hard reset above.
		PCD_Reset(mfrc);
	}
	
	// Reset baud rates
	PCD_WriteRegister(mfrc, TxModeReg, 0x00);
	PCD_WriteRegister(mfrc, RxModeReg, 0x00);
	// Reset ModWidthReg
	PCD_WriteRegister(mfrc, ModWidthReg, 0x26);

	// When communicating with a PICC we need a timeout if something goes wrong.
	// f_timer = 13.56 MHz / (2*TPreScaler+1) where TPreScaler = [TPrescaler_Hi:TPrescaler_Lo].
	// TPrescaler_Hi are the four low bits in TModeReg. TPrescaler_Lo is TPrescalerReg.
	PCD_WriteRegister(mfrc, TModeReg, 0x80);			// TAuto=1; timer starts automatically at the end of the transmission in all communication modes at all speeds
	PCD_WriteRegister(mfrc, TPrescalerReg, 0xA9);		// TPreScaler = TModeReg[3..0]:TPrescalerReg, ie 0x0A9 = 169 => f_timer=40kHz, ie a timer period of 25μs.
	PCD_WriteRegister(mfrc, TReloadRegH, 0x03);		// Reload timer with 0x3E8 = 1000, ie 25ms before timeout.
	PCD_WriteRegister(mfrc, TReloadRegL, 0xE8);
	
	PCD_WriteRegister(mfrc, TxASKReg, 0x40);		// Default 0x00. Force a 100 % ASK modulation independent of the ModGsPReg register setting
	PCD_WriteRegister(mfrc, ModeReg, 0x3D);		// Default 0x3F. Set the preset value for the CRC coprocessor for the CalcCRC command to 0x6363 (ISO 14443-3 part 6.2.4)
	PCD_AntennaOn(mfrc);						// Enable the antenna driver pins TX1 and TX2 (they were disabled by the reset)
        return ESP_OK;
} // End PCD_Init()

/**
 * Initializes the MFRC522 chip. WE ONLY USE ONE INIT FUNCTION WHICH ASSUMES A VALID MFRC522 Struct with the parameters _chipSelectPin and _resetPowerDownPin already set
 */
//void PCD_Init(MFRC522* mfrc, byte resetPowerDownPin	///< Arduino pin connected to MFRC522's reset and power down input (Pin 6, NRSTPD, active low)
//					) {
//	PCD_Init(mfrc, SS, resetPowerDownPin); // SS is defined in pins_arduino.h
//} // End PCD_Init()
//
///**
// * Initializes the MFRC522 chip.
// */
//void PCD_Init(MFRC522* mfrc, byte chipSelectPin, 	///< Arduino pin connected to MFRC522's SPI slave select input (Pin 24, NSS, active low)
//						byte resetPowerDownPin	///< Arduino pin connected to MFRC522's reset and power down input (Pin 6, NRSTPD, active low)
//					) {
//	mfrc->_chipSelectPin = chipSelectPin;
//	mfrc->_resetPowerDownPin = resetPowerDownPin; 
//	// Set the chipSelectPin as digital output, do not select the slave yet
//	PCD_Init(mfrc);
//} // End PCD_Init()

/**
 * Performs a soft reset on the MFRC522 chip and waits for it to be ready again.
 */
void PCD_Reset(MFRC522* mfrc) {
        printf("went into reset");
	PCD_WriteRegister(mfrc, CommandReg, PCD_SoftReset);	// Issue the SoftReset command.
	// The datasheet does not mention how long the SoftRest command takes to complete.
	// But the MFRC522 might have been in soft power-down mode (triggered by bit 4 of CommandReg) 
	// Section 8.8.2 in the datasheet says the oscillator start-up time is the start up time of the crystal + 37,74μs. Let us be generous: 50ms.
	uint8_t count = 0;
	do {
		// Wait for the PowerDown bit in CommandReg to be cleared (max 3x50ms)
		vTaskDelay(50/portTICK_PERIOD_MS);
	} while ((PCD_ReadRegister(mfrc, CommandReg) & (1 << 4)) && (++count) < 3);
} // End PCD_Reset()

/**
 * Turns the antenna on by enabling pins TX1 and TX2.
 * After a reset these pins are disabled.
 */
void PCD_AntennaOn(MFRC522* mfrc) {
	byte value = PCD_ReadRegister(mfrc, TxControlReg);
	if ((value & 0x03) != 0x03) {
		PCD_WriteRegister(mfrc, TxControlReg, value | 0x03);
	}
} // End PCD_AntennaOn()

/**
 * Turns the antenna off by disabling pins TX1 and TX2.
 */
void PCD_AntennaOff(MFRC522* mfrc) {
	PCD_ClearRegisterBitMask(mfrc, TxControlReg, 0x03);
} // End PCD_AntennaOff()

/**
 * Get the current MFRC522 Receiver Gain (RxGain[2:0]) value.
 * See 9.3.3.6 / table 98 in http://www.nxp.com/documents/data_sheet/MFRC522.pdf
 * NOTE: Return value scrubbed with (0x07<<4)=01110000b as RCFfgReg may use reserved bits.
 * 
 * @return Value of the RxGain, scrubbed to the 3 bits used.
 */
byte PCD_GetAntennaGain(MFRC522* mfrc) {
	return PCD_ReadRegister(mfrc, RFCfgReg) & (0x07<<4);
} // End PCD_GetAntennaGain()

/**
 * Set the MFRC522 Receiver Gain (RxGain) to value specified by given mask.
 * See 9.3.3.6 / table 98 in http://www.nxp.com/documents/data_sheet/MFRC522.pdf
 * NOTE: Given mask is scrubbed with (0x07<<4)=01110000b as RCFfgReg may use reserved bits.
 */
void PCD_SetAntennaGain(MFRC522* mfrc,byte mask) {
	if (PCD_GetAntennaGain(mfrc) != mask) {						// only bother if there is a change
		PCD_ClearRegisterBitMask(mfrc, RFCfgReg, (0x07<<4));		// clear needed to allow 000 pattern
		PCD_SetRegisterBitMask(mfrc, RFCfgReg, mask & (0x07<<4));	// only set RxGain[2:0] bits
	}
} // End PCD_SetAntennaGain()

/**
 * Performs a self-test of the MFRC522
 * See 16.1.1 in http://www.nxp.com/documents/data_sheet/MFRC522.pdf
 * 
 * @return Whether or not the test passed. Or false if no firmware reference is available.
 */
bool PCD_PerformSelfTest(MFRC522* mfrc) {
	// This follows directly the steps outlined in 16.1.1
	// 1. Perform a soft reset.
	PCD_Reset(mfrc);
	
	// 2. Clear the internal buffer by writing 25 bytes of 00h
	byte ZEROES[25] = {0x00};
	PCD_WriteRegister(mfrc, FIFOLevelReg, 0x80);		// flush the FIFO buffer
	PCD_WriteRegisterMult(mfrc, FIFODataReg, 25, ZEROES);	// write 25 bytes of 00h to FIFO
	PCD_WriteRegister(mfrc, CommandReg, PCD_Mem);		// transfer to internal buffer
	
	// 3. Enable self-test
	PCD_WriteRegister(mfrc, AutoTestReg, 0x09);
	
	// 4. Write 00h to FIFO buffer
	PCD_WriteRegister(mfrc, FIFODataReg, 0x00);
	
	// 5. Start self-test by issuing the CalcCRC command
	PCD_WriteRegister(mfrc, CommandReg, PCD_CalcCRC);
	
	// 6. Wait for self-test to complete
	byte n;
	for (uint8_t i = 0; i < 0xFF; i++) {
		// The datasheet does not specify exact completion condition except
		// that FIFO buffer should contain 64 bytes.
		// While selftest is initiated by CalcCRC command
		// it behaves differently from normal CRC computation,
		// so one can't reliably use DivIrqReg to check for completion.
		// It is reported that some devices does not trigger CRCIRq flag
		// during selftest.
		n = PCD_ReadRegister(mfrc, FIFOLevelReg);
		if (n >= 64) {
			break;
		}
	}
	PCD_WriteRegister(mfrc, CommandReg, PCD_Idle);		// Stop calculating CRC for new content in the FIFO.
	
	// 7. Read out resulting 64 bytes from the FIFO buffer.
	byte result[64];
	PCD_ReadRegisterMult(mfrc, FIFODataReg, 64, result, 0);
	
	// Auto self-test done
	// Reset AutoTestReg register to be 0 again. Required for normal operation.
	PCD_WriteRegister(mfrc, AutoTestReg, 0x00);
	
	// Determine firmware version (see section 9.3.4.8 in spec)
	byte version = PCD_ReadRegister(mfrc, VersionReg);
	
	// Pick the appropriate reference values
	const byte *reference;
	switch (version) {
		case 0x88:	// Fudan Semiconductor FM17522 clone
			reference = FM17522_firmware_reference;
			break;
		case 0x90:	// Version 0.0
			reference = MFRC522_firmware_referenceV0_0;
			break;
		case 0x91:	// Version 1.0
			reference = MFRC522_firmware_referenceV1_0;
			break;
		case 0x92:	// Version 2.0
			reference = MFRC522_firmware_referenceV2_0;
			break;
		default:	// Unknown version
                        printf("\n\n\nFound unkown version %x\n\n\n", version);
			return false; // abort test
	}
	
	// Verify that the results match up to our expectations
	for (uint8_t i = 0; i < 64; i++) {
            /*
            if ((ret = spi_flash_read(&(reference[i]), &check, sizeof(byte))) != ESP_OK) {
		// if (result[i] != pgm_read_byte(&(reference[i]))) {
                printf("%s: Verifying with spi_flash_read failed %d", TAG, ret);
                return false ;
            }
            */
		if (result[i] != reference[i]) {
			return false;
		}
	}
	
	// Test passed; all is good.
    printf("\n\n\nTests did work, Version %x\n\n\n", version);
    return true;
} // End PCD_PerformSelfTest()

/////////////////////////////////////////////////////////////////////////////////////
// Power control
/////////////////////////////////////////////////////////////////////////////////////

//IMPORTANT NOTE!!!!
//Calling any other function that uses CommandReg will disable soft power down mode !!!
//For more details about power control, refer to the datasheet - page 33 (8.6)

void PCD_SoftPowerDown(MFRC522* mfrc){//Note : Only soft power down mode is available throught software
    byte val = PCD_ReadRegister(mfrc, CommandReg); // Read state of the command register 
    val |= (1<<4);// set PowerDown bit ( bit 4 ) to 1 
    PCD_WriteRegister(mfrc, CommandReg, val);//write new value to the command register
}

void PCD_SoftPowerUp(MFRC522* mfrc){
    byte val = PCD_ReadRegister(mfrc, CommandReg); // Read state of the command register 
    val &= ~(1<<4);// set PowerDown bit ( bit 4 ) to 0 
    PCD_WriteRegister(mfrc, CommandReg, val);//write new value to the command register
    // wait until PowerDown bit is cleared (this indicates end of wake up procedure) 
    //const uint32_t timeout = (uint32_t)millis() + 500;// create timer for timeout (just in case) 
    
    while(1){
            val = PCD_ReadRegister(mfrc, CommandReg);// Read state of the command register
            if(!(val & (1<<4))){ // if powerdown bit is 0 
                    break;// wake up procedure is finished 
            }
            // Wait 500 ms // set timeout to 500 ms 
            vTaskDelay(500 / portTICK_PERIOD_MS);				
    }
}

/////////////////////////////////////////////////////////////////////////////////////
// Functions for communicating with PICCs
/////////////////////////////////////////////////////////////////////////////////////

/**
* Executes the Transceive command.
* CRC validation can only be done if backData and backLen are specified.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode PCD_TransceiveData(MFRC522* mfrc, byte *sendData, 	///< Pointer to the data to transfer to the FIFO.
                                                                                                    byte sendLen, 	///< Number of bytes to transfer to the FIFO.
                                                                                                    byte *backData, 	///< nullptr or pointer to buffer if data should be read back after executing the command.
                                                                                                    byte *backLen, 	///< In: Max number of bytes to write to *backData. Out: The number of bytes returned.
                                                                                                    byte *validBits, ///< In/Out: The number of valid bits in the last byte. 0 for 8 valid bits. Default nullptr.
                                                                                                    byte rxAlign, 	///< In: Defines the bit position in backData[0] for the first bit received. Default 0.
                                                                                                    bool checkCRC		///< In: True => The last two bytes of the response is assumed to be a CRC_A that must be validated.
                                                             ) {
    byte waitIRq = 0x30;		// RxIRq and IdleIRq
    StatusCode result = PCD_CommunicateWithPICC(mfrc, PCD_Transceive, waitIRq, sendData, sendLen, backData, backLen, validBits, rxAlign, checkCRC);
    return result;
} // End PCD_TransceiveData()

/**
* Transfers data to the MFRC522 FIFO, executes a command, waits for completion and transfers data back from the FIFO.
* CRC validation can only be done if backData and backLen are specified.
*
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode PCD_CommunicateWithPICC(MFRC522* mfrc, byte command, 	///< The command to execute. One of the PCD_Command enums.
                                                                                                            byte waitIRq, 	///< The bits in the ComIrqReg register that signals successful completion of the command.
                                                                                                            byte *sendData, 	///< Pointer to the data to transfer to the FIFO.
                                                                                                            byte sendLen, 	///< Number of bytes to transfer to the FIFO.
                                                                                                            byte *backData, 	///< nullptr or pointer to buffer if data should be read back after executing the command.
                                                                                                            byte *backLen, 	///< In: Max number of bytes to write to *backData. Out: The number of bytes returned.
                                                                                                            byte *validBits, ///< In/Out: The number of valid bits in the last byte. 0 for 8 valid bits.
                                                                                                            byte rxAlign, 	///< In: Defines the bit position in backData[0] for the first bit received. Default 0.
                                                                                                            bool checkCRC		///< In: True => The last two bytes of the response is assumed to be a CRC_A that must be validated.
    ) {
// Prepare values for BitFramingReg
byte txLastBits = validBits ? *validBits : 0;
byte bitFraming = (rxAlign << 4) + txLastBits;		// RxAlign = BitFramingReg[6..4]. TxLastBits = BitFramingReg[2..0]

PCD_WriteRegister(mfrc, CommandReg, PCD_Idle);			// Stop any active command.
PCD_WriteRegister(mfrc, ComIrqReg, 0x7F);					// Clear all seven interrupt request bits
PCD_WriteRegister(mfrc, FIFOLevelReg, 0x80);				// FlushBuffer = 1, FIFO initialization
PCD_WriteRegisterMult(mfrc, FIFODataReg, sendLen, sendData);	// Write sendData to the FIFO
PCD_WriteRegister(mfrc, BitFramingReg, bitFraming);		// Bit adjustments
PCD_WriteRegister(mfrc, CommandReg, command);				// Execute the command
if (command == PCD_Transceive) {
    PCD_SetRegisterBitMask(mfrc, BitFramingReg, 0x80);	// StartSend=1, transmission of data starts
}

// Wait for the command to complete.
// In PCD_Init() we set the TAuto flag in TModeReg. This means the timer automatically starts when the PCD stops transmitting.
// Each iteration of the do-while-loop takes 17.86μs.
// TODO check/modify for other architectures than Arduino Uno 16bit
uint16_t i;
for (i = 2000; i > 0; i--) {
    byte n = PCD_ReadRegister(mfrc, ComIrqReg);	// ComIrqReg[7..0] bits are: Set1 TxIRq RxIRq IdleIRq HiAlertIRq LoAlertIRq ErrIRq TimerIRq
    if (n & waitIRq) {					// One of the interrupts that signal success has been set.
        break;
    }
    if (n & 0x01) {						// Timer interrupt - nothing received in 25ms
        return STATUS_TIMEOUT;
    }
}
// 35.7ms and nothing happend. Communication with the MFRC522 might be down.
if (i == 0) {
    return STATUS_TIMEOUT;
}

// Stop now if any errors except collisions were detected.
byte errorRegValue = PCD_ReadRegister(mfrc, ErrorReg); // ErrorReg[7..0] bits are: WrErr TempErr reserved BufferOvfl CollErr CRCErr ParityErr ProtocolErr
if (errorRegValue & 0x13) {	 // BufferOvfl ParityErr ProtocolErr
    return STATUS_ERROR;
}

byte _validBits = 0;

// If the caller wants data back, get it from the MFRC522.
if (backData && backLen) {
    byte n = PCD_ReadRegister(mfrc, FIFOLevelReg);	// Number of bytes in the FIFO
    if (n > *backLen) {
        return STATUS_NO_ROOM;
    }
    *backLen = n;											// Number of bytes returned
    PCD_ReadRegisterMult(mfrc, FIFODataReg, n, backData, rxAlign);	// Get received data from FIFO
    _validBits = PCD_ReadRegister(mfrc, ControlReg) & 0x07;		// RxLastBits[2:0] indicates the number of valid bits in the last received byte. If this value is 000b, the whole byte is valid.
    if (validBits) {
        *validBits = _validBits;
    }
}

// Tell about collisions
if (errorRegValue & 0x08) {		// CollErr
    return STATUS_COLLISION;
}

// Perform CRC_A validation if requested.
if (backData && backLen && checkCRC) {
    // In this case a MIFARE Classic NAK is not OK.
    if (*backLen == 1 && _validBits == 4) {
        return STATUS_MIFARE_NACK;
    }
    // We need at least the CRC_A value and all 8 bits of the last byte must be received.
    if (*backLen < 2 || _validBits != 0) {
        return STATUS_CRC_WRONG;
    }
    // Verify CRC_A - do our own calculation and store the control in controlBuffer.
    byte controlBuffer[2];
    StatusCode status = PCD_CalculateCRC(mfrc, &backData[0], *backLen - 2, &controlBuffer[0]);
    if (status != STATUS_OK) {
        return status;
    }
    if ((backData[*backLen - 2] != controlBuffer[0]) || (backData[*backLen - 1] != controlBuffer[1])) {
        return STATUS_CRC_WRONG;
    }
}

return STATUS_OK;
} // End PCD_CommunicateWithPICC()

/**
* Transmits a REQuest command, Type A. Invites PICCs in state IDLE to go to READY and prepare for anticollision or selection. 7 bit frame.
* Beware: When two PICCs are in the field at the same time I often get STATUS_TIMEOUT - probably due do bad antenna design.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode PICC_RequestA(MFRC522* mfrc, byte *bufferATQA, ///< The buffer to store the ATQA (Answer to request) in
    byte *bufferSize	///< Buffer size, at least two bytes. Also number of bytes returned if STATUS_OK.
    ) {
return PICC_REQA_or_WUPA(mfrc, PICC_CMD_REQA, bufferATQA, bufferSize);
} // End PICC_RequestA()

/**
* Transmits a Wake-UP command, Type A. Invites PICCs in state IDLE and HALT to go to READY(*) and prepare for anticollision or selection. 7 bit frame.
* Beware: When two PICCs are in the field at the same time I often get STATUS_TIMEOUT - probably due do bad antenna design.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode PICC_WakeupA(MFRC522* mfrc, byte *bufferATQA, ///< The buffer to store the ATQA (Answer to request) in
    byte *bufferSize	///< Buffer size, at least two bytes. Also number of bytes returned if STATUS_OK.
    ) {
return PICC_REQA_or_WUPA(mfrc, PICC_CMD_WUPA, bufferATQA, bufferSize);
} // End PICC_WakeupA()

/**
* Transmits REQA or WUPA commands.
* Beware: When two PICCs are in the field at the same time I often get STATUS_TIMEOUT - probably due do bad antenna design.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/ 
StatusCode PICC_REQA_or_WUPA(MFRC522* mfrc, byte command, 		///< The command to send - PICC_CMD_REQA or PICC_CMD_WUPA
    byte *bufferATQA, ///< The buffer to store the ATQA (Answer to request) in
    byte *bufferSize	///< Buffer size, at least two bytes. Also number of bytes returned if STATUS_OK.
    ) {
byte validBits;
StatusCode status;

if (bufferATQA == NULL || *bufferSize < 2) {	// The ATQA response is 2 bytes long.
    return STATUS_NO_ROOM;
}
PCD_ClearRegisterBitMask(mfrc, CollReg, 0x80);		// ValuesAfterColl=1 => Bits received after collision are cleared.
validBits = 7;									// For REQA and WUPA we need the short frame format - transmit only 7 bits of the last (and only) byte. TxLastBits = BitFramingReg[2..0]
status = PCD_TransceiveData(mfrc, &command, 1, bufferATQA, bufferSize, &validBits, 0, false);
    if (status != STATUS_OK) {
            return status;
    }
    if (*bufferSize != 2 || validBits != 0) {		// ATQA must be exactly 16 bits.
            return STATUS_ERROR;
    }
    return STATUS_OK;
} // End PICC_REQA_or_WUPA()

StatusCode PICC_Select_Without_bytes(MFRC522* mfrc, Uid *uid) {
return PICC_Select(mfrc, uid, 0);
}

/**
* Transmits SELECT/ANTICOLLISION commands to select a single PICC.
* Before calling this function the PICCs must be placed in the READY(*) state by calling PICC_RequestA() or PICC_WakeupA().
* On success:
* 		- The chosen PICC is in state ACTIVE(*) and all other PICCs have returned to state IDLE/HALT. (Figure 7 of the ISO/IEC 14443-3 draft.)
* 		- The UID size and value of the chosen PICC is returned in *uid along with the SAK.
* 
* A PICC UID consists of 4, 7 or 10 bytes.
* Only 4 bytes can be specified in a SELECT command, so for the longer UIDs two or three iterations are used:
* 		UID size	Number of UID bytes		Cascade levels		Example of PICC
* 		========	===================		==============		===============
* 		single				 4						1				MIFARE Classic
* 		double				 7						2				MIFARE Ultralight
* 		triple				10						3				Not currently in use?
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode PICC_Select(MFRC522* mfrc, Uid *uid, 		///< Pointer to Uid struct. Normally output, but can also be used to supply a known UID.
                                                                                    byte validBits		///< The number of known UID bits supplied in *uid. Normally 0. If set you must also supply uid->size.
                                                                             ) {
    bool uidComplete;
    bool selectDone;
    bool useCascadeTag;
    byte cascadeLevel = 1;
    StatusCode result;
    byte count;
    byte checkBit;
    byte index;
    byte uidIndex;					// The first index in uid->uidByte[] that is used in the current Cascade Level.
    int8_t currentLevelKnownBits;		// The number of known UID bits in the current Cascade Level.
    byte buffer[9];					// The SELECT/ANTICOLLISION commands uses a 7 byte standard frame + 2 bytes CRC_A
    byte bufferUsed;				// The number of bytes used in the buffer, ie the number of bytes to transfer to the FIFO.
    byte rxAlign;					// Used in BitFramingReg. Defines the bit position for the first bit received.
    byte txLastBits;				// Used in BitFramingReg. The number of valid bits in the last transmitted byte. 
    byte *responseBuffer;
    byte responseLength;
    
    // Description of buffer structure:
    //		Byte 0: SEL 				Indicates the Cascade Level: PICC_CMD_SEL_CL1, PICC_CMD_SEL_CL2 or PICC_CMD_SEL_CL3
    //		Byte 1: NVB					Number of Valid Bits (in complete command, not just the UID): High nibble: complete bytes, Low nibble: Extra bits. 
    //		Byte 2: UID-data or CT		See explanation below. CT means Cascade Tag.
    //		Byte 3: UID-data
    //		Byte 4: UID-data
    //		Byte 5: UID-data
    //		Byte 6: BCC					Block Check Character - XOR of bytes 2-5
    //		Byte 7: CRC_A
    //		Byte 8: CRC_A
    // The BCC and CRC_A are only transmitted if we know all the UID bits of the current Cascade Level.
    //
    // Description of bytes 2-5: (Section 6.5.4 of the ISO/IEC 14443-3 draft: UID contents and cascade levels)
    //		UID size	Cascade level	Byte2	Byte3	Byte4	Byte5
    //		========	=============	=====	=====	=====	=====
    //		 4 bytes		1			uid0	uid1	uid2	uid3
    //		 7 bytes		1			CT		uid0	uid1	uid2
    //						2			uid3	uid4	uid5	uid6
    //		10 bytes		1			CT		uid0	uid1	uid2
    //						2			CT		uid3	uid4	uid5
    //						3			uid6	uid7	uid8	uid9
    
    // Sanity checks
    if (validBits > 80) {
            return STATUS_INVALID;
    }
    
    // Prepare MFRC522
    PCD_ClearRegisterBitMask(mfrc, CollReg, 0x80);		// ValuesAfterColl=1 => Bits received after collision are cleared.
    
    // Repeat Cascade Level loop until we have a complete UID.
    uidComplete = false;
    while (!uidComplete) {
            // Set the Cascade Level in the SEL byte, find out if we need to use the Cascade Tag in byte 2.
            switch (cascadeLevel) {
                    case 1:
                            buffer[0] = PICC_CMD_SEL_CL1;
                            uidIndex = 0;
                            useCascadeTag = validBits && uid->size > 4;	// When we know that the UID has more than 4 bytes
                            break;
                    
                    case 2:
                            buffer[0] = PICC_CMD_SEL_CL2;
                            uidIndex = 3;
                            useCascadeTag = validBits && uid->size > 7;	// When we know that the UID has more than 7 bytes
                            break;
                    
                    case 3:
                            buffer[0] = PICC_CMD_SEL_CL3;
                            uidIndex = 6;
                            useCascadeTag = false;						// Never used in CL3.
                            break;
                    
                    default:
                            return STATUS_INTERNAL_ERROR;
                            break;
            }
            
            // How many UID bits are known in this Cascade Level?
            currentLevelKnownBits = validBits - (8 * uidIndex);
            if (currentLevelKnownBits < 0) {
                    currentLevelKnownBits = 0;
            }
            // Copy the known bits from uid->uidByte[] to buffer[]
            index = 2; // destination index in buffer[]
            if (useCascadeTag) {
                    buffer[index++] = PICC_CMD_CT;
            }
            byte bytesToCopy = currentLevelKnownBits / 8 + (currentLevelKnownBits % 8 ? 1 : 0); // The number of bytes needed to represent the known bits for this level.
            if (bytesToCopy) {
                    byte maxBytes = useCascadeTag ? 3 : 4; // Max 4 bytes in each Cascade Level. Only 3 left if we use the Cascade Tag
                    if (bytesToCopy > maxBytes) {
                            bytesToCopy = maxBytes;
                    }
                    for (count = 0; count < bytesToCopy; count++) {
                            buffer[index++] = uid->uidByte[uidIndex + count];
                    }
            }
            // Now that the data has been copied we need to include the 8 bits in CT in currentLevelKnownBits
            if (useCascadeTag) {
                    currentLevelKnownBits += 8;
            }
            
            // Repeat anti collision loop until we can transmit all UID bits + BCC and receive a SAK - max 32 iterations.
            selectDone = false;
            while (!selectDone) {
                    // Find out how many bits and bytes to send and receive.
                    if (currentLevelKnownBits >= 32) { // All UID bits in this Cascade Level are known. This is a SELECT.
                            //Serial.print(F("SELECT: currentLevelKnownBits=")); Serial.println(currentLevelKnownBits, DEC);
                            buffer[1] = 0x70; // NVB - Number of Valid Bits: Seven whole bytes
                            // Calculate BCC - Block Check Character
                            buffer[6] = buffer[2] ^ buffer[3] ^ buffer[4] ^ buffer[5];
                            // Calculate CRC_A
                            result = PCD_CalculateCRC(mfrc, buffer, 7, &buffer[7]);
                            if (result != STATUS_OK) {
                                    return result;
                            }
                            txLastBits		= 0; // 0 => All 8 bits are valid.
                            bufferUsed		= 9;
                            // Store response in the last 3 bytes of buffer (BCC and CRC_A - not needed after tx)
                            responseBuffer	= &buffer[6];
                            responseLength	= 3;
                    }
                    else { // This is an ANTICOLLISION.
                            //Serial.print(F("ANTICOLLISION: currentLevelKnownBits=")); Serial.println(currentLevelKnownBits, DEC);
                            txLastBits		= currentLevelKnownBits % 8;
                            count			= currentLevelKnownBits / 8;	// Number of whole bytes in the UID part.
                            index			= 2 + count;					// Number of whole bytes: SEL + NVB + UIDs
                            buffer[1]		= (index << 4) + txLastBits;	// NVB - Number of Valid Bits
                            bufferUsed		= index + (txLastBits ? 1 : 0);
                            // Store response in the unused part of buffer
                            responseBuffer	= &buffer[index];
                            responseLength	= sizeof(buffer) - index;
                    }
                    
                    // Set bit adjustments
                    rxAlign = txLastBits;											// Having a separate variable is overkill. But it makes the next line easier to read.
                    PCD_WriteRegister(mfrc, BitFramingReg, (rxAlign << 4) + txLastBits);	// RxAlign = BitFramingReg[6..4]. TxLastBits = BitFramingReg[2..0]
                    
                    // Transmit the buffer and receive the response.
                    result = PCD_TransceiveData(mfrc, buffer, bufferUsed, responseBuffer, &responseLength, &txLastBits, rxAlign, false);
                    if (result == STATUS_COLLISION) { // More than one PICC in the field => collision.
                            byte valueOfCollReg = PCD_ReadRegister(mfrc, CollReg); // CollReg[7..0] bits are: ValuesAfterColl reserved CollPosNotValid CollPos[4:0]
                            if (valueOfCollReg & 0x20) { // CollPosNotValid
                                    return STATUS_COLLISION; // Without a valid collision position we cannot continue
                            }
                            byte collisionPos = valueOfCollReg & 0x1F; // Values 0-31, 0 means bit 32.
                            if (collisionPos == 0) {
                                    collisionPos = 32;
                            }
                            if (collisionPos <= currentLevelKnownBits) { // No progress - should not happen 
                                    return STATUS_INTERNAL_ERROR;
                            }
                            // Choose the PICC with the bit set.
                            currentLevelKnownBits	= collisionPos;
                            count			= currentLevelKnownBits % 8; // The bit to modify
                            checkBit		= (currentLevelKnownBits - 1) % 8;
                            index			= 1 + (currentLevelKnownBits / 8) + (count ? 1 : 0); // First byte is index 0.
                            buffer[index]	|= (1 << checkBit);
                    }
                    else if (result != STATUS_OK) {
                            return result;
                    }
                    else { // STATUS_OK
                            if (currentLevelKnownBits >= 32) { // This was a SELECT.
                                    selectDone = true; // No more anticollision 
                                    // We continue below outside the while.
                            }
                            else { // This was an ANTICOLLISION.
                                    // We now have all 32 bits of the UID in this Cascade Level
                                    currentLevelKnownBits = 32;
                                    // Run loop again to do the SELECT.
                            }
                    }
            } // End of while (!selectDone)
            
            // We do not check the CBB - it was constructed by us above.
            
            // Copy the found UID bytes from buffer[] to uid->uidByte[]
            index			= (buffer[2] == PICC_CMD_CT) ? 3 : 2; // source index in buffer[]
            bytesToCopy		= (buffer[2] == PICC_CMD_CT) ? 3 : 4;
            for (count = 0; count < bytesToCopy; count++) {
                    uid->uidByte[uidIndex + count] = buffer[index++];
            }
            
            // Check response SAK (Select Acknowledge)
            if (responseLength != 3 || txLastBits != 0) { // SAK must be exactly 24 bits (1 byte + CRC_A).
                    return STATUS_ERROR;
            }
            // Verify CRC_A - do our own calculation and store the control in buffer[2..3] - those bytes are not needed anymore.
            result = PCD_CalculateCRC(mfrc, responseBuffer, 1, &buffer[2]);
            if (result != STATUS_OK) {
                    return result;
            }
            if ((buffer[2] != responseBuffer[1]) || (buffer[3] != responseBuffer[2])) {
                    return STATUS_CRC_WRONG;
            }
            if (responseBuffer[0] & 0x04) { // Cascade bit set - UID not complete yes
                    cascadeLevel++;
            }
            else {
                    uidComplete = true;
                    uid->sak = responseBuffer[0];
            }
    } // End of while (!uidComplete)
    
    // Set correct uid->size
    uid->size = 3 * cascadeLevel + 1;

    return STATUS_OK;
} // End PICC_Select()

/**
* Instructs a PICC in state ACTIVE(*) to go to state HALT.
*
* @return STATUS_OK on success, STATUS_??? otherwise.
*/ 
StatusCode PICC_HaltA(MFRC522* mfrc) {
    StatusCode result;
    byte buffer[4];
    
    // Build command buffer
    buffer[0] = PICC_CMD_HLTA;
    buffer[1] = 0;
    // Calculate CRC_A
    result = PCD_CalculateCRC(mfrc, buffer, 2, &buffer[2]);
    if (result != STATUS_OK) {
            return result;
    }
    
    // Send the command.
    // The standard says:
    //		If the PICC responds with any modulation during a period of 1 ms after the end of the frame containing the
    //		HLTA command, this response shall be interpreted as 'not acknowledge'.
    // We interpret that this way: Only STATUS_TIMEOUT is a success.
    result = PCD_TransceiveData(mfrc, buffer, sizeof(buffer), NULL, 0, NULL, 0, false);
    if (result == STATUS_TIMEOUT) {
            return STATUS_OK;
    }
    if (result == STATUS_OK) { // That is ironically NOT ok in this case ;-)
            return STATUS_ERROR;
    }
    return result;
} // End PICC_HaltA()

/////////////////////////////////////////////////////////////////////////////////////
// Functions for communicating with MIFARE PICCs
/////////////////////////////////////////////////////////////////////////////////////

/**
* Executes the MFRC522 MFAuthent command.
* This command manages MIFARE authentication to enable a secure communication to any MIFARE Mini, MIFARE 1K and MIFARE 4K card.
* The authentication is described in the MFRC522 datasheet section 10.3.1.9 and http://www.nxp.com/documents/data_sheet/MF1S503x.pdf section 10.1.
* For use with MIFARE Classic PICCs.
* The PICC must be selected - ie in state ACTIVE(*) - before calling this function.
* Remember to call PCD_StopCrypto1() after communicating with the authenticated PICC - otherwise no new communications can start.
* 
* All keys are set to FFFFFFFFFFFFh at chip delivery.
* 
* @return STATUS_OK on success, STATUS_??? otherwise. Probably STATUS_TIMEOUT if you supply the wrong key.
*/
StatusCode PCD_Authenticate(MFRC522* mfrc, byte command, 	///< PICC_CMD_MF_AUTH_KEY_A or PICC_CMD_MF_AUTH_KEY_B
                                                                                    byte blockAddr, 	///< The block number. See numbering in the comments in the .h file.
                                                                                    MIFARE_Key *key, ///< Pointer to the Crypteo1 key to use (6 bytes)
                                                                                    Uid *uid			///< Pointer to Uid struct. The first 4 bytes of the UID is used.
                                                                                    ) {
    byte waitIRq = 0x10;		// IdleIRq
    
    // Build command buffer
    byte sendData[12];
    sendData[0] = command;
    sendData[1] = blockAddr;
    for (byte i = 0; i < MF_KEY_SIZE; i++) {	// 6 key bytes
            sendData[2+i] = key->keyByte[i];
    }
    // Use the last uid bytes as specified in http://cache.nxp.com/documents/application_note/AN10927.pdf
    // section 3.2.5 "MIFARE Classic Authentication".
    // The only missed case is the MF1Sxxxx shortcut activation,
    // but it requires cascade tag (CT) byte, that is not part of uid.
    for (byte i = 0; i < 4; i++) {				// The last 4 bytes of the UID
            sendData[8+i] = uid->uidByte[i+uid->size-4];
    }
    
    // Start the authentication.
    return PCD_CommunicateWithPICC(mfrc, PCD_MFAuthent, waitIRq, &sendData[0], sizeof(sendData), NULL,NULL,NULL,0,false);
} // End PCD_Authenticate()

/**
* Used to exit the PCD from its authenticated state.
* Remember to call this function after communicating with an authenticated PICC - otherwise no new communications can start.
*/
void PCD_StopCrypto1(MFRC522* mfrc) {
    // Clear MFCrypto1On bit
    PCD_ClearRegisterBitMask(mfrc, Status2Reg, 0x08); // Status2Reg[7..0] bits are: TempSensClear I2CForceHS reserved reserved MFCrypto1On ModemState[2:0]
} // End PCD_StopCrypto1()

/**
* Reads 16 bytes (+ 2 bytes CRC_A) from the active PICC.
* 
* For MIFARE Classic the sector containing the block must be authenticated before calling this function.
* 
* For MIFARE Ultralight only addresses 00h to 0Fh are decoded.
* The MF0ICU1 returns a NAK for higher addresses.
* The MF0ICU1 responds to the READ command by sending 16 bytes starting from the page address defined by the command argument.
* For example; if blockAddr is 03h then pages 03h, 04h, 05h, 06h are returned.
* A roll-back is implemented: If blockAddr is 0Eh, then the contents of pages 0Eh, 0Fh, 00h and 01h are returned.
* 
* The buffer must be at least 18 bytes because a CRC_A is also returned.
* Checks the CRC_A before returning STATUS_OK.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_Read(MFRC522* mfrc, 	byte blockAddr, 	///< MIFARE Classic: The block (0-0xff) number. MIFARE Ultralight: The first page to return data from.
                                                                                    byte *buffer, 	///< The buffer to store the data in
                                                                                    byte *bufferSize	///< Buffer size, at least 18 bytes. Also number of bytes returned if STATUS_OK.
                                                                            ) {
    StatusCode result;
    
    // Sanity check
    if (buffer == NULL || *bufferSize < 18) {
            return STATUS_NO_ROOM;
    }
    
    // Build command buffer
    buffer[0] = PICC_CMD_MF_READ;
    buffer[1] = blockAddr;
    // Calculate CRC_A
    result = PCD_CalculateCRC(mfrc, buffer, 2, &buffer[2]);
    if (result != STATUS_OK) {
            return result;
    }
    
    // Transmit the buffer and receive the response, validate CRC_A.
    return PCD_TransceiveData(mfrc, buffer, 4, buffer, bufferSize, NULL, 0, true);
} // End MIFARE_Read()

/**
* Writes 16 bytes to the active PICC.
* 
* For MIFARE Classic the sector containing the block must be authenticated before calling this function.
* 
* For MIFARE Ultralight the operation is called "COMPATIBILITY WRITE".
* Even though 16 bytes are transferred to the Ultralight PICC, only the least significant 4 bytes (bytes 0 to 3)
* are written to the specified address. It is recommended to set the remaining bytes 04h to 0Fh to all logic 0.
* * 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_Write(MFRC522* mfrc, 	byte blockAddr, ///< MIFARE Classic: The block (0-0xff) number. MIFARE Ultralight: The page (2-15) to write to.
                                                                                    byte *buffer, ///< The 16 bytes to write to the PICC
                                                                                    byte bufferSize	///< Buffer size, must be at least 16 bytes. Exactly 16 bytes are written.
                                                                            ) {
    StatusCode result;
    
    // Sanity check
    if (buffer == NULL || bufferSize < 16) {
            return STATUS_INVALID;
    }
    
    // Mifare Classic protocol requires two communications to perform a write.
    // Step 1: Tell the PICC we want to write to block blockAddr.
    byte cmdBuffer[2];
    cmdBuffer[0] = PICC_CMD_MF_WRITE;
    cmdBuffer[1] = blockAddr;
    result = PCD_MIFARE_Transceive(mfrc, cmdBuffer, 2, false); // Adds CRC_A and checks that the response is MF_ACK.
    if (result != STATUS_OK) {
            return result;
    }
    
    // Step 2: Transfer the data
    result = PCD_MIFARE_Transceive(mfrc, buffer, bufferSize, false); // Adds CRC_A and checks that the response is MF_ACK.
    if (result != STATUS_OK) {
            return result;
    }
    
    return STATUS_OK;
} // End MIFARE_Write()

/**
* Writes a 4 byte page to the active MIFARE Ultralight PICC.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_Ultralight_Write(MFRC522* mfrc, 	byte page, 		///< The page (2-15) to write to.
                                                                                                            byte *buffer, ///< The 4 bytes to write to the PICC
                                                                                                            byte bufferSize	///< Buffer size, must be at least 4 bytes. Exactly 4 bytes are written.
                                                                                                    ) {
    StatusCode result;
    
    // Sanity check
    if (buffer == NULL || bufferSize < 4) {
            return STATUS_INVALID;
    }
    
    // Build commmand buffer
    byte cmdBuffer[6];
    cmdBuffer[0] = PICC_CMD_UL_WRITE;
    cmdBuffer[1] = page;
    memcpy(&cmdBuffer[2], buffer, 4);
    
    // Perform the write
    result = PCD_MIFARE_Transceive(mfrc, cmdBuffer, 6, false); // Adds CRC_A and checks that the response is MF_ACK.
    if (result != STATUS_OK) {
            return result;
    }
    return STATUS_OK;
} // End MIFARE_Ultralight_Write()

/**
* MIFARE Decrement subtracts the delta from the value of the addressed block, and stores the result in a volatile memory.
* For MIFARE Classic only. The sector containing the block must be authenticated before calling this function.
* Only for blocks in "value block" mode, ie with access bits [C1 C2 C3] = [110] or [001].
* Use MIFARE_Transfer() to store the result in a block.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_Decrement(MFRC522* mfrc, byte blockAddr, ///< The block (0-0xff) number.
                                                                                            int32_t delta		///< This number is subtracted from the value of block blockAddr.
                                                                                    ) {
    return MIFARE_TwoStepHelper(mfrc, PICC_CMD_MF_DECREMENT, blockAddr, delta);
} // End MIFARE_Decrement()

/**
* MIFARE Increment adds the delta to the value of the addressed block, and stores the result in a volatile memory.
* For MIFARE Classic only. The sector containing the block must be authenticated before calling this function.
* Only for blocks in "value block" mode, ie with access bits [C1 C2 C3] = [110] or [001].
* Use MIFARE_Transfer() to store the result in a block.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_Increment(MFRC522* mfrc, byte blockAddr, ///< The block (0-0xff) number.
                                                                                            int32_t delta		///< This number is added to the value of block blockAddr.
                                                                                    ) {
    return MIFARE_TwoStepHelper(mfrc, PICC_CMD_MF_INCREMENT, blockAddr, delta);
} // End MIFARE_Increment()

/**
* MIFARE Restore copies the value of the addressed block into a volatile memory.
* For MIFARE Classic only. The sector containing the block must be authenticated before calling this function.
* Only for blocks in "value block" mode, ie with access bits [C1 C2 C3] = [110] or [001].
* Use MIFARE_Transfer() to store the result in a block.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_Restore(MFRC522* mfrc, byte blockAddr ///< The block (0-0xff) number.
                                                                                    ) {
    // The datasheet describes Restore as a two step operation, but does not explain what data to transfer in step 2.
    // Doing only a single step does not work, so I chose to transfer 0L in step two.
    return MIFARE_TwoStepHelper(mfrc, PICC_CMD_MF_RESTORE, blockAddr, 0L);
} // End MIFARE_Restore()

/**
* Helper function for the two-step MIFARE Classic protocol operations Decrement, Increment and Restore.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_TwoStepHelper(MFRC522* mfrc, byte command, ///< The command to use
                                                                                                    byte blockAddr, ///< The block (0-0xff) number.
                                                                                                    int32_t data		///< The data to transfer in step 2
                                                                                                    ) {
    StatusCode result;
    byte cmdBuffer[2]; // We only need room for 2 bytes.
    
    // Step 1: Tell the PICC the command and block address
    cmdBuffer[0] = command;
    cmdBuffer[1] = blockAddr;
    result = PCD_MIFARE_Transceive(mfrc, cmdBuffer, 2, false); // Adds CRC_A and checks that the response is MF_ACK.
    if (result != STATUS_OK) {
            return result;
    }
    
    // Step 2: Transfer the data
    result = PCD_MIFARE_Transceive(mfrc, (byte *)&data, 4, true); // Adds CRC_A and accept timeout as success.
    if (result != STATUS_OK) {
            return result;
    }
    
    return STATUS_OK;
} // End MIFARE_TwoStepHelper()

/**
* MIFARE Transfer writes the value stored in the volatile memory into one MIFARE Classic block.
* For MIFARE Classic only. The sector containing the block must be authenticated before calling this function.
* Only for blocks in "value block" mode, ie with access bits [C1 C2 C3] = [110] or [001].
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_Transfer(MFRC522* mfrc, byte blockAddr ///< The block (0-0xff) number.
                                                                                    ) {
    StatusCode result;
    byte cmdBuffer[2]; // We only need room for 2 bytes.
    
    // Tell the PICC we want to transfer the result into block blockAddr.
    cmdBuffer[0] = PICC_CMD_MF_TRANSFER;
    cmdBuffer[1] = blockAddr;
    result = PCD_MIFARE_Transceive(mfrc, 	cmdBuffer, 2, false); // Adds CRC_A and checks that the response is MF_ACK.
    if (result != STATUS_OK) {
            return result;
    }
    return STATUS_OK;
} // End MIFARE_Transfer()

/**
* Helper routine to read the current value from a Value Block.
* 
* Only for MIFARE Classic and only for blocks in "value block" mode, that
* is: with access bits [C1 C2 C3] = [110] or [001]. The sector containing
* the block must be authenticated before calling this function. 
* 
* @param[in]   blockAddr   The block (0x00-0xff) number.
* @param[out]  value       Current value of the Value Block.
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_GetValue(MFRC522* mfrc,byte blockAddr, int32_t *value) {
    StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);
    
    // Read the block
    status = MIFARE_Read(mfrc, blockAddr, buffer, &size);
    if (status == STATUS_OK) {
            // Extract the value
            *value = ((int32_t)(buffer[3])<<24) | ((int32_t)(buffer[2])<<16) | ((int32_t)(buffer[1])<<8) | (int32_t)(buffer[0]);
    }
    return status;
} // End MIFARE_GetValue()

/**
* Helper routine to write a specific value into a Value Block.
* 
* Only for MIFARE Classic and only for blocks in "value block" mode, that
* is: with access bits [C1 C2 C3] = [110] or [001]. The sector containing
* the block must be authenticated before calling this function. 
* 
* @param[in]   blockAddr   The block (0x00-0xff) number.
* @param[in]   value       New value of the Value Block.
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode MIFARE_SetValue(MFRC522* mfrc,byte blockAddr, int32_t value) {
    byte buffer[18];
    
    // Translate the int32_t into 4 bytes; repeated 2x in value block
    buffer[0] = buffer[ 8] = (value & 0xFF);
    buffer[1] = buffer[ 9] = (value & 0xFF00) >> 8;
    buffer[2] = buffer[10] = (value & 0xFF0000) >> 16;
    buffer[3] = buffer[11] = (value & 0xFF000000) >> 24;
    // Inverse 4 bytes also found in value block
    buffer[4] = ~buffer[0];
    buffer[5] = ~buffer[1];
    buffer[6] = ~buffer[2];
    buffer[7] = ~buffer[3];
    // Address 2x with inverse address 2x
    buffer[12] = buffer[14] = blockAddr;
    buffer[13] = buffer[15] = ~blockAddr;
    
    // Write the whole data block
    return MIFARE_Write(mfrc, blockAddr, buffer, 16);
} // End MIFARE_SetValue()

/**
* Authenticate with a NTAG216.
* 
* Only for NTAG216. First implemented by Gargantuanman.
* 
* @param[in]   passWord   password.
* @param[in]   pACK       result success???.
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode PCD_NTAG216_AUTH(MFRC522* mfrc,byte* passWord, byte pACK[]) //Authenticate with 32bit password
{
    // TODO: Fix cmdBuffer length and rxlength. They really should match.
    //       (Better still, rxlength should not even be necessary.)

    StatusCode result;
    byte				cmdBuffer[18]; // We need room for 16 bytes data and 2 bytes CRC_A.
    
    cmdBuffer[0] = 0x1B; //Comando de autentificacion
    
    for (byte i = 0; i<4; i++)
            cmdBuffer[i+1] = passWord[i];
    
    result = PCD_CalculateCRC(mfrc, cmdBuffer, 5, &cmdBuffer[5]);
    
    if (result!=STATUS_OK) {
            return result;
    }
    
    // Transceive the data, store the reply in cmdBuffer[]
    byte waitIRq		= 0x30;	// RxIRq and IdleIRq
//	byte cmdBufferSize	= sizeof(cmdBuffer);
    byte validBits		= 0;
    byte rxlength		= 5;
    result = PCD_CommunicateWithPICC(mfrc, PCD_Transceive, waitIRq, cmdBuffer, 7, cmdBuffer, &rxlength, &validBits, 0, false);
    
    pACK[0] = cmdBuffer[0];
    pACK[1] = cmdBuffer[1];
    
    if (result!=STATUS_OK) {
            return result;
    }
    
    return STATUS_OK;
} // End PCD_NTAG216_AUTH()


/////////////////////////////////////////////////////////////////////////////////////
// Support functions
/////////////////////////////////////////////////////////////////////////////////////

/**
* Wrapper for MIFARE protocol communication.
* Adds CRC_A, executes the Transceive command and checks that the response is MF_ACK or a timeout.
* 
* @return STATUS_OK on success, STATUS_??? otherwise.
*/
StatusCode PCD_MIFARE_Transceive(MFRC522* mfrc, byte *sendData, 	///< Pointer to the data to transfer to the FIFO. Do NOT include the CRC_A.
                                                                                                    byte sendLen, 	///< Number of bytes in sendData.
                                                                                                    bool acceptTimeout	///< True => A timeout is also success
                                                                                            ) {
    StatusCode result;
    byte cmdBuffer[18]; // We need room for 16 bytes data and 2 bytes CRC_A.
    
    // Sanity check
    if (sendData == NULL || sendLen > 16) {
            return STATUS_INVALID;
    }
    
    // Copy sendData[] to cmdBuffer[] and add CRC_A
    memcpy(cmdBuffer, sendData, sendLen);
    result = PCD_CalculateCRC(mfrc, cmdBuffer, sendLen, &cmdBuffer[sendLen]);
    if (result != STATUS_OK) { 
            return result;
    }
    sendLen += 2;
    
    // Transceive the data, store the reply in cmdBuffer[]
    byte waitIRq = 0x30;		// RxIRq and IdleIRq
    byte cmdBufferSize = sizeof(cmdBuffer);
    byte validBits = 0;
    result = PCD_CommunicateWithPICC(mfrc, PCD_Transceive, waitIRq, cmdBuffer, sendLen, cmdBuffer, &cmdBufferSize, &validBits, 0, false);
    if (acceptTimeout && result == STATUS_TIMEOUT) {
            return STATUS_OK;
    }
    if (result != STATUS_OK) {
            return result;
    }
    // The PICC must reply with a 4 bit ACK
    if (cmdBufferSize != 1 || validBits != 4) {
            return STATUS_ERROR;
    }
    if (cmdBuffer[0] != MF_ACK) {
            return STATUS_MIFARE_NACK;
    }
    return STATUS_OK;
} // End PCD_MIFARE_Transceive()

/**
* Returns a char pointer to a status code name.
* 
* @return const char *
*/
const char *GetStatusCodeName(StatusCode code	///< One of the StatusCode enums.
                                                                            ) {
    switch (code) {
            case STATUS_OK:				return "Success.";
            case STATUS_ERROR:			return "Error in communication.";
            case STATUS_COLLISION:		return "Collision detected.";
            case STATUS_TIMEOUT:		return "Timeout in communication.";
            case STATUS_NO_ROOM:		return "A buffer is not big enough.";
            case STATUS_INTERNAL_ERROR:	return "Internal error in the code. Should not happen.";
            case STATUS_INVALID:		return "Invalid argument.";
            case STATUS_CRC_WRONG:		return "The CRC_A does not match.";
            case STATUS_MIFARE_NACK:	return "A MIFARE PICC responded with NAK.";
            default:					return "Unknown error";
    }
} // End GetStatusCodeName()

/**
* Translates the SAK (Select Acknowledge) to a PICC type.
* 
* @return PICC_Type
*/
PICC_Type PICC_GetType(byte sak		///< The SAK byte returned from PICC_Select().
                                                                            ) {
    // http://www.nxp.com/documents/application_note/AN10833.pdf 
    // 3.2 Coding of Select Acknowledge (SAK)
    // ignore 8-bit (iso14443 starts with LSBit = bit 1)
    // fixes wrong type for manufacturer Infineon (http://nfc-tools.org/index.php?title=ISO14443A)
    sak &= 0x7F;
    switch (sak) {
            case 0x04:	return PICC_TYPE_NOT_COMPLETE;	// UID not complete
            case 0x09:	return PICC_TYPE_MIFARE_MINI;
            case 0x08:	return PICC_TYPE_MIFARE_1K;
            case 0x18:	return PICC_TYPE_MIFARE_4K;
            case 0x00:	return PICC_TYPE_MIFARE_UL;
            case 0x10:
            case 0x11:	return PICC_TYPE_MIFARE_PLUS;
            case 0x01:	return PICC_TYPE_TNP3XXX;
            case 0x20:	return PICC_TYPE_ISO_14443_4;
            case 0x40:	return PICC_TYPE_ISO_18092;
            default:	return PICC_TYPE_UNKNOWN;
    }
} // End PICC_GetType()

/**
* Returns a char pointer to the PICC type name.
* 
* @return const char *
*/
const char *PICC_GetTypeName(PICC_Type piccType	///< One of the PICC_Type enums.
                                                                                                    ) {
    switch (piccType) {
            case PICC_TYPE_ISO_14443_4:		return "PICC compliant with ISO/IEC 14443-4";
            case PICC_TYPE_ISO_18092:		return "PICC compliant with ISO/IEC 18092 (NFC)";
            case PICC_TYPE_MIFARE_MINI:		return "MIFARE Mini, 320 bytes";
            case PICC_TYPE_MIFARE_1K:		return "MIFARE 1KB";
            case PICC_TYPE_MIFARE_4K:		return "MIFARE 4KB";
            case PICC_TYPE_MIFARE_UL:		return "MIFARE Ultralight or Ultralight C";
            case PICC_TYPE_MIFARE_PLUS:		return "MIFARE Plus";
            case PICC_TYPE_MIFARE_DESFIRE:	return "MIFARE DESFire";
            case PICC_TYPE_TNP3XXX:			return "MIFARE TNP3XXX";
            case PICC_TYPE_NOT_COMPLETE:	return "SAK indicates UID is not complete.";
            case PICC_TYPE_UNKNOWN:
            default:						return "Unknown type";
    }
} // End PICC_GetTypeName()

/**
* Dumps debug info about the connected PCD to Serial.
* Shows all known firmware versions
*/
void PCD_DumpVersionToSerial(MFRC522* mfrc) {
    // Get the MFRC522 firmware version
	byte v = PCD_ReadRegister(mfrc, VersionReg);
	printf("Firmware Version: 0x");
	printf("%d", v);
	// Lookup which version
	switch(v) {
		case 0x88: printf(" = (clone)\n");  break;
		case 0x90: printf(" = v0.0\n");     break;
		case 0x91: printf(" = v1.0\n");     break;
		case 0x92: printf(" = v2.0\n");     break;
		case 0x12: printf(" = counterfeit chip\n");     break;
		default:   printf(" = (unknown)\n");
	}
	// When 0x00 or 0xFF is returned, communication probably failed
	if ((v == 0x00) || (v == 0xFF))
		printf("WARNING: Communication failure, is the MFRC522 properly connected?");
} // End PCD_DumpVersionToSerial()

/**
 * Dumps debug info about the selected PICC to Serial.
 * On success the PICC is halted after dumping the data.
 * For MIFARE Classic the factory default key of 0xFFFFFFFFFFFF is tried.  
 */
void PICC_DumpToSerial(MFRC522* mfrc,Uid *uid	///< Pointer to Uid struct returned from a successful PICC_Select().
								) {
	MIFARE_Key key;
	
	// Dump UID, SAK and Type
	PICC_DumpDetailsToSerial(mfrc, uid);
	
	// Dump contents
	PICC_Type piccType = PICC_GetType(uid->sak);
	switch (piccType) {
		case PICC_TYPE_MIFARE_MINI:
		case PICC_TYPE_MIFARE_1K:
		case PICC_TYPE_MIFARE_4K:
			// All keys are set to FFFFFFFFFFFFh at chip delivery from the factory.
			for (byte i = 0; i < 6; i++) {
				key.keyByte[i] = 0xFF;
			}
			PICC_DumpMifareClassicToSerial(mfrc, uid, piccType, &key);
			break;
			
		case PICC_TYPE_MIFARE_UL:
			PICC_DumpMifareUltralightToSerial(mfrc);
			break;
			
		case PICC_TYPE_ISO_14443_4:
		case PICC_TYPE_MIFARE_DESFIRE:
		case PICC_TYPE_ISO_18092:
		case PICC_TYPE_MIFARE_PLUS:
		case PICC_TYPE_TNP3XXX:
			printf("Dumping memory contents not implemented for that PICC type.\n");
			break;
			
		case PICC_TYPE_UNKNOWN:
		case PICC_TYPE_NOT_COMPLETE:
		default:
			break; // No memory dump here
	}
	
	printf("\n");
	PICC_HaltA(mfrc); // Already done if it was a MIFARE Classic PICC.
} // End PICC_DumpToSerial()

/**
 * Dumps card info (UID,SAK,Type) about the selected PICC to Serial.
 */
void PICC_DumpDetailsToSerial(MFRC522* mfrc,Uid *uid	///< Pointer to Uid struct returned from a successful PICC_Select().
									) {
	// UID
	printf("Card UID:");
	for (byte i = 0; i < uid->size; i++) {
		if(uid->uidByte[i] < 0x10)
			printf(" 0");
		else
			printf(" ");
		printf("%x", uid->uidByte[i]);
	} 
	printf("\n");
	
	// SAK
	printf("Card SAK: ");
	if(uid->sak < 0x10)
		printf("0");
	printf("%x", uid->sak);
	
	// (suggested) PICC type
	PICC_Type piccType = PICC_GetType(uid->sak);
	printf("PICC type: ");
	printf("%s", PICC_GetTypeName(piccType));
} // End PICC_DumpDetailsToSerial()

/**
 * Dumps memory contents of a MIFARE Classic PICC.
 * On success the PICC is halted after dumping the data.
 */
void PICC_DumpMifareClassicToSerial(MFRC522* mfrc, Uid *uid, 		///< Pointer to Uid struct returned from a successful PICC_Select().
												PICC_Type piccType, ///< One of the PICC_Type enums.
												MIFARE_Key *key		///< Key A used for all sectors.
											) {
	byte no_of_sectors = 0;
	switch (piccType) {
		case PICC_TYPE_MIFARE_MINI:
			// Has 5 sectors * 4 blocks/sector * 16 bytes/block = 320 bytes.
			no_of_sectors = 5;
			break;
			
		case PICC_TYPE_MIFARE_1K:
			// Has 16 sectors * 4 blocks/sector * 16 bytes/block = 1024 bytes.
			no_of_sectors = 16;
			break;
			
		case PICC_TYPE_MIFARE_4K:
			// Has (32 sectors * 4 blocks/sector + 8 sectors * 16 blocks/sector) * 16 bytes/block = 4096 bytes.
			no_of_sectors = 40;
			break;
			
		default: // Should not happen. Ignore.
			break;
	}
	
	// Dump sectors, highest address first.
	if (no_of_sectors) {
		printf("Sector Block   0  1  2  3   4  5  6  7   8  9 10 11  12 13 14 15  AccessBits\n");
		for (int8_t i = no_of_sectors - 1; i >= 0; i--) {
			PICC_DumpMifareClassicSectorToSerial(mfrc, uid, key, i);
		}
	}
	PICC_HaltA(mfrc); // Halt the PICC before stopping the encrypted session.
	PCD_StopCrypto1(mfrc);
} // End PICC_DumpMifareClassicToSerial()

/**
 * Dumps memory contents of a sector of a MIFARE Classic PICC.
 * Uses PCD_Authenticate(), MIFARE_Read() and PCD_StopCrypto1.
 * Always uses PICC_CMD_MF_AUTH_KEY_A because only Key A can always read the sector trailer access bits.
 */
void PICC_DumpMifareClassicSectorToSerial(MFRC522* mfrc,Uid *uid, 		///< Pointer to Uid struct returned from a successful PICC_Select().
													MIFARE_Key *key, ///< Key A for the sector.
													byte sector			///< The sector to dump, 0..39.
													) {
	StatusCode status;
	byte firstBlock;		// Address of lowest address to dump actually last block dumped)
	byte no_of_blocks;		// Number of blocks in sector
	bool isSectorTrailer;	// Set to true while handling the "last" (ie highest address) in the sector.
	
	// The access bits are stored in a peculiar fashion.
	// There are four groups:
	//		g[3]	Access bits for the sector trailer, block 3 (for sectors 0-31) or block 15 (for sectors 32-39)
	//		g[2]	Access bits for block 2 (for sectors 0-31) or blocks 10-14 (for sectors 32-39)
	//		g[1]	Access bits for block 1 (for sectors 0-31) or blocks 5-9 (for sectors 32-39)
	//		g[0]	Access bits for block 0 (for sectors 0-31) or blocks 0-4 (for sectors 32-39)
	// Each group has access bits [C1 C2 C3]. In this code C1 is MSB and C3 is LSB.
	// The four CX bits are stored together in a nible cx and an inverted nible cx_.
	byte c1, c2, c3;		// Nibbles
	byte c1_, c2_, c3_;		// Inverted nibbles
	bool invertedError;		// True if one of the inverted nibbles did not match
	byte g[4];				// Access bits for each of the four groups.
	byte group;				// 0-3 - active group for access bits
	bool firstInGroup;		// True for the first block dumped in the group
	
	// Determine position and size of sector.
	if (sector < 32) { // Sectors 0..31 has 4 blocks each
		no_of_blocks = 4;
		firstBlock = sector * no_of_blocks;
	}
	else if (sector < 40) { // Sectors 32-39 has 16 blocks each
		no_of_blocks = 16;
		firstBlock = 128 + (sector - 32) * no_of_blocks;
	}
	else { // Illegal input, no MIFARE Classic PICC has more than 40 sectors.
		return;
	}
		
	// Dump blocks, highest address first.
	byte byteCount;
	byte buffer[18];
	byte blockAddr;
	isSectorTrailer = true;
	invertedError = false;	// Avoid "unused variable" warning.
	for (int8_t blockOffset = no_of_blocks - 1; blockOffset >= 0; blockOffset--) {
		blockAddr = firstBlock + blockOffset;
		// Sector number - only on first line
		if (isSectorTrailer) {
			if(sector < 10)
				printf("   "); // Pad with spaces
			else
				printf("  "); // Pad with spaces
			printf("%d", sector);
			printf("   ");
		}
		else {
			printf("       ");
		}
		// Block number
		if(blockAddr < 10)
			printf("   "); // Pad with spaces
		else {
			if(blockAddr < 100)
				printf("  "); // Pad with spaces
			else
				printf(" "); // Pad with spaces
		}
		printf("%d", blockAddr);
		printf("  ");
		// Establish encrypted communications before reading the first block
		if (isSectorTrailer) {
			status = PCD_Authenticate(mfrc, PICC_CMD_MF_AUTH_KEY_A, firstBlock, key, uid);
			if (status != STATUS_OK) {
				printf("PCD_Authenticate() failed: ");
				printf("%s\n", GetStatusCodeName(status));
				return;
			}
		}
		// Read block
		byteCount = sizeof(buffer);
		status = MIFARE_Read(mfrc, blockAddr, buffer, &byteCount);
		if (status != STATUS_OK) {
			printf("MIFARE_Read() failed: ");
			printf("%s\n", GetStatusCodeName(status));
			continue;
		}
		// Dump data
		for (byte index = 0; index < 16; index++) {
			if(buffer[index] < 0x10)
				printf(" 0");
			else
				printf(" ");
			printf("%x", buffer[index]);
			if ((index % 4) == 3) {
				printf(" ");
			}
		}
		// Parse sector trailer data
		if (isSectorTrailer) {
			c1  = buffer[7] >> 4;
			c2  = buffer[8] & 0xF;
			c3  = buffer[8] >> 4;
			c1_ = buffer[6] & 0xF;
			c2_ = buffer[6] >> 4;
			c3_ = buffer[7] & 0xF;
			invertedError = (c1 != (~c1_ & 0xF)) || (c2 != (~c2_ & 0xF)) || (c3 != (~c3_ & 0xF));
			g[0] = ((c1 & 1) << 2) | ((c2 & 1) << 1) | ((c3 & 1) << 0);
			g[1] = ((c1 & 2) << 1) | ((c2 & 2) << 0) | ((c3 & 2) >> 1);
			g[2] = ((c1 & 4) << 0) | ((c2 & 4) >> 1) | ((c3 & 4) >> 2);
			g[3] = ((c1 & 8) >> 1) | ((c2 & 8) >> 2) | ((c3 & 8) >> 3);
			isSectorTrailer = false;
		}
		
		// Which access group is this block in?
		if (no_of_blocks == 4) {
			group = blockOffset;
			firstInGroup = true;
		}
		else {
			group = blockOffset / 5;
			firstInGroup = (group == 3) || (group != (blockOffset + 1) / 5);
		}
		
		if (firstInGroup) {
			// Print access bits
			printf(" [ ");
			printf("%d", (g[group] >> 2) & 1); 
                        printf(" ");
			printf("%d", (g[group] >> 1) & 1); 
                        printf(" ");
			printf("%d", (g[group] >> 0) & 1);
			printf(" ] ");
			if (invertedError) {
				printf(" Inverted access bits did not match! ");
			}
		}
		
		if (group != 3 && (g[group] == 1 || g[group] == 6)) { // Not a sector trailer, a value block
			int32_t value = ((int32_t)(buffer[3])<<24) | ((int32_t)(buffer[2])<<16) | ((int32_t)(buffer[1])<<8) | (int32_t)(buffer[0]);
			printf(" Value=0x"); 
                        printf("%x", value);
			printf(" Adr=0x"); 
                        printf("%x", buffer[12]);
		}
		printf("\n");
	}
	
	return;
} // End PICC_DumpMifareClassicSectorToSerial()

/**
 * Dumps memory contents of a MIFARE Ultralight PICC.
 */
void PICC_DumpMifareUltralightToSerial(MFRC522* mfrc) {
	StatusCode status;
	byte byteCount;
	byte buffer[18];
	byte i;
	
	printf("Page  0  1  2  3");
	// Try the mpages of the original Ultralight. Ultralight C has more pages.
	for (byte page = 0; page < 16; page +=4) { // Read returns data for 4 pages at a time.
		// Read pages
		byteCount = sizeof(buffer);
		status = MIFARE_Read(mfrc, page, buffer, &byteCount);
		if (status != STATUS_OK) {
			printf("MIFARE_Read() failed: ");
			printf("%s\n", GetStatusCodeName(status));
			break;
		}
		// Dump data
		for (byte offset = 0; offset < 4; offset++) {
			i = page + offset;
			if(i < 10)
				printf("  "); // Pad with spaces
			else
				printf(" "); // Pad with spaces
			printf("%d", i);
			printf("  ");
			for (byte index = 0; index < 4; index++) {
				i = 4 * offset + index;
				if(buffer[i] < 0x10)
					printf(" 0");
				else
					printf(" ");
				printf("%x", buffer[i]);
			}
                        printf("\n");
		}
	}
} // End PICC_DumpMifareUltralightToSerial()

/**
 * Calculates the bit pattern needed for the specified access bits. In the [C1 C2 C3] tuples C1 is MSB (=4) and C3 is LSB (=1).
 */
void MIFARE_SetAccessBits(MFRC522* mfrc, byte *accessBitBuffer, ///< Pointer to byte 6, 7 and 8 in the sector trailer. Bytes [0..2] will be set.
									byte g0, 			///< Access bits [C1 C2 C3] for block 0 (for sectors 0-31) or blocks 0-4 (for sectors 32-39)
									byte g1, 			///< Access bits C1 C2 C3] for block 1 (for sectors 0-31) or blocks 5-9 (for sectors 32-39)
									byte g2, 			///< Access bits C1 C2 C3] for block 2 (for sectors 0-31) or blocks 10-14 (for sectors 32-39)
									byte g3					///< Access bits C1 C2 C3] for the sector trailer, block 3 (for sectors 0-31) or block 15 (for sectors 32-39)
								) {
	byte c1 = ((g3 & 4) << 1) | ((g2 & 4) << 0) | ((g1 & 4) >> 1) | ((g0 & 4) >> 2);
	byte c2 = ((g3 & 2) << 2) | ((g2 & 2) << 1) | ((g1 & 2) << 0) | ((g0 & 2) >> 1);
	byte c3 = ((g3 & 1) << 3) | ((g2 & 1) << 2) | ((g1 & 1) << 1) | ((g0 & 1) << 0);
	
	accessBitBuffer[0] = (~c2 & 0xF) << 4 | (~c1 & 0xF);
	accessBitBuffer[1] =          c1 << 4 | (~c3 & 0xF);
	accessBitBuffer[2] =          c3 << 4 | c2;
} // End MIFARE_SetAccessBits()


/**
 * Performs the "magic sequence" needed to get Chinese UID changeable
 * Mifare cards to allow writing to sector 0, where the card UID is stored.
 *
 * Note that you do not need to have selected the card through REQA or WUPA,
 * this sequence works immediately when the card is in the reader vicinity.
 * This means you can use this method even on "bricked" cards that your reader does
 * not recognise anymore (see MIFARE_UnbrickUidSector).
 * 
 * Of course with non-bricked devices, you're free to select them before calling this function.
 */
bool MIFARE_OpenUidBackdoor(MFRC522* mfrc,bool logErrors) {
	// Magic sequence:
	// > 50 00 57 CD (HALT + CRC)
	// > 40 (7 bits only)
	// < A (4 bits only)
	// > 43
	// < A (4 bits only)
	// Then you can write to sector 0 without authenticating
	
	PICC_HaltA(mfrc); // 50 00 57 CD
	
	byte cmd = 0x40;
	byte validBits = 7; /* Our command is only 7 bits. After receiving card response,
						  this will contain amount of valid response bits. */
	byte response[32]; // Card's response is written here
	byte received = sizeof(response);
	StatusCode status = PCD_TransceiveData(mfrc, &cmd, (byte)1, response, &received, &validBits, (byte)0, false); // 40
	if(status != STATUS_OK) {
		if(logErrors) {
			printf("Card did not respond to 0x40 after HALT command. Are you sure it is a UID changeable one?");
			printf("Error name: ");
			printf("%s\n", GetStatusCodeName(status));
		}
		return false;
	}
	if (received != 1 || response[0] != 0x0A) {
		if (logErrors) {
			printf("Got bad response on backdoor 0x40 command: ");
			printf("%x", response[0]);
			printf(" (");
			printf("%d", validBits);
			printf(" valid bits)\r\n");
		}
		return false;
	}
	
	cmd = 0x43;
	validBits = 8;
	status = PCD_TransceiveData(mfrc, &cmd, (byte)1, response, &received, &validBits, (byte)0, false); // 43
	if(status != STATUS_OK) {
		if(logErrors) {
			printf("Error in communication at command 0x43, after successfully executing 0x40");
			printf("Error name: ");
			printf("%s\n", GetStatusCodeName(status));
		}
		return false;
	}
	if (received != 1 || response[0] != 0x0A) {
		if (logErrors) {
			printf("Got bad response on backdoor 0x43 command: ");
			printf("%x", response[0]);
			printf(" (");
			printf("%d", validBits);
			printf(" valid bits)\r\n");
		}
		return false;
	}
	
	// You can now write to sector 0 without authenticating!
	return true;
} // End MIFARE_OpenUidBackdoor()

/**
 * Reads entire block 0, including all manufacturer data, and overwrites
 * that block with the new UID, a freshly calculated BCC, and the original
 * manufacturer data.
 *
 * It assumes a default KEY A of 0xFFFFFFFFFFFF.
 * Make sure to have selected the card before this function is called.
 */
bool MIFARE_SetUid(MFRC522* mfrc,byte *newUid, byte uidSize, bool logErrors) {
	
	// UID + BCC byte can not be larger than 16 together
	if (!newUid || !uidSize || uidSize > 15) {
		if (logErrors) {
			printf("New UID buffer empty, size 0, or size > 15 given\n");
		}
		return false;
	}
	
	// Authenticate for reading
	MIFARE_Key key = { 
            .keyByte = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
        }; 
	StatusCode status = PCD_Authenticate(mfrc, PICC_CMD_MF_AUTH_KEY_A, (byte)1, &key, &mfrc->uid);
	if (status != STATUS_OK) {
		
		if (status == STATUS_TIMEOUT) {
			// We get a read timeout if no card is selected yet, so let's select one
			
			// Wake the card up again if sleeping
//			  byte atqa_answer[2];
//			  byte atqa_size = 2;
//			  PICC_WakeupA(mfrc, atqa_answer, &atqa_size);
			
			if (!PICC_IsNewCardPresent(mfrc) || !PICC_ReadCardSerial(mfrc)) {
				printf("No card was previously selected, and none are available. Failed to set UID.\n");
				return false;
			}
			
			status = PCD_Authenticate(mfrc, PICC_CMD_MF_AUTH_KEY_A, (byte)1, &key, &mfrc->uid);
			if (status != STATUS_OK) {
				// We tried, time to give up
				if (logErrors) {
					printf("Failed to authenticate to card for reading, could not set UID: \n");
					printf("%s\n", GetStatusCodeName(status));
				}
				return false;
			}
		}
		else {
			if (logErrors) {
				printf("PCD_Authenticate() failed: ");
				printf("%s\n", GetStatusCodeName(status));
			}
			return false;
		}
	}
	
	// Read block 0
	byte block0_buffer[18];
	byte byteCount = sizeof(block0_buffer);
	status = MIFARE_Read(mfrc, (byte)0, block0_buffer, &byteCount);
	if (status != STATUS_OK) {
		if (logErrors) {
			printf("MIFARE_Read() failed: ");
			printf("%s\n", GetStatusCodeName(status));
			printf("Are you sure your KEY A for sector 0 is 0xFFFFFFFFFFFF?\n");
		}
		return false;
	}
	
	// Write new UID to the data we just read, and calculate BCC byte
	byte bcc = 0;
	for (uint8_t i = 0; i < uidSize; i++) {
		block0_buffer[i] = newUid[i];
		bcc ^= newUid[i];
	}
	
	// Write BCC byte to buffer
	block0_buffer[uidSize] = bcc;
	
	// Stop encrypted traffic so we can send raw bytes
	PCD_StopCrypto1(mfrc);
	
	// Activate UID backdoor
	if (!MIFARE_OpenUidBackdoor(mfrc, logErrors)) {
		if (logErrors) {
			printf("Activating the UID backdoor failed.\n");
		}
		return false;
	}
	
	// Write modified block 0 back to card
	status = MIFARE_Write(mfrc, (byte)0, block0_buffer, (byte)16);
	if (status != STATUS_OK) {
		if (logErrors) {
			printf("MIFARE_Write() failed: ");
			printf("%s\n", GetStatusCodeName(status));
		}
		return false;
	}
	
	// Wake the card up again
	byte atqa_answer[2];
	byte atqa_size = 2;
	PICC_WakeupA(mfrc, atqa_answer, &atqa_size);
	
	return true;
}

/**
 * Resets entire sector 0 to zeroes, so the card can be read again by readers.
 */
bool MIFARE_UnbrickUidSector(MFRC522* mfrc,bool logErrors) {
	MIFARE_OpenUidBackdoor(mfrc, logErrors);
	
	byte block0_buffer[] = {0x01, 0x02, 0x03, 0x04, 0x04, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	
	
	// Write modified block 0 back to card
	StatusCode status = MIFARE_Write(mfrc, (byte)0, block0_buffer, (byte)16);
	if (status != STATUS_OK) {
		if (logErrors) {
			printf("MIFARE_Write() failed: ");
			printf("%s\n", GetStatusCodeName(status));
		}
		return false;
	}
	return true;
}

/////////////////////////////////////////////////////////////////////////////////////
// Convenience functions - does not add extra functionality
/////////////////////////////////////////////////////////////////////////////////////

/**
 * Returns true if a PICC responds to PICC_CMD_REQA.
 * Only "new" cards in state IDLE are invited. Sleeping cards in state HALT are ignored.
 * 
 * @return bool
 */
bool PICC_IsNewCardPresent(MFRC522* mfrc) {
	byte bufferATQA[2];
	byte bufferSize = sizeof(bufferATQA);

	// Reset baud rates
	PCD_WriteRegister(mfrc, TxModeReg, 0x00);
	PCD_WriteRegister(mfrc, RxModeReg, 0x00);
	// Reset ModWidthReg
	PCD_WriteRegister(mfrc, ModWidthReg, 0x26);

	StatusCode result = PICC_RequestA(mfrc, bufferATQA, &bufferSize);
	return (result == STATUS_OK || result == STATUS_COLLISION);
} // End PICC_IsNewCardPresent()

/**
 * Simple wrapper around PICC_Select.
 * Returns true if a UID could be read.
 * Remember to call PICC_IsNewCardPresent(), PICC_RequestA() or PICC_WakeupA() first.
 * The read UID is available in the class variable uid.
 * 
 * @return bool
 */
bool PICC_ReadCardSerial(MFRC522* mfrc) {
	StatusCode result = PICC_Select_Without_bytes(mfrc, &mfrc->uid);
	return (result == STATUS_OK);
} // End 

/*
static void IRAM_ATTR spi_master_transmit(spi_master_mode_t trans_mode, uint32_t* data)
{
    spi_trans_t trans;
    uint16_t cmd;
    uint32_t addr = 0x0;

    memset(&trans, 0x0, sizeof(trans));
    trans.bits.val = 0;            // clear all bit

    if (trans_mode == SPI_WRITE) {
        cmd = SPI_MASTER_WRITE_DATA_TO_SLAVE_CMD;
        trans.bits.mosi = 8 * ESP8266_SPI_MAX_DATA_LENGTH;             // One time transmit only support 64bytes
        trans.mosi = data;
    } else if (trans_mode == SPI_READ) {
        cmd = SPI_MASTER_READ_DATA_FROM_SLAVE_CMD;
        trans.bits.miso = 8 * ESP8266_SPI_MAX_DATA_LENGTH;
        trans.miso = data;
    }

    trans.bits.cmd = 8 * 1;
    trans.bits.addr = 8 * 1;     // transmit data will use 8bit address
    trans.cmd = &cmd;
    trans.addr = &addr;

    spi_trans(HSPI_HOST, &trans);
}
*/

/* SPI master send length, format: 8bit command(value:1) + 8 bit data length */
void IRAM_ATTR spi_master_send_byte(byte data)
{
    // TODO What the fuck are those trans.addr !!! just set to 0 and hope
    uint32_t data_send_big =  (uint32_t) data;
    printf("into send_byte %x\n", data_send_big);
    esp_err_t err;
    spi_trans_t trans;
    uint16_t cmd = SPI_MASTER_WRITE_DATA_TO_SLAVE_CMD;
    memset(&trans, 0x0, sizeof(trans));
    trans.bits.val = 0;
    trans.bits.cmd = 8 * 1;
    trans.bits.addr = 0;          // transmit status do not use address bit
    trans.bits.mosi = 8 * 1;      // mosi length given through byte length
    trans.cmd = &cmd;
    trans.addr = NULL;
    trans.mosi = &data_send_big;
    if ((err = spi_trans(HSPI_HOST, &trans)) != ESP_OK) {
        printf("%s: spi_trans() error: %s", TAG, esp_err_to_name(err));
    }
    printf("out of send_byte\n");
}

/* SPI master revecive length, format: 8bit command(value:4) + 8bit status length */
byte IRAM_ATTR spi_master_get_byte_and_send_byte(byte data_send)
{
    uint32_t data_send_big =  (uint32_t) data_send;
    printf("into get and send_byte %x\n", data_send_big);
    spi_trans_t trans;
    uint32_t data_received = 0;
    uint16_t cmd = SPI_MASTER_READ_DATA_FROM_SLAVE_CMD;
    memset(&trans, 0x0, sizeof(trans));
    trans.bits.val = 0;
    trans.cmd = &cmd;
    trans.miso =  &data_received;
    trans.addr = NULL;
    trans.bits.cmd = 8 * 1;
    trans.bits.miso = 8 * 1;

    trans.bits.mosi = 8 * 1;      // mosi length given through byte length
    trans.mosi = &data_send_big;

    esp_err_t err;
    if ((err = spi_trans(HSPI_HOST, &trans)) != ESP_OK) {
        printf("%s: spi_trans() error: %s", TAG, esp_err_to_name(err));
    }
    printf("out of get and send_byte %d\n", data_received);
    return (byte) data_received;
}
