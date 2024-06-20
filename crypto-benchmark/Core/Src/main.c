/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "crc.h"
#include "usart.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "crypto.h"
#include "stdio.h"
#include "string.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
/* Private typedef -----------------------------------------------------------*/
typedef enum {FAILED = 0, PASSED = !FAILED} TestStatus;
/* Private define ------------------------------------------------------------*/
#define PLAINTEXT_LENGTH 16
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
#define USE_CHACHA


#ifdef USE_AES_CBC
const uint8_t Plaintext[PLAINTEXT_LENGTH] =
  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x5f, 0x12
  };

uint8_t Key[CRL_AES128_KEY] =
  {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
  };

uint8_t IV[CRL_AES_BLOCK] =
  {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };

uint8_t OutputMessage[PLAINTEXT_LENGTH];
uint32_t OutputMessageLength = 0;

const uint8_t Expected_Ciphertext[PLAINTEXT_LENGTH] =
  {
   0xDC, 0x19, 0xE0, 0xF1, 0x38, 0x8B, 0x06, 0x21, 0x1C, 0xD1, 0xB2, 0x7E, 0xA2, 0x10, 0xD8, 0xD0
  };

int32_t STM32_AES_CBC_Encrypt(uint8_t*  InputMessage,
                              uint32_t  InputMessageLength,
                              uint8_t  *AES192_Key,
                              uint8_t  *InitializationVector,
                              uint32_t  IvLength,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength);

int32_t STM32_AES_CBC_Decrypt(uint8_t*  InputMessage,
                              uint32_t  InputMessageLength,
                              uint8_t  *AES192_Key,
                              uint8_t  *InitializationVector,
                              uint32_t  IvLength,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength);

#endif

#ifdef USE_AES_EBC
const uint8_t Plaintext_ECB[PLAINTEXT_LENGTH] =
  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x5f, 0x12
  };

uint8_t Key_ECB[CRL_AES128_KEY] =
  {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
  };

uint8_t OutputMessage_ECB[PLAINTEXT_LENGTH];
uint32_t OutputMessageLength_ECB = 0;

const uint8_t Expected_Ciphertext_ECB[PLAINTEXT_LENGTH] =
  {
    0x8D, 0x16, 0x7C, 0x19, 0x9E, 0x62, 0xFD, 0x1D, 0x3F, 0x9F, 0x0D, 0x68, 0x38, 0xC5, 0xF8, 0xA4
  };

int32_t STM32_AES_ECB_Encrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t  *AES256_Key,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength);

int32_t STM32_AES_ECB_Decrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t *AES256_Key,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength);
#endif

TestStatus Buffercmp(const uint8_t* pBuffer,
                     uint8_t* pBuffer1,
                     uint16_t BufferLength);


#ifdef USE_RSA
uint8_t preallocated_buffer[4096]; /* buffer required for internal allocation of memory */
/******************************************************************************/
/************************** RSA 2048 Test Vector  ****************************/
/******************************************************************************/
const uint8_t Message[] =
  {
    0xEB, 0x39, 0x49, 0x2F, 0x73, 0xED, 0x5E, 0x1C, 0x5E,
    0x45, 0xAF, 0xB5, 0x7F, 0xC1, 0xD6, 0xFE,
  };

const uint8_t Modulus[] =
  {
    0xB5, 0x05, 0xFC, 0xA2, 0xCA, 0x33, 0x48, 0xD5, 0x9B, 0xF3, 0x00, 0x5F, 0x7C, 0xFD, 0xC4, 0x56, 0x4C, 0x25, 0x07,
    0x67, 0xE9, 0xC9, 0x40, 0x24, 0x69, 0x79, 0x61, 0x41, 0x98, 0x1D, 0x6A, 0xF5, 0x6A, 0x1A, 0x84, 0xB5, 0xA9, 0xA4,
    0xB3, 0x33, 0x5F, 0xA0, 0x25, 0xA8, 0x7F, 0x4B, 0x4D, 0x0B, 0xA0, 0x60, 0xB8, 0xBE, 0xF9, 0x34, 0x0B, 0xE4, 0x5F,
    0xDB, 0x05, 0x76, 0x20, 0x38, 0x90, 0xA0, 0x71, 0xCE, 0xE9, 0xB0, 0x59, 0x4B, 0x95, 0x12, 0x7B, 0xB4, 0x80, 0xED,
    0xC7, 0x43, 0xBD, 0xCE, 0x27, 0xFD, 0x2B, 0xEC, 0xD0, 0x33, 0x00, 0x24, 0x32, 0x9E, 0xED, 0xAF, 0x3C, 0x1A, 0x12,
    0x13, 0xB2, 0x8D, 0x32, 0xD1, 0x83, 0xEA, 0xF4, 0x1A, 0x9A, 0x46, 0x3A, 0x08, 0x8C, 0xD4, 0xBA, 0x67, 0xDA, 0x91,
    0x26, 0x79, 0x49, 0xBA, 0xAA, 0x54, 0x26, 0x56, 0x03, 0x76, 0xA7, 0x70, 0x58, 0x9E, 0xA8, 0x37, 0x60, 0xB8, 0xC5,
    0xC1, 0xF9, 0xDD, 0x54, 0x18, 0x4D, 0x7F, 0x91, 0xCC, 0x0A, 0xBB, 0x08, 0xC3, 0x05, 0x3C, 0x04, 0x8B, 0xDC, 0xD0,
    0xE9, 0x7A, 0x16, 0x28, 0x53, 0x0D, 0x20, 0x74, 0x0B, 0xD1, 0xD5, 0x0F, 0x16, 0x48, 0x06, 0xB2, 0x5F, 0x1E, 0x0A,
    0xC9, 0xDD, 0x9E, 0x17, 0xE5, 0x00, 0xD6, 0xB9, 0x2D, 0x40, 0xE6, 0xA8, 0xDC, 0x7F, 0xAE, 0x5B, 0x6B, 0x7F, 0x76,
    0x27, 0xF7, 0xED, 0x0C, 0xF5, 0x1D, 0xC1, 0x6F, 0xA4, 0x00, 0x45, 0x8A, 0x22, 0x09, 0x84, 0xD1, 0xB4, 0xB1, 0x18,
    0x44, 0x76, 0xC9, 0xD6, 0xA7, 0xC6, 0x72, 0x5B, 0x43, 0x48, 0x91, 0x85, 0xBB, 0x7F, 0xB1, 0x44, 0x73, 0x45, 0xF5,
    0x5A, 0x7E, 0x72, 0x3D, 0xA1, 0x8C, 0x43, 0xAE, 0x83, 0xD9, 0xB4, 0xCB, 0x1D, 0xDC, 0x26, 0x3F, 0x7F, 0x1E, 0xFE,
    0x83, 0x6C, 0x9A, 0x0D, 0xEA, 0xE1, 0x94, 0x55, 0xF1
  };

const uint8_t PublicExponent[] =
  {
    0x01, 0x00, 0x01
  };

const uint8_t PrivateExponent[] =
  {
    0x06, 0xBE, 0x0F, 0x57, 0xDC, 0xE2, 0x26, 0x1F, 0x56, 0xAC, 0xA9, 0x61, 0xE5, 0x1C, 0xEA, 0x98, 0x30, 0x43,
    0xDC, 0xCF, 0xC1, 0x04, 0x6E, 0xF0, 0x2C, 0x41, 0x8A, 0x1E, 0xD0, 0x54, 0xA0, 0x2C, 0x3D, 0xE4, 0x78, 0xF6,
    0xEF, 0x37, 0xA4, 0x39, 0x10, 0xA1, 0xBD, 0x65, 0x56, 0x40, 0x6E, 0xC1, 0x35, 0x1B, 0x05, 0x26, 0x8F, 0xCF,
    0xA1, 0x75, 0xC3, 0x20, 0x3C, 0x46, 0xD7, 0x12, 0x64, 0x48, 0xA5, 0x94, 0x88, 0x5D, 0xBA, 0x25, 0xB7, 0x8A,
    0xB5, 0xB2, 0xD6, 0x6E, 0x84, 0xD2, 0x80, 0x1A, 0x52, 0xA0, 0xFA, 0x66, 0xDA, 0xA6, 0x5B, 0xA5, 0xFD, 0x80,
    0xAF, 0xE7, 0xAB, 0xFC, 0x68, 0x99, 0xF5, 0x37, 0x8F, 0x22, 0x00, 0xA0, 0xDA, 0xB0, 0xB6, 0xF8, 0x50, 0xA7,
    0x0A, 0xDF, 0xCD, 0x85, 0x9A, 0xBD, 0x77, 0x4A, 0x63, 0x35, 0xA1, 0xAC, 0x7A, 0xB5, 0x0F, 0x71, 0xF6, 0xF0,
    0x97, 0x4C, 0x59, 0x7B, 0x53, 0xD1, 0x71, 0x98, 0x3D, 0xFD, 0x1E, 0xE3, 0x81, 0x39, 0x0A, 0xD7, 0x8D, 0x2B,
    0x82, 0x12, 0xCC, 0x9D, 0xF9, 0xC7, 0xEE, 0xAC, 0x90, 0x65, 0xC7, 0x01, 0xBC, 0x58, 0x52, 0xEF, 0x02, 0x74,
    0x04, 0x70, 0x87, 0xA0, 0x55, 0x42, 0xAF, 0x89, 0xF2, 0x9B, 0x22, 0xFB, 0x14, 0x5D, 0xF3, 0x26, 0x55, 0xD3,
    0x2F, 0x04, 0xF0, 0x92, 0xC3, 0x1F, 0x45, 0x7B, 0x82, 0xE9, 0x0F, 0xF1, 0x8C, 0xA2, 0x32, 0xA9, 0x56, 0x65,
    0xC8, 0x2E, 0xA1, 0xA5, 0x95, 0x16, 0xBF, 0xC5, 0xDB, 0x78, 0xF8, 0x83, 0xDB, 0xFD, 0x04, 0xD8, 0x29, 0x92,
    0x58, 0xD4, 0xE3, 0x8D, 0xD2, 0x66, 0xB6, 0xDB, 0x4A, 0xC0, 0x4B, 0xE0, 0xF4, 0xF8, 0x02, 0x9B, 0xE8, 0xD3,
    0x41, 0xD9, 0x4A, 0x32, 0x3C, 0x75, 0x43, 0x19, 0xA8, 0x1F, 0x41, 0x90, 0x92, 0x1E, 0xF7, 0x18, 0xE8, 0x0C,
    0x55, 0xC2, 0x98, 0x01
  };

const uint8_t EncryptedMessage[] =
  {
    0x45, 0x4E, 0x4F, 0xE2, 0x40, 0xBA, 0xF4, 0xD9, 0xED, 0xEA, 0x65, 0x79, 0xB4, 0xCF, 0x8D, 0xE4, 0x41, 0x3E,
    0x56, 0x78, 0xAC, 0x5C, 0x47, 0x3F, 0x22, 0x1F, 0x16, 0xCB, 0xBC, 0xFC, 0x9E, 0xB7, 0x31, 0x96, 0x37, 0x83,
    0x3A, 0xFE, 0x46, 0x51, 0x75, 0x27, 0xE6, 0x6F, 0x66, 0x3E, 0xC9, 0xB9, 0xB4, 0x7C, 0x1E, 0xB8, 0xF3, 0xB1,
    0xBA, 0x87, 0xF6, 0x12, 0x0F, 0xCA, 0xD7, 0x63, 0xC0, 0x8A, 0x86, 0xE3, 0xF6, 0x1C, 0x61, 0x5A, 0x01, 0xDD,
    0x3F, 0x97, 0xC9, 0x2A, 0x55, 0x0B, 0x46, 0x25, 0xE6, 0xAE, 0x87, 0x72, 0x08, 0xA8, 0x49, 0x10, 0xED, 0xE0,
    0xAB, 0xD5, 0x73, 0xE4, 0xF2, 0x74, 0x01, 0xCE, 0x7B, 0xAA, 0xD2, 0xC2, 0x86, 0xC1, 0x64, 0x8D, 0xD7, 0x63,
    0xA4, 0x7C, 0xDC, 0xA8, 0x21, 0x93, 0x12, 0x0D, 0xC3, 0x8D, 0xD9, 0x59, 0x97, 0x80, 0xC1, 0xC7, 0x8F, 0x0D,
    0x3B, 0x16, 0x3C, 0xE2, 0x2F, 0xB4, 0x52, 0x8C, 0x0C, 0x15, 0xE5, 0x98, 0x81, 0xEF, 0xB4, 0xD3, 0x5E, 0x72,
    0xC8, 0x89, 0x64, 0xBE, 0x54, 0xEC, 0xFB, 0x38, 0x85, 0xB4, 0x62, 0x39, 0xA6, 0xCC, 0xC4, 0x68, 0x0C, 0xDF,
    0xA4, 0x5A, 0x9D, 0x34, 0x31, 0x2A, 0x0C, 0x3B, 0x52, 0xCF, 0x13, 0xF3, 0xE8, 0x5A, 0x0C, 0xEA, 0x41, 0x94,
    0xD5, 0x25, 0xAA, 0xC0, 0x2B, 0xC8, 0xB2, 0x04, 0xA6, 0xCD, 0x26, 0xF6, 0x02, 0x98, 0x89, 0x79, 0x62, 0x76,
    0x76, 0xEF, 0xF4, 0x3C, 0x09, 0x16, 0x4B, 0x1A, 0x9C, 0xCA, 0x4F, 0x42, 0x9A, 0xA2, 0x4B, 0x98, 0xF8, 0xFF,
    0xBE, 0xBF, 0xE4, 0xA0, 0x0F, 0xEB, 0xC1, 0xDB, 0x69, 0x4D, 0x93, 0x16, 0x5F, 0x3D, 0xBF, 0xA1, 0xD8, 0x4D,
    0x05, 0x21, 0xD1, 0xB4, 0xDA, 0x13, 0x4C, 0x27, 0x8E, 0xB2, 0x4F, 0x57, 0x07, 0xCC, 0xA6, 0xA1, 0x0F, 0x52,
    0xD5, 0x72, 0x16, 0x9D
  };

/* String of entropy */
uint8_t entropy_data[32] =
  {
    0x91, 0x20, 0x1a, 0x18, 0x9b, 0x6d, 0x1a, 0xa7,
    0x0e, 0x69, 0x57, 0x6f, 0x36, 0xb6, 0xaa, 0x88,
    0x55, 0xfd, 0x4a, 0x7f, 0x97, 0xe9, 0x72, 0x69,
    0xb6, 0x60, 0x88, 0x78, 0xe1, 0x9c, 0x8c, 0xa5
  };

uint8_t output[2048/8];
int32_t outputSize = 0;


/* Private function prototypes -----------------------------------------------*/

int32_t RSA_Encrypt(RSApubKey_stt *P_pPubKey,
                    const uint8_t *P_pInputMessage,
                    int32_t P_InputSize,
                    uint8_t *P_pOutput);

int32_t RSA_Decrypt(RSAprivKey_stt * P_pPrivKey,
                    const uint8_t * P_pInputMessage,
                    uint8_t *P_pOutput,
                    int32_t *P_OutputSize);

#endif

#ifdef USE_CHACHA
const uint8_t key[] =
  {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  };

const uint8_t nonce[] =
  {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  };

const uint8_t input[] =
  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x5f, 0x12
  };

const uint8_t aad[] =
  {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
  };

uint8_t rfc_result[] =
  {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16,
  };

const uint8_t rfc_tag[] =
  {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
  };
uint8_t outputBuffer_enc[265];
uint8_t outputBuffer_dec[265];

/* Private function prototypes -----------------------------------------------*/
int32_t STM32_ChaChaPoly_Encrypt(const uint8_t *AAD,
                                 int32_t      AADSize,
                                 const uint8_t *InputMessage,
                                 int32_t      InputMessageSize,
                                 const uint8_t  *Key,
                                 const uint8_t  *Nonce,
                                 uint8_t     *Output);

int32_t STM32_ChaChaPoly_Decrypt(const uint8_t *AAD,
                                 int32_t      AADSize,
                                 const uint8_t *InputMessage,
                                 int32_t      InputMessageSize,
                                 const uint8_t  *Key,
                                 const uint8_t  *Nonce,
                                 uint8_t     *Output,
                                 const uint8_t  *Tag);
#endif
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */
  int32_t status = AES_SUCCESS;
  uint32_t stop_millis, start_millis;
  uint32_t result;
  uint8_t buff[50];
#ifdef USE_RSA
  RSApubKey_stt PubKey_st;
  RSAprivKey_stt PrivKey_st;
#endif
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  MX_CRC_Init();
  /* USER CODE BEGIN 2 */
  HAL_UART_Transmit(&huart2, (uint8_t *)"Piotr Slawecki & Jan Chyczynski - Crypto Alg test for STM32F446:\n\r", strlen("Piotr Slawecki & Jan Chyczynski - Crypto Alg test for STM32F446:\n\r"), 100);
#ifdef USE_AES_CBC
  /* Encrypt DATA with AES in CBC mode */
  uint32_t start_millis = HAL_GetTick();
  for(int i = 0; i < 50000; i++) {
    status = STM32_AES_CBC_Encrypt( (uint8_t *) Plaintext, PLAINTEXT_LENGTH, Key, IV, sizeof(IV), OutputMessage,
                                    &OutputMessageLength);
    if (status == AES_SUCCESS)
    {
//      if (Buffercmp(Expected_Ciphertext, OutputMessage, PLAINTEXT_LENGTH) == PASSED)
//      {
//      }
//      else
//      {
//        Error_Handler();
//      }
    }
    else
    {
      Error_Handler();
    }

    /* Decrypt DATA with AES in CBC mode */
    status = STM32_AES_CBC_Decrypt( (uint8_t *) Expected_Ciphertext, PLAINTEXT_LENGTH, Key, IV, sizeof(IV), OutputMessage,
                                    &OutputMessageLength);
    if (status == AES_SUCCESS)
    {
//      if (Buffercmp(Plaintext, OutputMessage, PLAINTEXT_LENGTH) == PASSED)
//      {
//      }
//      else
//      {
//        Error_Handler();
//      }
    }
    else
    {
      Error_Handler();
    }
  }
  uint32_t stop_millis = HAL_GetTick();
  uint32_t result = stop_millis - start_millis;
    /* Turn on the green led in case of AES CBC operations are succssfuls*/
  uint8_t buff[50];
  sprintf(buff, "Elapsed (CryptoLib CBC 50k ops): %ld\n\r", result);
  HAL_UART_Transmit(&huart2, (uint8_t *)buff, strlen(buff), 100);
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_5, GPIO_PIN_SET);
  HAL_Delay(1000);
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_5, GPIO_PIN_RESET);
#endif

#ifdef USE_AES_EBC
  /* Encrypt DATA with AES in ECB mode */
  start_millis = HAL_GetTick();
  for(int i = 0; i < 50000; i++) {
    status = STM32_AES_ECB_Encrypt( (uint8_t *) Plaintext_ECB, PLAINTEXT_LENGTH, Key_ECB, OutputMessage_ECB,
                                    &OutputMessageLength_ECB);
    if (status == AES_SUCCESS)
    {
//      if (Buffercmp(Expected_Ciphertext_ECB, OutputMessage_ECB, PLAINTEXT_LENGTH) == PASSED)
//      {
//      }
//      else
//      {
//    	HAL_UART_Transmit(&huart2, (uint8_t *)"Error\n\r", strlen("Error\n\r"), 100);
//    	uint8_t errbuff[50];
//
//    	for(int b = 0; b < 16; b++) {
//    		sprintf(errbuff, "Ciphertext Byte %d: %02x\n\r", b, OutputMessage_ECB[b]);
//    		HAL_UART_Transmit(&huart2, (uint8_t *)errbuff, strlen(errbuff), 100);
//    	}
//
//        Error_Handler();
//      }
    }
    else
    {
      Error_Handler();
    }
    /* Decrypt DATA with AES in ECB mode */
    status = STM32_AES_ECB_Decrypt( (uint8_t *) Expected_Ciphertext_ECB, PLAINTEXT_LENGTH, Key_ECB, OutputMessage_ECB,
                                    &OutputMessageLength_ECB);
    if (status == AES_SUCCESS)
    {
//      if (Buffercmp(Plaintext_ECB, OutputMessage_ECB, PLAINTEXT_LENGTH) == PASSED)
//      {
//      }
//      else
//      {
//        Error_Handler();
//      }
    }
    else
    {
      Error_Handler();
    }
  }
  stop_millis = HAL_GetTick();
  result = stop_millis - start_millis;
  sprintf(buff, "Elapsed (CryptoLib ECB 50k ops): %ld\n\r", result);
  HAL_UART_Transmit(&huart2, (uint8_t *)buff, strlen(buff), 100);
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_5, GPIO_PIN_SET);
  HAL_Delay(1000);
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_5, GPIO_PIN_RESET);
#endif

#ifdef USE_RSA
  status = RSA_ERR_GENERIC;
  start_millis = HAL_GetTick();
  for(int i = 0; i < 50; i++) {
  /* Testing Encryption and Decryption */
    /* Preparing for Encryption */
    PubKey_st.mExponentSize = sizeof(PublicExponent);
    PubKey_st.mModulusSize = sizeof(Modulus);
    PubKey_st.pmExponent = (uint8_t *) PublicExponent;
    PubKey_st.pmModulus = (uint8_t *)Modulus;
    status = RSA_Encrypt(&PubKey_st, Message, sizeof(Message), output);

    if (status == RSA_SUCCESS)
    {
      /* Now we will test decryption */
      PrivKey_st.mExponentSize = sizeof(PrivateExponent);
      PrivKey_st.mModulusSize = sizeof(Modulus);
      PrivKey_st.pmExponent = (uint8_t *) PrivateExponent;
      PrivKey_st.pmModulus = (uint8_t *) Modulus;
      status = RSA_Decrypt(&PrivKey_st, output, output, &outputSize);

      if (status == RSA_SUCCESS)
      {
        /* Check expected output */
//        if ( (Buffercmp(Message, output, sizeof(Message)) == PASSED ) && (outputSize == sizeof(Message)))
//        {
//          /* add application traitment in case of Encryption/Decryption is passed */
//        }
//        else
//        {
//          HAL_UART_Transmit(&huart2, (uint8_t *)"Error\n\r", strlen("Error\n\r"), 100);
//          Error_Handler();
//        }
      }
      else
      {
    	HAL_UART_Transmit(&huart2, (uint8_t *)"Error\n\r", strlen("Error\n\r"), 100);
        Error_Handler();
      }
    }
    else
    {
      HAL_UART_Transmit(&huart2, (uint8_t *)"Error\n\r", strlen("Error\n\r"), 100);
      Error_Handler();
    }


  }
  stop_millis = HAL_GetTick();
  result = stop_millis - start_millis;
  sprintf(buff, "Elapsed (CryptoLib RSA-256 50 ops): %ld\n\r", result);
  HAL_UART_Transmit(&huart2, (uint8_t *)buff, strlen(buff), 100);
    /* Turn on the green led in case of RSA encryption/decryption operations are successful*/
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_5, GPIO_PIN_SET);
  HAL_Delay(1000);
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_5, GPIO_PIN_RESET);
#endif

#ifdef USE_CHACHA
  status = CHACHA20POLY1305_SUCCESS; /* Status */
  start_millis = HAL_GetTick();
  for(int i = 0; i < 50000; i++) {
  	status = STM32_ChaChaPoly_Encrypt(aad, sizeof(aad), input, sizeof(input), key, nonce, outputBuffer_enc);

    if (status == CHACHA20POLY1305_SUCCESS)
    {
      /* Function returned SUCCESS */
      /* Checking Encrypted text with expected value */
//      if (Buffercmp(rfc_result, outputBuffer, sizeof(rfc_result)) == PASSED)
//      {
//        /* add application traitment in case of CHACHA20-POLY1305 success */
//      }
//      else
//      {
//        Error_Handler();
//      }
      /* Checking TAG with expected value */
//      if (Buffercmp(rfc_tag, outputBuffer + sizeof(rfc_result), sizeof(rfc_tag)) == PASSED)
//      {
//        /* add application traitment in case of CHACHA20-POLY1305 success */
//      }
//      else
//      {
//        Error_Handler();
//      }
    }
    else
    {
      HAL_UART_Transmit(&huart2, (uint8_t *)"Error\n\r", strlen("Error\n\r"), 100);
      Error_Handler();

    }


    status = STM32_ChaChaPoly_Decrypt(aad, sizeof(aad), outputBuffer_enc, sizeof(outputBuffer_enc), key, nonce, outputBuffer_dec, rfc_tag);

    if (status == AUTHENTICATION_SUCCESSFUL)
    {

      /* Function returned AUTHENTICATION_SUCCESSFUL */
      /* Checking Decrypted text with expected value */
      if (Buffercmp(input, outputBuffer_dec, sizeof(input)) == PASSED)

      {
        /* add application traitment in case of CHACHA20-POLY1305 success */
      }
      else
      {
    	HAL_UART_Transmit(&huart2, (uint8_t *)"Error\n\r", strlen("Error\n\r"), 100);
        Error_Handler();

      }
    }
    else
    {

      //Error_Handler();
    }
  }
  stop_millis = HAL_GetTick();
  result = stop_millis - start_millis;
  sprintf(buff, "Elapsed (CryptoLib ChaCha20-Poly1305 50k ops): %ld\n\r", result);
  HAL_UART_Transmit(&huart2, (uint8_t *)buff, strlen(buff), 100);
    /* Turn on the green led in case of ARC4 operations are successful*/
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_5, GPIO_PIN_SET);
#endif
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 180;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 2;
  RCC_OscInitStruct.PLL.PLLR = 2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Activate the Over-Drive mode
  */
  if (HAL_PWREx_EnableOverDrive() != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */
#ifdef USE_AES_CBC
int32_t STM32_AES_CBC_Encrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t  *AES192_Key,
                              uint8_t  *InitializationVector,
                              uint32_t  IvLength,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength)
{
  AESCBCctx_stt AESctx;

  uint32_t error_status = AES_SUCCESS;

  int32_t outputLength = 0;

  /* Set flag field to default value */
  AESctx.mFlags = E_SK_DEFAULT;

  /* Set key size to 24 (corresponding to AES-192) */
  AESctx.mKeySize = 16;

  /* Set iv size field to IvLength*/
  AESctx.mIvSize = IvLength;

  /* Initialize the operation, by passing the key.
   * Third parameter is NULL because CBC doesn't use any IV */
  error_status = AES_CBC_Encrypt_Init(&AESctx, AES192_Key, InitializationVector );

  /* check for initialization errors */
  if (error_status == AES_SUCCESS)
  {
    /* Encrypt Data */
    error_status = AES_CBC_Encrypt_Append(&AESctx,
                                          InputMessage,
                                          InputMessageLength,
                                          OutputMessage,
                                          &outputLength);

    if (error_status == AES_SUCCESS)
    {
      /* Write the number of data written*/
      *OutputMessageLength = outputLength;
      /* Do the Finalization */
      error_status = AES_CBC_Encrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength);
      /* Add data written to the information to be returned */
      *OutputMessageLength += outputLength;
    }
  }

  return error_status;
}


/**
  * @brief  AES CBC Decryption example.
  * @param  InputMessage: pointer to input message to be decrypted.
  * @param  InputMessageLength: input data message length in byte.
  * @param  AES192_Key: pointer to the AES key to be used in the operation
  * @param  InitializationVector: pointer to the Initialization Vector (IV)
  * @param  IvLength: IV length in bytes.
  * @param  OutputMessage: pointer to output parameter that will handle the decrypted message
  * @param  OutputMessageLength: pointer to decrypted message length.
  * @retval error status: can be AES_SUCCESS if success or one of
  *         AES_ERR_BAD_INPUT_SIZE, AES_ERR_BAD_OPERATION, AES_ERR_BAD_CONTEXT
  *         AES_ERR_BAD_PARAMETER if error occured.
  */
int32_t STM32_AES_CBC_Decrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t  *AES192_Key,
                              uint8_t  *InitializationVector,
                              uint32_t  IvLength,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength)
{
  AESCBCctx_stt AESctx;

  uint32_t error_status = AES_SUCCESS;

  int32_t outputLength = 0;

  /* Set flag field to default value */
  AESctx.mFlags = E_SK_DEFAULT;

  /* Set key size to 24 (corresponding to AES-128) */
  AESctx.mKeySize = 16;

  /* Set iv size field to IvLength*/
  AESctx.mIvSize = IvLength;

  /* Initialize the operation, by passing the key.
   * Third parameter is NULL because CBC doesn't use any IV */
  error_status = AES_CBC_Decrypt_Init(&AESctx, AES192_Key, InitializationVector );

  /* check for initialization errors */
  if (error_status == AES_SUCCESS)
  {
    /* Decrypt Data */
    error_status = AES_CBC_Decrypt_Append(&AESctx,
                                          InputMessage,
                                          InputMessageLength,
                                          OutputMessage,
                                          &outputLength);

    if (error_status == AES_SUCCESS)
    {
      /* Write the number of data written*/
      *OutputMessageLength = outputLength;
      /* Do the Finalization */
      error_status = AES_CBC_Decrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength);
      /* Add data written to the information to be returned */
      *OutputMessageLength += outputLength;
    }
  }

  return error_status;
}
#endif

#ifdef USE_AES_EBC
/**
  * @brief  AES ECB Encryption example.
  * @param  InputMessage: pointer to input message to be encrypted.
  * @param  InputMessageLength: input data message length in byte.
  * @param  AES128_Key: pointer to the AES key to be used in the operation
  * @param  OutputMessage: pointer to output parameter that will handle the encrypted message
  * @param  OutputMessageLength: pointer to encrypted message length.
  * @retval error status: can be AES_SUCCESS if success or one of
  *         AES_ERR_BAD_INPUT_SIZE, AES_ERR_BAD_OPERATION, AES_ERR_BAD_CONTEXT
  *         AES_ERR_BAD_PARAMETER if error occured.
  */
int32_t STM32_AES_ECB_Encrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t  *AES256_Key,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength)
{
  AESECBctx_stt AESctx;

  uint32_t error_status = AES_SUCCESS;

  int32_t outputLength = 0;

  /* Set flag field to default value */
  AESctx.mFlags = E_SK_DEFAULT;

  /* Set key size to 32 (corresponding to AES-256) */
  AESctx.mKeySize = 16;

  /* Initialize the operation, by passing the key.
   * Third parameter is NULL because ECB doesn't use any IV */
  error_status = AES_ECB_Encrypt_Init(&AESctx, AES256_Key, NULL );

  /* check for initialization errors */
  if (error_status == AES_SUCCESS)
  {
    /* Encrypt Data */
    error_status = AES_ECB_Encrypt_Append(&AESctx,
                                          InputMessage,
                                          InputMessageLength,
                                          OutputMessage,
                                          &outputLength);

    if (error_status == AES_SUCCESS)
    {
      /* Write the number of data written*/
      *OutputMessageLength = outputLength;
      /* Do the Finalization */
      error_status = AES_ECB_Encrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength);
      /* Add data written to the information to be returned */
      *OutputMessageLength += outputLength;
    }
  }

  return error_status;
}


/**
  * @brief  AES ECB Decryption example.
  * @param  InputMessage: pointer to input message to be decrypted.
  * @param  InputMessageLength: input data message length in byte.
  * @param  AES128_Key: pointer to the AES key to be used in the operation
  * @param  OutputMessage: pointer to output parameter that will handle the decrypted message
  * @param  OutputMessageLength: pointer to decrypted message length.
  * @retval error status: can be AES_SUCCESS if success or one of
  *         AES_ERR_BAD_INPUT_SIZE, AES_ERR_BAD_OPERATION, AES_ERR_BAD_CONTEXT
  *         AES_ERR_BAD_PARAMETER if error occured.
  */
int32_t STM32_AES_ECB_Decrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t  *AES256_Key,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength)
{
  AESECBctx_stt AESctx;

  uint32_t error_status = AES_SUCCESS;

  int32_t outputLength = 0;

  /* Set flag field to default value */
  AESctx.mFlags = E_SK_DEFAULT;

  /* Set key size to 32 (corresponding to AES-256) */
  AESctx.mKeySize = 16;

  /* Initialize the operation, by passing the key.
   * Third parameter is NULL because ECB doesn't use any IV */
  error_status = AES_ECB_Decrypt_Init(&AESctx, AES256_Key, NULL );

  /* check for initialization errors */
  if (error_status == AES_SUCCESS)
  {
    /* Decrypt Data */
    error_status = AES_ECB_Decrypt_Append(&AESctx,
                                          InputMessage,
                                          InputMessageLength,
                                          OutputMessage,
                                          &outputLength);

    if (error_status == AES_SUCCESS)
    {
      /* Write the number of data written*/
      *OutputMessageLength = outputLength;
      /* Do the Finalization */
      error_status = AES_ECB_Decrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength);
      /* Add data written to the information to be returned */
      *OutputMessageLength += outputLength;
    }
  }

  return error_status;
}
#endif

#ifdef USE_RSA
/**
  * @brief  RSA Encryption with PKCS#1v1.5
  * @param  P_pPubKey The RSA public key structure, already initialized
  * @param  P_pInputMessage Input Message to be signed
  * @param  P_MessageSize Size of input message
  * @param  P_pOutput Pointer to output buffer
  * @retval error status: can be RSA_SUCCESS if success or one of
  * RSA_ERR_BAD_PARAMETER, RSA_ERR_MESSAGE_TOO_LONG, RSA_ERR_BAD_OPERATION
*/
int32_t RSA_Encrypt(RSApubKey_stt *P_pPubKey,
                    const uint8_t *P_pInputMessage,
                    int32_t P_InputSize,
                    uint8_t *P_pOutput)
{
  int32_t status = RNG_SUCCESS ;
  RNGstate_stt RNGstate;
  RNGinitInput_stt RNGinit_st;
  RNGinit_st.pmEntropyData = entropy_data;
  RNGinit_st.mEntropyDataSize = sizeof(entropy_data);
  RNGinit_st.mPersDataSize = 0;
  RNGinit_st.mNonceSize = 0;

  status = RNGinit(&RNGinit_st, &RNGstate);
  if (status == RNG_SUCCESS)
  {
    RSAinOut_stt inOut_st;
    membuf_stt mb;

    mb.mSize = sizeof(preallocated_buffer);
    mb.mUsed = 0;
    mb.pmBuf = preallocated_buffer;

    /* Fill the RSAinOut_stt */
    inOut_st.pmInput = P_pInputMessage;
    inOut_st.mInputSize = P_InputSize;
    inOut_st.pmOutput = P_pOutput;

    /* Encrypt the message, this function will write sizeof(modulus) data */
    status = RSA_PKCS1v15_Encrypt(P_pPubKey, &inOut_st, &RNGstate, &mb);
  }
  return(status);
}

/**
  * @brief  RSA Decryption with PKCS#1v1.5
  * @param  P_pPrivKey The RSA private key structure, already initialized
  * @param  P_pInputMessage Input Message to be signed
  * @param  P_MessageSize Size of input message
  * @param  P_pOutput Pointer to output buffer
  * @retval error status: can be RSA_SUCCESS if success or RSA_ERR_GENERIC in case of fail
*/
int32_t RSA_Decrypt(RSAprivKey_stt * P_pPrivKey,
                    const uint8_t * P_pInputMessage,
                    uint8_t *P_pOutput,
                    int32_t *P_OutputSize)
{
  int32_t status = RSA_SUCCESS ;
  RSAinOut_stt inOut_st;
  membuf_stt mb;

  mb.mSize = sizeof(preallocated_buffer);
  mb.mUsed = 0;
  mb.pmBuf = preallocated_buffer;

  /* Fill the RSAinOut_stt */
  inOut_st.pmInput = P_pInputMessage;
  inOut_st.mInputSize = P_pPrivKey->mModulusSize;
  inOut_st.pmOutput = P_pOutput;

  /* Encrypt the message, this function will write sizeof(modulus) data */
  status = RSA_PKCS1v15_Decrypt(P_pPrivKey, &inOut_st, P_OutputSize, &mb);
  return(status);
}
#endif

#ifdef USE_CHACHA
/**
* @brief  ChaCha20-Poly1305 AEAD Encryption
* @param  AAD: Pointer to Additional Authenticated Data
* @param  AADSize: size of AAD
* @param  InputMessage: pointer to input message
* @param  InputMessageSize: size of input message
* @param  Key: pointer to the 256-bit key
* @param  Nonce: pointer to the 96-bit Nonce
* @param  Output: pointer to output buffer, the tag will be concatenated to the encrypted text
* @retval error status: can be CHACHA20POLY1305_SUCCESS if success or one of
*                     CHACHA20POLY1305_ERR_BAD_PARAMETER,CHACHA20POLY1305_ERR_BAD_OPERATION if error occured.
*/
int32_t STM32_ChaChaPoly_Encrypt(const uint8_t *AAD,
                                 int32_t      AADSize,
                                 const uint8_t *InputMessage,
                                 int32_t      InputMessageSize,
                                 const uint8_t  *Key,
                                 const uint8_t  *Nonce,
                                 uint8_t     *Output)
{
  /* ChaCha20Poly1305, error status and output length */
  ChaCha20Poly1305ctx_stt ctx;
  /* Default value for error status */
  uint32_t error_status = CHACHA20POLY1305_SUCCESS;
  /* Integer to store size of written data */
  int32_t outputLength = 0;

  /* Set flag field to default value */
  ctx.mFlags = E_SK_DEFAULT;

  /* Call the Init */
  error_status = ChaCha20Poly1305_Encrypt_Init(&ctx, Key, Nonce);
  if (error_status == CHACHA20POLY1305_SUCCESS)
  {
    /* Process the AAD */
    error_status = ChaCha20Poly1305_Header_Append(&ctx, AAD, AADSize);
    if (error_status == CHACHA20POLY1305_SUCCESS)
    {
      /* Encrypt Message */
      error_status = ChaCha20Poly1305_Encrypt_Append(&ctx, InputMessage, InputMessageSize, Output, &outputLength);
      if (error_status == CHACHA20POLY1305_SUCCESS)
      {
        /* Generate authentication tag */
        error_status = ChaCha20Poly1305_Encrypt_Finish(&ctx, Output + outputLength, &outputLength);
      }
    }
  }

  return error_status;
}

/**
* @brief  ChaCha20-Poly1305 AEAD Decryption and Authentication
* @param  AAD: Pointer to Additional Authenticated Data
* @param  AADSize: size of AAD
* @param  InputMessage: pointer to input message
* @param  InputMessageSize: size of input message
* @param  Key: pointer to the 256-bit key
* @param  Nonce: pointer to the 96-bit Nonce
* @param  Output: pointer to output buffer
* @param  Tag: pointer to input Tag to be verified
* @retval error status: AUTHENTICATION_SUCCESSFUL if success or one of
*                     CHACHA20POLY1305_ERR_BAD_PARAMETER,CHACHA20POLY1305_ERR_BAD_OPERATION
*                     CHACHA20POLY1305_ERR_BAD_CONTEXT, AUTHENTICATION_FAILED if error occured.
*/
int32_t STM32_ChaChaPoly_Decrypt(const uint8_t *AAD,
                                 int32_t      AADSize,
                                 const uint8_t *InputMessage,
                                 int32_t      InputMessageSize,
                                 const uint8_t  *Key,
                                 const uint8_t  *Nonce,
                                 uint8_t     *Output,
                                 const uint8_t  *Tag)
{
  /* ChaCha20Poly1305, error status and output length */
  ChaCha20Poly1305ctx_stt ctx;
  /* Default value for error status */
  uint32_t error_status = AUTHENTICATION_FAILED;
  /* Integer to store size of written data */
  int32_t outputLength = 0;

  /* Set flag field to default value */
  ctx.mFlags = E_SK_DEFAULT;
  /* Set the tag that will be verified */
  ctx.pmTag = Tag;

  /* Call the Init */
  error_status = ChaCha20Poly1305_Decrypt_Init(&ctx, Key, Nonce);
  if (error_status == CHACHA20POLY1305_SUCCESS)
  {
    /* Process the AAD */
    error_status = ChaCha20Poly1305_Header_Append(&ctx, AAD, AADSize);
    if (error_status == CHACHA20POLY1305_SUCCESS)
    {
      /* Decrypt Message */
      error_status = ChaCha20Poly1305_Decrypt_Append(&ctx, InputMessage, InputMessageSize, Output, &outputLength);
      if (error_status == CHACHA20POLY1305_SUCCESS)
      {
        /* Verify authentication tag */
        error_status = ChaCha20Poly1305_Decrypt_Finish(&ctx, NULL, 0);
      }
    }
  }

  return error_status;
}

#endif
/**
  * @brief  Compares two buffers.
  * @param  pBuffer, pBuffer1: buffers to be compared.
  * @param  BufferLength: buffer's length
  * @retval PASSED: pBuffer identical to pBuffer1
  *         FAILED: pBuffer differs from pBuffer1
  */
TestStatus Buffercmp(const uint8_t* pBuffer, uint8_t* pBuffer1, uint16_t BufferLength)
{
  while (BufferLength--)
  {
    if (*pBuffer != *pBuffer1)
    {
      return FAILED;
    }

    pBuffer++;
    pBuffer1++;
  }

  return PASSED;
}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
