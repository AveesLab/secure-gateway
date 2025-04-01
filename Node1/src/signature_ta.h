#pragma once
#include <tee_client_api.h>

/* TA와 동일한 UUID */
#define TA_SIGN_UUID { 0x98765432, 0xabcd, 0xabcd, \
    { 0x12,0x34,0x56,0x78,0xab,0xcd,0xef,0x01 } }

/* TA에서 정의한 명령 */
#define CMD_GENKEY     0
#define CMD_SIGN       1 
#define CMD_GET_PUBKEY 2

bool createRSAKey(TEEC_Session &sess);
bool getRSAPublicKey(TEEC_Session &sess, std::vector<uint8_t> &pubKeyOut);
bool signData(TEEC_Session &sess, const std::vector<uint8_t> &message, std::vector<uint8_t> &signature);
