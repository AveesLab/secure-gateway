#pragma once
#include <tee_client_api.h>

/* TA와 동일한 UUID */
#define TA_SIGN_UUID { 0x98765432, 0xabcd, 0xabcd, \
    { 0x12,0x34,0x56,0x78,0xab,0xcd,0xef,0x01 } }

/* TA에서 정의한 명령 */
#define CMD_GENKEY                   0
#define CMD_SIGN                     1
#define CMD_GET_PUBKEY               2
/* ECDH 관련 명령어 (DH 관련 명령어는 삭제) */
#define CMD_GENERATE_ECDH            3
#define CMD_COMPUTE_ECDH_SHARED_SECRET 4
#define CMD_DECRYPT_GROUPKEY   5  // 기존 커맨드 ID 이후의 새로운 ID

bool createRSAKey(TEEC_Session &sess);
bool getRSAPublicKey(TEEC_Session &sess, std::vector<uint8_t> &pubKeyOut);
bool signData(TEEC_Session &sess, const std::vector<uint8_t> &message, std::vector<uint8_t> &signature);
bool getECDHPublicKey(TEEC_Session &sess, std::vector<uint8_t> &ecdhPubKeyOut);
bool computeECDHSharedSecret(TEEC_Session &sess, const std::vector<uint8_t> &gatewayPubKey, std::vector<uint8_t> &sharedSecret);
bool decryptGroupKey(TEEC_Session &sess,
                     const std::vector<uint8_t> &sharedSecret,
                     const std::vector<uint8_t> &iv,
                     const std::vector<uint8_t> &tag,
                     std::vector<uint8_t> &encryptedGroupKey);

