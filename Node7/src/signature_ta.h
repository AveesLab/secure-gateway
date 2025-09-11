// signature_ta.h
#ifndef TA_SIGN_H
#define TA_SIGN_H

/* TA의 UUID */
#define TA_SIGN_UUID { 0x98765432, 0xabcd, 0xabcd, \
    { 0x12,0x34,0x56,0x78,0xab,0xcd,0xef,0x07 } }

/* ECDSA 키 관련 */
#define ECDSA_KEY_SIZE 256 // NIST P-256 사용
#define KEY_ID "node_ecdsa_key.db" // 저장될 키 파일 ID
#define KEY_ID_LEN (sizeof(KEY_ID) -1)

// P-256 공개키 (비압축: 0x04 + X(32) + Y(32) = 65 바이트)
#define ECDSA_PUBKEY_UNCOMPRESSED_SIZE 65
// P-256 ECDSA 서명 (R(32) + S(32) = 64 바이트), DER 인코딩 시 약간 더 클 수 있음. 여유있게.
#define ECDSA_SIGNATURE_MAX_SIZE 72 // ASN.1 DER 인코딩된 ECDSA 서명은 약간 더 클 수 있습니다.

/* 서브 마스터키 관련 */
#define SUB_MASTER_KEY_SIZE 32 // 예시 크기, gateway_ta.c와 일치해야 함
#define SUB_MASTER_KEY_ID "node_sub_master_key.db"
#define SUB_MASTER_KEY_ID_LEN (sizeof(SUB_MASTER_KEY_ID) -1)
#define TAG_SIZE 16 // AES-GCM 인증 태그 크기

#define NODE_ECDH_PUBKEY_SIZE ECDSA_PUBKEY_UNCOMPRESSED_SIZE // SECP256R1 공개키 비압축 형식 65바이트

/* InvokeCommand ID 정의 */
#define CMD_GENKEY                     0
#define CMD_SIGN                       1
#define CMD_GET_PUBKEY                 2
#define CMD_GENERATE_ECDH              3
#define CMD_COMPUTE_ECDH_SHARED_SECRET 4
#define CMD_DECRYPT_SUB_MASTER_KEY     5
#define CMD_DERIVE_ECU_KEY             6 // ECU 키 파생
#define CMD_STORE_SMK                  7

/* ECU 키 파생 시 보안 요구 레벨 (세분화) */
// 무결성 전용 (MAC)
#define SEC_LEVEL_CMAC_AES128_KEY     10 // AES-128 기반 CMAC용 키 (16 바이트)
#define SEC_LEVEL_HMAC_SHA256_KEY     11 // HMAC-SHA256용 키 (32 바이트 권장)

// 기밀성 전용 (Encryption only)
#define SEC_LEVEL_AES_ENC_128_KEY     30 // AES-128 일반 암호화용 키 (16 바이트)
#define SEC_LEVEL_AES_ENC_256_KEY     31 // AES-256 일반 암호화용 키 (32 바이트)

// 기밀성 + 무결성 (Authenticated Encryption)
#define SEC_LEVEL_AES_GCM_128_KEY     20 // AES-128 GCM용 키 (16 바이트)
#define SEC_LEVEL_AES_GCM_256_KEY     21 // AES-256 GCM용 키 (32 바이트)
//#define SEC_LEVEL_CHACHA20_POLY1305_KEY  22 // CHACHA20_POLY1305용 키 (32 바이트)


#endif /* TA_SIGN_H */
