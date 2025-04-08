#ifndef GATEWAY_TA_H
#define GATEWAY_TA_H

/* TA의 UUID: 예시 */
#define TA_GATEWAY_UUID { 0x99999999, 0xabcd, 0xabcd, \
    { 0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x01 } }

/* 명령 (InvokeCommand) ID */
#define CMD_STORE_NODE_PUBKEY         0
#define CMD_VERIFY_SIGNATURE          1
#define CMD_GENERATE_ECDH             2
#define CMD_COMPUTE_ECDH_SHARED_SECRET 3
#define CMD_ENCRYPT_GROUP_KEY         4

#ifndef TEE_ERROR_ITEM_ALREADY_EXISTS
#define TEE_ERROR_ITEM_ALREADY_EXISTS 0xFFFF0001
#endif

#endif /* GATEWAY_TA_H */

