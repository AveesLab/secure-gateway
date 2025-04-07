#include "Node1.hpp"
#include "signature_ta.h"
#include <tee_client_api.h>

// 기존 유틸 함수들: 메시지 직렬화, 난수 및 타임스탬프 생성
uint64_t generateNonce() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    return gen();
}

uint64_t getTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::system_clock::to_time_t(now);
    return static_cast<uint64_t>(epoch);
}

std::vector<uint8_t> serializeMessage(uint32_t node_id, uint64_t nonce, uint64_t timestamp) {
    std::vector<uint8_t> serialized;
    // node_id (4바이트)
    for (int i = 0; i < 4; ++i)
        serialized.push_back(static_cast<uint8_t>((node_id >> (8 * i)) & 0xFF));
    // nonce (8바이트)
    for (int i = 0; i < 8; ++i)
        serialized.push_back(static_cast<uint8_t>((nonce >> (8 * i)) & 0xFF));
    // timestamp (8바이트)
    for (int i = 0; i < 8; ++i)
        serialized.push_back(static_cast<uint8_t>((timestamp >> (8 * i)) & 0xFF));
    return serialized;
}

// SecurityGatewayClient (노드 측 클라이언트)는 기존과 동일합니다.
SecurityGatewayClient::SecurityGatewayClient()
{
    std::cout << "[Client] SecurityGatewayClient created.\n";
}

SecurityGatewayClient::~SecurityGatewayClient()
{
    std::cout << "[Client] SecurityGatewayClient destroyed.\n";
}

bool SecurityGatewayClient::connectToService(const std::string &instanceName)
{
    runtime = CommonAPI::Runtime::get();
    if (!runtime) {
        std::cerr << "[Client] Failed to get CommonAPI runtime.\n";
        return false;
    }

    myProxy = runtime->buildProxy<SecurityGatewayProxy>(
        "local",
        instanceName
    );

    if (!myProxy) {
        std::cerr << "[Client] Failed to create Proxy object.\n";
        return false;
    }

    std::cout << "[Client] Proxy created. Waiting for availability...\n";
    while (!myProxy->isAvailable()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    std::cout << "[Client] Service is available!\n";
    return true;
}

// requestSessionKey 인터페이스는 헤더와 일치하도록 구현합니다.
bool SecurityGatewayClient::requestSessionKey(
    uint32_t _nodeID,
    uint64_t _nonce,
    uint64_t _timestamp,
    const std::vector<uint8_t> &_publicKey,
    const std::vector<uint8_t> &_signature,
    const std::vector<uint8_t> &_ecdhPublicKey,  // 추가된 파라미터
    bool &_success,
    std::vector<uint8_t> &_gatewayPublicKey,
    std::vector<uint8_t> &_encryptedGroupKey   // [IV | tag | ciphertext] 포함
)
{
    if (!myProxy) {
        std::cerr << "[Client] Proxy is not initialized.\n";
        return false;
    }
    CommonAPI::CallStatus callStatus;
    
    myProxy->requestSessionKey(
        _nodeID,
        _nonce,
        _timestamp,
        _publicKey,
        _signature,
        _ecdhPublicKey,      // 추가된 ECDH 공개키 전달
        callStatus,          // [out]
        _success,            // [out] 인증 성공 여부
        _gatewayPublicKey,   // [out] 게이트웨이의 ECDH 공개키
        _encryptedGroupKey   // [out] 암호화된 그룹키 (IV, tag, ciphertext)
    );
    
    if (callStatus == CommonAPI::CallStatus::SUCCESS) {
        std::cout << "[Client] requestSessionKeySync => success=" 
                  << (_success ? "true" : "false")
                  << ", gatewayPublicKey.size=" << _gatewayPublicKey.size()
                  << ", encryptedGroupKey.size=" << _encryptedGroupKey.size()
                  << std::endl;
        return true;
    } else {
        std::cerr << "[Client] requestSessionKey call failed. callStatus="
                  << static_cast<int>(callStatus) << std::endl;
        return false;
    }
}

// ----- 기존 TEEC 관련 함수 (RSA 키 생성, 공개키 획득, 서명, ECDH 공개키 획득) -----
bool createRSAKey(TEEC_Session &sess) {
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_GENKEY, &op, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Node-CA] CMD_GENKEY fail: 0x" << std::hex << res << std::endl;
        return false;
    }
    std::cout << "[Node-CA] RSA key created & stored.\n";
    return true;
}

bool getRSAPublicKey(TEEC_Session &sess, std::vector<uint8_t> &pubKeyOut) {
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    std::vector<uint8_t> tempBuf(256, 0);
    op.params[0].tmpref.buffer = tempBuf.data();
    op.params[0].tmpref.size   = tempBuf.size();

    TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_GET_PUBKEY, &op, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Node-CA] CMD_GET_PUBKEY fail: 0x" << std::hex << res << std::endl;
        return false;
    }

    size_t outLen = op.params[0].tmpref.size;
    pubKeyOut.resize(outLen);
    memcpy(pubKeyOut.data(), tempBuf.data(), outLen);

    std::cout << "[Node-CA] getRSAPublicKey => size=" << outLen << "\n";
    return true;
}

bool signData(TEEC_Session &sess, const std::vector<uint8_t> &message, std::vector<uint8_t> &signature) {
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = (void*)message.data();
    op.params[0].tmpref.size   = message.size();

    std::vector<uint8_t> sigBuf(256, 0);
    op.params[1].tmpref.buffer = sigBuf.data();
    op.params[1].tmpref.size   = sigBuf.size();

    TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_SIGN, &op, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Node-CA] CMD_SIGN fail: 0x" << std::hex << res << std::endl;
        return false;
    }
    size_t sigLen = op.params[1].tmpref.size;
    signature.resize(sigLen);
    std::copy(sigBuf.begin(), sigBuf.begin() + sigLen, signature.begin());

    std::cout << "[Node-CA] signData => signature size=" << sigLen << "\n";
    return true;
}

bool getECDHPublicKey(TEEC_Session &sess, std::vector<uint8_t> &ecdhPubKeyOut) {
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    std::vector<uint8_t> tempBuf(100, 0);
    op.params[0].tmpref.buffer = tempBuf.data();
    op.params[0].tmpref.size   = tempBuf.size();
    TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_GENERATE_ECDH, &op, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Node-CA] CMD_GENERATE_ECDH fail: 0x" << std::hex << res << std::endl;
        return false;
    }
    size_t outLen = op.params[0].tmpref.size;
    ecdhPubKeyOut.resize(outLen);
    memcpy(ecdhPubKeyOut.data(), tempBuf.data(), outLen);
    std::cout << "[Node-CA] getECDHPublicKey => size=" << outLen << "\n";
    return true;
}

bool computeECDHSharedSecret(TEEC_Session &sess, const std::vector<uint8_t> &gatewayPubKey, std::vector<uint8_t> &sharedSecret) {
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void*)gatewayPubKey.data();
    op.params[0].tmpref.size = gatewayPubKey.size();
    
    std::vector<uint8_t> tempSecret(32, 0);
    op.params[1].tmpref.buffer = tempSecret.data();
    op.params[1].tmpref.size = tempSecret.size();
    
    TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_COMPUTE_ECDH_SHARED_SECRET, &op, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Node-CA] CMD_COMPUTE_ECDH_SHARED_SECRET fail: 0x" << std::hex << res << std::endl;
        return false;
    }
    size_t secretLen = op.params[1].tmpref.size;
    sharedSecret.resize(secretLen);
    memcpy(sharedSecret.data(), tempSecret.data(), secretLen);
    std::cout << "[Node-CA] computeECDHSharedSecret => secret size=" << secretLen << "\n";
    return true;
}

// 그룹키 복호화: 입력으로 전달된 공유 비밀, IV, 태그, 암호화된 그룹키를 이용하여 TA의 CMD_DECRYPT_GROUPKEY 호출
bool decryptGroupKey(TEEC_Session &sess,
                     const std::vector<uint8_t> &sharedSecret,
                     const std::vector<uint8_t> &iv,
                     const std::vector<uint8_t> &tag,
                     std::vector<uint8_t> &encryptedGroupKey) {
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_MEMREF_TEMP_INPUT);
    op.params[0].tmpref.buffer = (void*)sharedSecret.data();
    op.params[0].tmpref.size   = sharedSecret.size();
    
    op.params[1].tmpref.buffer = (void*)iv.data();
    op.params[1].tmpref.size   = iv.size();
    
    op.params[2].tmpref.buffer = encryptedGroupKey.data();
    op.params[2].tmpref.size   = encryptedGroupKey.size();
    
    op.params[3].tmpref.buffer = (void*)tag.data();
    op.params[3].tmpref.size   = tag.size();
    
    TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_DECRYPT_GROUPKEY, &op, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Node-CA] CMD_DECRYPT_GROUPKEY fail: 0x" << std::hex << res << std::endl;
        return false;
    }
    size_t plainLen = op.params[2].tmpref.size;
    encryptedGroupKey.resize(plainLen);
    std::cout << "[Node-CA] decryptGroupKey => decrypted group key size=" << plainLen << "\n";
    return true;
}

int main() {
    uint32_t node_id = 42;
    uint64_t nonce = generateNonce();
    uint64_t timestamp = getTimestamp();
    std::cout << "[Main] nodeID=" << node_id 
              << ", nonce=" << nonce 
              << ", timestamp=" << timestamp << std::endl;
    
    // TEEC 세션을 통해 RSA/ECDH 관련 기능 호출 (TA_SIGN_UUID 사용)
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_SIGN_UUID;
    TEEC_Result res;
    
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Main] TEEC_InitializeContext fail: 0x" << std::hex << res << std::endl;
        return 1;
    }
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Main] TEEC_OpenSession fail: 0x" << std::hex << res << std::endl;
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    
    // 1) RSA 키 생성
    if (!createRSAKey(sess)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    
    // 2) RSA 공개키 획득
    std::vector<uint8_t> rsaPubKey;
    if (!getRSAPublicKey(sess, rsaPubKey)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    std::cout << "[Main] rsaPubKey length=" << rsaPubKey.size() << std::endl;
    
    // 3) 메시지 직렬화
    std::vector<uint8_t> message = serializeMessage(node_id, nonce, timestamp);
    
    // 4) 메시지 서명
    std::vector<uint8_t> signature;
    if (!signData(sess, message, signature)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    std::cout << "[Main] signature length=" << signature.size() << std::endl;
    
    // 5) ECDH 공개키 획득 (노드 측 키 쌍 생성 및 공개키 획득)
    std::vector<uint8_t> ecdhPubKey;
    if (!getECDHPublicKey(sess, ecdhPubKey)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    std::cout << "[Main] ecdhPubKey length=" << ecdhPubKey.size() << std::endl;
    
    // 세션을 닫지 않고 계속 재사용합니다.
    // (이렇게 해야 노드의 ECDH 키 쌍이 유지되어 이후 공유 비밀 도출이 정상적으로 동작함)
    
    // 6) CommonAPI를 이용해 gateway 서비스에 requestSessionKey 호출
    SecurityGatewayClient client;
    if (!client.connectToService("gateway_service")) {
        return 1;
    }
    
    bool success = false;
    std::vector<uint8_t> gatewayPublicKey;
    std::vector<uint8_t> encryptedGroupKey;
    bool callOk = client.requestSessionKey(
        node_id,
        nonce,
        timestamp,
        rsaPubKey,
        signature,
        ecdhPubKey,   // 노드의 ECDH 공개키 전달
        success,
        gatewayPublicKey,
        encryptedGroupKey  // [IV (12) | tag (16) | ciphertext (32)]로 구성되었다고 가정
    );
  
    if (!callOk) {
        std::cerr << "[Main] requestSessionKey failed.\n";
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    
    std::cout << "[Main] requestSessionKey callOk, success=" 
              << (success ? "true" : "false")
              << ", gatewayPublicKey size=" << gatewayPublicKey.size()
              << ", encryptedGroupKey size=" << encryptedGroupKey.size()
              << std::endl;
    
    if (!success) {
        std::cerr << "[Main] Authentication failed.\n";
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    
    // 7) 노드 측에서 TEEC 세션(이미 열려있는 세션)을 재사용하여
    //     공유 비밀(세션키) 도출 및 그룹키 복호화 수행
    std::vector<uint8_t> sharedSecret;
    if (!computeECDHSharedSecret(sess, gatewayPublicKey, sharedSecret)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    
    // 7-2) 암호화된 그룹키 분리: [IV (12) | tag (16) | ciphertext (32)]로 구성되었다고 가정
    if (encryptedGroupKey.size() < 60) {
        std::cerr << "[Main] encryptedGroupKey size too small.\n";
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    std::vector<uint8_t> decIV(encryptedGroupKey.begin(), encryptedGroupKey.begin() + 12);
    std::vector<uint8_t> decTag(encryptedGroupKey.begin() + 12, encryptedGroupKey.begin() + 28);
    std::vector<uint8_t> cipherText(encryptedGroupKey.begin() + 28, encryptedGroupKey.end());
    
    if (!decryptGroupKey(sess, sharedSecret, decIV, decTag, cipherText)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    
    std::cout << "[Main] Decrypted group key size=" << cipherText.size() << "\n";
    // 복호화된 그룹키는 cipherText에 저장됨.
    
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    
    return 0;
}

