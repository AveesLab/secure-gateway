#include "SecurityGatewayStubImpl.hpp"
#include "gateway_ta.h"  // TA 명령어, UUID 등 정의 (헤더파일 예제 참조)
#include <tee_client_api.h>

// 노드에서 직렬화한 방식과 동일하게 nodeID, nonce, timestamp를 직렬화하는 함수
static std::vector<uint8_t> serializeMessage(uint32_t nodeID, uint64_t nonce, uint64_t timestamp) {
    std::vector<uint8_t> serialized;
    for (int i = 0; i < 4; ++i)
        serialized.push_back(static_cast<uint8_t>((nodeID >> (8 * i)) & 0xFF));
    for (int i = 0; i < 8; ++i)
        serialized.push_back(static_cast<uint8_t>((nonce >> (8 * i)) & 0xFF));
    for (int i = 0; i < 8; ++i)
        serialized.push_back(static_cast<uint8_t>((timestamp >> (8 * i)) & 0xFF));
    return serialized;
}

SecurityGatewayStubImpl::SecurityGatewayStubImpl() { }
SecurityGatewayStubImpl::~SecurityGatewayStubImpl() { }

/*
 * requestSessionKey:
 *  - 추가 파라미터 _ecdhPublicKey: 노드 측 ECDH 공개키 전달
 *  - [A] 노드의 RSA 공개키를 TA에 저장
 *  - [C] (nodeID, nonce, timestamp) 직렬화 및 서명 검증
 *  - [D] 서명 검증 성공 시, 게이트웨이 TA의 CMD_GENERATE_ECDH를 호출하여 게이트웨이 ECDH 공개키 생성
 *  - [E] 노드의 ECDH 공개키를 이용해 CMD_COMPUTE_ECDH_SHARED_SECRET을 호출하여 공유 비밀(세션키) 도출
 *  - [F] 도출한 공유 비밀을 AES-GCM 키로 사용하여 TA에서 하드코딩된 그룹키를 암호화(CMD_ENCRYPT_GROUP_KEY)한 결과,
 *        즉, [IV || tag || ciphertext]를 최종 노드에 전달합니다.
 * 
 * 여기서는 그룹키 복호화는 수행하지 않고, 암호화된 그룹키를 그대로 반환합니다.
 */
void SecurityGatewayStubImpl::requestSessionKey(
    const std::shared_ptr<CommonAPI::ClientId> _client,
    uint32_t _nodeID,
    uint64_t _nonce,
    uint64_t _timestamp,
    std::vector<uint8_t> _publicKey,      // 노드의 RSA 공개키
    std::vector<uint8_t> _signature,      // 노드의 서명
    std::vector<uint8_t> _ecdhPublicKey,  // 노드의 ECDH 공개키
    requestSessionKeyReply_t _reply)      // [out] 콜백 인터페이스
{
    std::cout << "[StubImpl] requestSessionKey called" << std::endl;
    std::cout << " - nodeID: " << _nodeID 
              << ", nonce: " << _nonce 
              << ", timestamp: " << _timestamp << std::endl;
    std::cout << " - RSA publicKey size: " << _publicKey.size() << std::endl;
    std::cout << " - signature size: " << _signature.size() << std::endl;
    std::cout << " - Node ECDH publicKey size: " << _ecdhPublicKey.size() << std::endl;

    bool success = false;
    std::vector<uint8_t> gatewayPublicKey;
    std::vector<uint8_t> encryptedGroupKey;  // 최종 노드로 전달할 암호화된 그룹키

    // 예제에서는 노드 ID 42만 허용
    if (_nodeID != 42) {
        std::cout << "[StubImpl] Node ID is not accepted." << std::endl;
        _reply(false, gatewayPublicKey, encryptedGroupKey);
        return;
    }

    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Result res;
    TEEC_UUID uuid = TA_GATEWAY_UUID;  // 게이트웨이 TA UUID

    // TEE 컨텍스트 초기화 및 세션 열기
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[StubImpl] TEEC_InitializeContext failed: 0x"
                  << std::hex << res << std::endl;
        _reply(false, gatewayPublicKey, encryptedGroupKey);
        return;
    }
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[StubImpl] TEEC_OpenSession failed: 0x"
                  << std::hex << res << std::endl;
        TEEC_FinalizeContext(&ctx);
        _reply(false, gatewayPublicKey, encryptedGroupKey);
        return;
    }

    // [A] 노드의 RSA 공개키 저장
    {
        TEEC_Operation opStore;
        memset(&opStore, 0, sizeof(opStore));
        opStore.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT,       // 노드 ID
            TEEC_MEMREF_TEMP_INPUT, // RSA 공개키 데이터
            TEEC_NONE,
            TEEC_NONE
        );
        opStore.params[0].value.a = _nodeID;
        opStore.params[1].tmpref.buffer = _publicKey.data();
        opStore.params[1].tmpref.size = _publicKey.size();
        res = TEEC_InvokeCommand(&sess, CMD_STORE_NODE_PUBKEY, &opStore, NULL);
        if (res == TEE_ERROR_ITEM_ALREADY_EXISTS) {
            std::cout << "[StubImpl] Public key for node " << _nodeID
                      << " already stored." << std::endl;
        } else if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] Failed to store public key: 0x"
                      << std::hex << res << std::endl;
            TEEC_CloseSession(&sess);
            TEEC_FinalizeContext(&ctx);
            _reply(false, gatewayPublicKey, encryptedGroupKey);
            return;
        } else {
            std::cout << "[StubImpl] Public key stored successfully." << std::endl;
        }
    }

    // [C] 서명 검증: (nodeID, nonce, timestamp) 직렬화한 메시지와 서명 사용
    {
        std::vector<uint8_t> msg = serializeMessage(_nodeID, _nonce, _timestamp);
        TEEC_Operation opVerify;
        memset(&opVerify, 0, sizeof(opVerify));
        opVerify.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT,       // 노드 ID
            TEEC_MEMREF_TEMP_INPUT, // 메시지 데이터
            TEEC_MEMREF_TEMP_INPUT, // 서명 데이터
            TEEC_MEMREF_TEMP_OUTPUT // 검증 결과 (uint32_t)
        );
        opVerify.params[0].value.a = _nodeID;
        opVerify.params[1].tmpref.buffer = msg.data();
        opVerify.params[1].tmpref.size = msg.size();
        opVerify.params[2].tmpref.buffer = _signature.data();
        opVerify.params[2].tmpref.size = _signature.size();
        uint32_t verificationResult = 0;
        opVerify.params[3].tmpref.buffer = &verificationResult;
        opVerify.params[3].tmpref.size = sizeof(verificationResult);
        res = TEEC_InvokeCommand(&sess, CMD_VERIFY_SIGNATURE, &opVerify, NULL);
        if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] TEEC_InvokeCommand (verify signature) failed: 0x"
                      << std::hex << res << std::endl;
            success = false;
        } else {
            success = (verificationResult == 1);
            if (success)
                std::cout << "[StubImpl] Signature verified successfully." << std::endl;
            else
                std::cout << "[StubImpl] Signature verification failed." << std::endl;
        }
    }

    // [D] 서명 검증 성공 시, 게이트웨이 TA의 CMD_GENERATE_ECDH를 호출하여 게이트웨이의 ECDH 공개키 생성
    if (success) {
        TEEC_Operation opECDH;
        memset(&opECDH, 0, sizeof(opECDH));
        opECDH.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_OUTPUT, // 게이트웨이 ECDH 공개키 반환
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
        std::vector<uint8_t> gwECDHPubKey(100, 0);  // 충분한 버퍼 (예: 100바이트)
        opECDH.params[0].tmpref.buffer = gwECDHPubKey.data();
        opECDH.params[0].tmpref.size = gwECDHPubKey.size();

        res = TEEC_InvokeCommand(&sess, CMD_GENERATE_ECDH, &opECDH, NULL);
        if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] CMD_GENERATE_ECDH failed: 0x" 
                      << std::hex << res << std::endl;
            success = false;
        } else {
            gwECDHPubKey.resize(opECDH.params[0].tmpref.size);
            std::cout << "[StubImpl] Gateway ECDH publicKey size: " 
                      << gwECDHPubKey.size() << std::endl;
            gatewayPublicKey = gwECDHPubKey;
        }
    }

    // [E] 노드의 ECDH 공개키(_ecdhPublicKey)를 이용해 CMD_COMPUTE_ECDH_SHARED_SECRET 호출하여 공유 비밀 도출
    std::vector<uint8_t> sharedSecret;
    if (success) {
        TEEC_Operation opCompute;
        memset(&opCompute, 0, sizeof(opCompute));
        opCompute.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,  // 노드의 ECDH 공개키
            TEEC_MEMREF_TEMP_OUTPUT, // 도출된 공유 비밀 (예: 32바이트)
            TEEC_NONE,
            TEEC_NONE
        );
        opCompute.params[0].tmpref.buffer = _ecdhPublicKey.data();
        opCompute.params[0].tmpref.size = _ecdhPublicKey.size();
        std::vector<uint8_t> tempSecret(32, 0);
        opCompute.params[1].tmpref.buffer = tempSecret.data();
        opCompute.params[1].tmpref.size = tempSecret.size();

        res = TEEC_InvokeCommand(&sess, CMD_COMPUTE_ECDH_SHARED_SECRET, &opCompute, NULL);
        if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] CMD_COMPUTE_ECDH_SHARED_SECRET failed: 0x" 
                      << std::hex << res << std::endl;
            success = false;
        } else {
            size_t secretLen = opCompute.params[1].tmpref.size;
            tempSecret.resize(secretLen);
            sharedSecret = tempSecret;
            std::cout << "[StubImpl] Shared secret computed, size: " << secretLen << std::endl;
        }
    }

    // [F] 그룹키 암호화: 도출한 공유 비밀(sharedSecret)을 AES-GCM 키로 사용하여,
    //     TA의 CMD_ENCRYPT_GROUP_KEY를 호출, 결과로 [IV || tag || ciphertext] 구성
    if (success) {
        // 랜덤 IV (12바이트) 생성
        std::vector<uint8_t> iv(12, 0);
        {
            std::random_device rd;
            for (auto &b : iv) {
                b = rd() & 0xFF;
            }
        }
        // 인증 태그 버퍼 (16바이트)
        std::vector<uint8_t> tag(16, 0);
        // 암호화 결과 버퍼 (평문 그룹키와 동일 크기; 32바이트)
        std::vector<uint8_t> encryptedBuffer(32, 0);

        TEEC_Operation opEncrypt;
        memset(&opEncrypt, 0, sizeof(opEncrypt));
        opEncrypt.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,    // 공유 비밀 (세션키)
            TEEC_MEMREF_TEMP_INPUT,    // IV
            TEEC_MEMREF_TEMP_INOUT,    // 암호문 (출력 버퍼)
            TEEC_MEMREF_TEMP_OUTPUT    // 인증 태그
        );
        opEncrypt.params[0].tmpref.buffer = sharedSecret.data();
        opEncrypt.params[0].tmpref.size = sharedSecret.size();
        opEncrypt.params[1].tmpref.buffer = iv.data();
        opEncrypt.params[1].tmpref.size = iv.size();
        opEncrypt.params[2].tmpref.buffer = encryptedBuffer.data();
        opEncrypt.params[2].tmpref.size = encryptedBuffer.size();
        opEncrypt.params[3].tmpref.buffer = tag.data();
        opEncrypt.params[3].tmpref.size = tag.size();

        res = TEEC_InvokeCommand(&sess, CMD_ENCRYPT_GROUP_KEY, &opEncrypt, NULL);
        if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] CMD_ENCRYPT_GROUP_KEY failed: 0x" 
                      << std::hex << res << std::endl;
            success = false;
        } else {
            // 최종 암호화 결과는 평문 그룹키와 동일한 길이 (32바이트)
            encryptedBuffer.resize(opEncrypt.params[2].tmpref.size);
            // 최종적으로 encryptedGroupKey는 [IV || tag || ciphertext]로 구성됨
            encryptedGroupKey.clear();
            encryptedGroupKey.insert(encryptedGroupKey.end(), iv.begin(), iv.end());
            encryptedGroupKey.insert(encryptedGroupKey.end(), tag.begin(), tag.end());
            encryptedGroupKey.insert(encryptedGroupKey.end(), encryptedBuffer.begin(), encryptedBuffer.end());
            std::cout << "[StubImpl] Group key encrypted. Encrypted size: " 
                      << encryptedGroupKey.size() << std::endl;
        }
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    // 최종 결과를 콜백으로 전달 (암호화된 그룹키 및 게이트웨이의 ECDH 공개키)
    _reply(success, gatewayPublicKey, encryptedGroupKey);
}

int main() {
    std::cout << "[Server] Starting SecurityGateway with SOME/IP..." << std::endl;
    
    auto runtime = CommonAPI::Runtime::get();
    std::shared_ptr<SecurityGatewayStubImpl> myService = std::make_shared<SecurityGatewayStubImpl>();
    runtime->registerService("local", "gateway_service", myService);
    std::cout << "[Server] Service registered successfully." << std::endl;
    
    while(true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
