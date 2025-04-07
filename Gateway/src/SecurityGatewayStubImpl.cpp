#include "SecurityGatewayStubImpl.hpp"
#include "gateway_ta.h"  // TA 명령어, UUID 등 정의 (헤더파일 예제 참조)
#include <tee_client_api.h>
#include <random>
#include <chrono>
#include <cstring>

// 노드에서 직렬화한 방식과 동일하게 노드ID, 난수, 타임스탬프를 직렬화하는 함수
static std::vector<uint8_t> serializeMessage(uint32_t nodeID, uint64_t nonce, uint64_t timestamp) {
    std::vector<uint8_t> serialized;
    // nodeID (4바이트, 리틀 엔디언)
    for (int i = 0; i < 4; ++i) {
        serialized.push_back((nodeID >> (8 * i)) & 0xFF);
    }
    // nonce (8바이트)
    for (int i = 0; i < 8; ++i) {
        serialized.push_back((nonce >> (8 * i)) & 0xFF);
    }
    // timestamp (8바이트)
    for (int i = 0; i < 8; ++i) {
        serialized.push_back((timestamp >> (8 * i)) & 0xFF);
    }
    return serialized;
}

SecurityGatewayStubImpl::SecurityGatewayStubImpl() { }
SecurityGatewayStubImpl::~SecurityGatewayStubImpl() { }

/*
 * 수정된 requestSessionKey:
 * - 추가 파라미터 _ecdhPublicKey: 노드 측 ECDH 공개키
 * - 기존: RSA 공개키, 서명, (노드ID, 난수, 타임스탬프)를 검증한 후,
 * - 수정: 서명 검증 성공 시
 *     [1] TA의 CMD_GENERATE_ECDH를 호출해 게이트웨이 ECDH 공개키를 생성하고,
 *     [2] 노드의 ECDH 공개키를 이용해 CMD_COMPUTE_ECDH_SHARED_SECRET를 호출하여 세션키(공유비밀)를 도출한 후,
 *     [3] TA의 store_group_key 기능(CMD_STORE_GROUP_KEY)을 이용해 그룹키를 TA 내부에서 생성·저장하고 생성된 그룹키를 반환받고,
 *     [4] 도출한 세션키로 TA의 CMD_ENCRYPT_GROUP_KEY를 호출하여, 평문 그룹키를 AES‑GCM 암호화한 결과(IV, 태그, 암호문)를 구성하여 반환합니다.
 */
void SecurityGatewayStubImpl::requestSessionKey(
    const std::shared_ptr<CommonAPI::ClientId> _client,
    uint32_t _nodeID,
    uint64_t _nonce,
    uint64_t _timestamp,
    std::vector<uint8_t> _publicKey,      // 노드의 RSA 공개키
    std::vector<uint8_t> _signature,      // 노드의 서명
    std::vector<uint8_t> _ecdhPublicKey,  // 노드의 ECDH 공개키 (추가된 파라미터)
    requestSessionKeyReply_t _reply)
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

    // TEE 컨텍스트 초기화
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[StubImpl] TEEC_InitializeContext failed: 0x"
                  << std::hex << res << std::endl;
        _reply(false, gatewayPublicKey, encryptedGroupKey);
        return;
    }
    // TA와 세션 열기
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[StubImpl] TEEC_OpenSession failed: 0x"
                  << std::hex << res << std::endl;
        TEEC_FinalizeContext(&ctx);
        _reply(false, gatewayPublicKey, encryptedGroupKey);
        return;
    }

    // [1] 노드의 RSA 공개키 저장 시도 (이미 등록되어 있다면 무시)
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

    // [2] 서명 검증: 노드가 직렬화한 (nodeID, nonce, timestamp) 메시지와 서명 데이터를 이용
    {
        std::vector<uint8_t> message = serializeMessage(_nodeID, _nonce, _timestamp);
        TEEC_Operation opVerify;
        memset(&opVerify, 0, sizeof(opVerify));
        opVerify.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT,       // 노드 ID
            TEEC_MEMREF_TEMP_INPUT, // 원본 메시지
            TEEC_MEMREF_TEMP_INPUT, // 서명 데이터
            TEEC_MEMREF_TEMP_OUTPUT // 검증 결과 (uint32_t)
        );
        opVerify.params[0].value.a = _nodeID;
        opVerify.params[1].tmpref.buffer = message.data();
        opVerify.params[1].tmpref.size = message.size();
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

    // [3] 서명 검증 성공 시, 게이트웨이 TA의 CMD_GENERATE_ECDH를 호출하여 게이트웨이의 ECDH 공개키 생성
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

    // [4] 노드의 ECDH 공개키(_ecdhPublicKey)를 이용하여 TA의 CMD_COMPUTE_ECDH_SHARED_SECRET 호출 -> 공유 비밀(세션키) 도출
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

    // [5] 그룹키 생성 및 저장: TA의 CMD_STORE_GROUP_KEY 호출 (입/출력 버퍼 사용)
    //    -> TA 내부에서 TEE_GenerateRandom()로 그룹키를 생성하여 저장하고, 생성된 그룹키를 입력 버퍼에 기록했다고 가정
    std::vector<uint8_t> plaintextGroupKey(32, 0); // 32바이트 버퍼
    if (success) {
        TEEC_Operation opStoreGroup;
        memset(&opStoreGroup, 0, sizeof(opStoreGroup));
        // TEEC_MEMREF_TEMP_INOUT: TA에서 생성한 그룹키가 클라이언트로 복사됨
        opStoreGroup.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
        opStoreGroup.params[0].tmpref.buffer = plaintextGroupKey.data();
        opStoreGroup.params[0].tmpref.size = plaintextGroupKey.size();
        res = TEEC_InvokeCommand(&sess, CMD_STORE_GROUP_KEY, &opStoreGroup, NULL);
        if (res == TEE_ERROR_ITEM_ALREADY_EXISTS) {
            std::cout << "[StubImpl] Group key already exists." << std::endl;
            // In this case, plaintextGroupKey remains unchanged.
        } else if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] CMD_STORE_GROUP_KEY failed: 0x" 
                      << std::hex << res << std::endl;
            success = false;
        } else {
            std::cout << "[StubImpl] Group key generated and stored in TA." << std::endl;
            // plaintextGroupKey now contains the generated key.
        }
    }

    // [6] 그룹키 암호화: 도출된 공유 비밀(sharedSecret)을 AES-GCM 키로 사용하여, 평문 그룹키를 암호화
    //     TA의 CMD_ENCRYPT_GROUP_KEY를 호출하여 암호문과 인증 태그를 얻고, 최종적으로 [IV || tag || ciphertext] 형태로 구성
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
        // 복호화 후 평문 그룹키의 길이와 동일한 암호문 버퍼 (초기 크기는 평문 그룹키 크기)
        std::vector<uint8_t> encryptedBuffer = plaintextGroupKey; // in/out

        TEEC_Operation opEncrypt;
        memset(&opEncrypt, 0, sizeof(opEncrypt));
        opEncrypt.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,    // 공유 비밀 (세션키)
            TEEC_MEMREF_TEMP_INPUT,    // IV
            TEEC_MEMREF_TEMP_INOUT,    // 평문 그룹키 -> 암호문으로 대체
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
            size_t cipherLen = opEncrypt.params[2].tmpref.size;
            encryptedBuffer.resize(cipherLen);
            // 최종적으로 encryptedGroupKey를 [IV || tag || 암호문]으로 구성
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

    // 최종 결과 전달: 서명 검증, ECDH 키 생성, 공유 비밀 도출, 그룹키 생성/암호화 모두 성공 시 true 반환
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

