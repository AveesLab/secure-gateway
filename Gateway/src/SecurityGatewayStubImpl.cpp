#include "SecurityGatewayStubImpl.hpp"
#include "gateway_ta.h"  // TA 명령어, UUID 등 정의 (헤더파일 예제 참조)
#include <tee_client_api.h>

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
 * - 기존: RSA 공개키, 서명, (노드ID, 난수, 타임스탬프)를 검증한 후
 * - 수정: 서명 검증 성공 시 게이트웨이 TA의 CMD_GENERATE_ECDH를 호출해 게이트웨이 ECDH 공개키를 생성하여 반환
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

    // 예제에서는 노드 ID 42만 허용
    if (_nodeID != 42) {
        std::cout << "[StubImpl] Node ID is not accepted." << std::endl;
        _reply(false, gatewayPublicKey);
        return;
    }

    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Result res;
    TEEC_UUID uuid = TA_GATEWAY_UUID;  // gateway TA UUID

    // TEE 컨텍스트 초기화
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[StubImpl] TEEC_InitializeContext failed: 0x"
                  << std::hex << res << std::endl;
        _reply(false, gatewayPublicKey);
        return;
    }
    // TA와 세션 열기
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[StubImpl] TEEC_OpenSession failed: 0x"
                  << std::hex << res << std::endl;
        TEEC_FinalizeContext(&ctx);
        _reply(false, gatewayPublicKey);
        return;
    }

    // [1] 노드의 RSA 공개키 저장 시도 (이미 등록되어 있다면 무시)
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
        _reply(false, gatewayPublicKey);
        return;
    } else {
        std::cout << "[StubImpl] Public key stored successfully." << std::endl;
    }

    // [2] 서명 검증: 노드가 직렬화한 (nodeID, nonce, timestamp) 메시지와 서명 데이터를 이용
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

    // [3] 서명 검증 성공 시, 게이트웨이 TA의 CMD_GENERATE_ECDH를 호출하여 자신의 ECDH 공개키 생성
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

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    // 최종 결과 전달: 서명 검증 및 ECDH 키 생성 성공 시, 게이트웨이 ECDH 공개키를 반환
    _reply(success, gatewayPublicKey);
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
