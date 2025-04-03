#include "Node1.hpp"
#include "signature_ta.h"
#include <tee_client_api.h>
#include <tuple>

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

    // 서비스가 활성화될 때까지 대기
    while (!myProxy->isAvailable()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cout << "[Client] Service is available!\n";
    return true;
}

bool SecurityGatewayClient::requestSessionKey(
    uint32_t _nodeID,
    uint64_t _nonce,
    uint64_t _timestamp,
    const std::vector<uint8_t> &_publicKey,
    const std::vector<uint8_t> &_signature,
    const std::vector<uint8_t> &_ecdhPublicKey,  // 추가된 파라미터
    bool &_success,
    std::vector<uint8_t> &_gatewayPublicKey
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
        _ecdhPublicKey,      // 새로운 ECDH 공개키 파라미터 전달
        callStatus,          // [out]
        _success,            // [out]
        _gatewayPublicKey    // [out]
    );
    
    if (callStatus == CommonAPI::CallStatus::SUCCESS) {
        std::cout << "[Client] requestSessionKeySync => success=" 
                  << (_success ? "true" : "false")
                  << ", gatewayPublicKeyOut.size=" << _gatewayPublicKey.size()
                  << std::endl;
        return true;
    } else {
        std::cerr << "[Client] requestSessionKey call failed. callStatus="
                  << static_cast<int>(callStatus) << std::endl;
        return false;
    }
}

//code for signature
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

    std::vector<uint8_t> tempBuf(256, 0); // 임시 버퍼
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

    // in: message
    op.params[0].tmpref.buffer = (void*)message.data();
    op.params[0].tmpref.size   = message.size();

    // out: signature buffer (초기 크기 설정)
    std::vector<uint8_t> sigBuf(256, 0);  // 2048-bit RSA 기준 256바이트
    op.params[1].tmpref.buffer = sigBuf.data();
    op.params[1].tmpref.size   = sigBuf.size();  // 반드시 초기화 필요

    TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_SIGN, &op, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Node-CA] CMD_SIGN fail: 0x" << std::hex << res << std::endl;
        return false;
    }

    // TA에서 실제 서명된 길이로 size 업데이트
    size_t sigLen = op.params[1].tmpref.size;
    signature.resize(sigLen);
    std::copy(sigBuf.begin(), sigBuf.begin() + sigLen, signature.begin());

    std::cout << "[Node-CA] signData => signature size=" << sigLen << "\n";
    return true;
}
//

// ECDH 공개키 획득 함수 (새로운 기능)
// ---------------------------------------------------------------
bool getECDHPublicKey(TEEC_Session &sess, std::vector<uint8_t> &ecdhPubKeyOut) {
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    // TA에서 할당한 버퍼 크기와 동일하게 (예: 100바이트)
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

// 메시지 직렬화 (예: nodeID, nonce, timestamp)
// ---------------------------------------------------------------
uint64_t generateNonce() {
    // 간단한 64비트 난수
    std::random_device rd;
    std::mt19937_64 gen(rd());
    return gen();
}

uint64_t getTimestamp() {
    // 현재 시간을 초 단위로 64비트 값으로 얻기
    // (고해상도 시간 필요시 .count() 사용)
    // 여기서는 epoch부터의 초 단위
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::system_clock::to_time_t(now);
    return static_cast<uint64_t>(epoch);
}

std::vector<uint8_t> serializeMessage(uint32_t node_id, uint64_t nonce, uint64_t timestamp) {
    std::vector<uint8_t> serialized;

    // node_id (uint32_t, 4바이트)
    for (int i = 0; i < 4; ++i)
        serialized.push_back(static_cast<uint8_t>((node_id >> (8 * i)) & 0xFF));

    // nonce (uint64_t, 8바이트)
    for (int i = 0; i < 8; ++i)
        serialized.push_back(static_cast<uint8_t>((nonce >> (8 * i)) & 0xFF));

    // timestamp (uint64_t, 8바이트)
    for (int i = 0; i < 8; ++i)
        serialized.push_back(static_cast<uint8_t>((timestamp >> (8 * i)) & 0xFF));

    return serialized;
}

int main() {
    // 노드 정보 생성
    uint32_t node_id = 42;
    uint64_t nonce = generateNonce();
    uint64_t timestamp = getTimestamp();
    std::cout << "[Main] nodeID=" << node_id 
              << ", nonce=" << nonce 
              << ", timestamp=" << timestamp << std::endl;
    
    // TEEC 컨텍스트 및 세션 생성
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
    
    // 1) RSA 키 생성 (최초 1회)
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
    
    // 3) 메시지 직렬화 (nodeID, nonce, timestamp)
    std::vector<uint8_t> message = serializeMessage(node_id, nonce, timestamp);
    
    // 4) 메시지 서명 (RSA 서명)
    std::vector<uint8_t> signature;
    if (!signData(sess, message, signature)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    std::cout << "[Main] signature length=" << signature.size() << std::endl;
    
    // 5) ECDH 공개키 획득
    std::vector<uint8_t> ecdhPubKey;
    if (!getECDHPublicKey(sess, ecdhPubKey)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    std::cout << "[Main] ecdhPubKey length=" << ecdhPubKey.size() << std::endl;
    
    // TEEC 세션 종료
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    
    // 6) CommonAPI를 이용하여 게이트웨이와 연결하고, requestSessionKey 호출
    SecurityGatewayClient client;
    if (!client.connectToService("gateway_service")) {
        return 1;
    }
    
    bool success = false;
    std::vector<uint8_t> gatewayPublicKey;
    // 수정된 인터페이스: ecdhPublicKey 추가
    bool callOk = client.requestSessionKey(
        node_id,        // 노드 식별자
        nonce,          // 1회성 난수
        timestamp,      // 메시지 생성 시각
        rsaPubKey,      // RSA 공개키
        signature,      // RSA 서명
        ecdhPubKey,     // 노드의 ECDH 공개키 (새로운 파라미터)
        success,        // 인증 성공 여부 (out)
        gatewayPublicKey// 게이트웨이의 공개키 (out)
    );
    
    if (callOk) {
        std::cout << "[Main] requestSessionKey callOk, success=" 
                  << (success ? "true" : "false")
                  << ", gatewayPublicKey size=" << gatewayPublicKey.size() << std::endl;
    } else {
        std::cerr << "[Main] requestSessionKey failed.\n";
    }
    
    return 0;
}
