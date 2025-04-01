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
        callStatus,        // [out]
        _success,          // [out]
        _gatewayPublicKey  // [out]
    );
    
    if (callStatus == CommonAPI::CallStatus::SUCCESS) {
        std::cout << "[Client] requestSessionKeySync => success=" 
                  << (_success ? "true" : "false")
                  << ", gatewayPublicKeyOut.size=" << _gatewayPublicKey.size()
                  << std::endl;
        return true;
    } else {
        std::cerr << "[Client] requestSessionKey call failed. callStatus="
                  << (int)callStatus << std::endl;
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
    // Node ID (고정 42)
    uint32_t node_id = 42;

    // 난수 / 타임스탬프 실제 값 생성
    uint64_t nonce = generateNonce();
    uint64_t timestamp = getTimestamp();

    std::cout << "[Main] nodeID=" << node_id 
              << ", nonce=" << nonce 
              << ", timestamp=" << timestamp << std::endl;

    // 1) TEEC 컨텍스트 및 세션 준비
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_SIGN_UUID;
    TEEC_Result res;

    // Initialize context
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Main] TEEC_InitializeContext fail 0x" << std::hex << res << std::endl;
        return 1;
    }
    // Open session
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[Main] TEEC_OpenSession fail 0x" << std::hex << res << std::endl;
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    // 2) RSA 키 생성 (한번만)
    if (!createRSAKey(sess)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    // 3) 공개키(모듈러스) 가져오기
    std::vector<uint8_t> pubKey;
    if (!getRSAPublicKey(sess, pubKey)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    std::cout << "[Main] pubKey length=" << pubKey.size() << std::endl;

    // 4) 임의의 메시지 준비( nodeID, nonce, timestamp )를 직렬화
    std::vector<uint8_t> message = serializeMessage(node_id, nonce, timestamp);

    // 5) 서명
    std::vector<uint8_t> signature;
    if (!signData(sess, message, signature)) {
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    std::cout << "[Main] signature length=" << signature.size() << std::endl;

    // TEEC 세션은 계속 유지된 상태거나, 여기서 닫아도 됨
    // For demonstration, let's keep it open or we can close
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
	
    SecurityGatewayClient client;

    // 서비스 연결
    if (!client.connectToService("gateway_service")) {
        // cleanup TEEC
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    // requestSessionKey
    bool success = false;
    std::vector<uint8_t> gatewayPublicKey;
    bool callOk = client.requestSessionKey(
        node_id,                    // nodeID=42
        nonce,                     // 생성된 난수
        timestamp,                 // 생성된 타임스탬프
        pubKey,                    // OP-TEE에서 얻은 공개키 (모듈러스 등)
        signature,                 // OP-TEE로 서명된 값
        success,
        gatewayPublicKey
    );

    if (callOk) {
        std::cout << "[Main] requestSessionKey callOk, success="
                  << (success ? "true":"false")
                  << ", gwPublicKey.size=" << gatewayPublicKey.size()
                  << std::endl;
    } else {
        std::cerr << "[Main] requestSessionKey failed.\n";
    }

    return 0;
}

