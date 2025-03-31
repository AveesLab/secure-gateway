#include "Node1.hpp"
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

//void SecurityGatewayClient::authNode() {
//    if (!myProxy) {
//        std::cerr << "[Client] Proxy is not initialized.\n";
//        return;
//    }
//    CommonAPI::CallStatus callStatus;
//
//    myProxy->requestSessionKey(
//        _nodeID,
//        _nonce,
//        _timestamp,
//        _publicKey,
//        _signature,
//        callStatus,        // [out] 호출 상태
//        successOut,        // [out] 인증 성공 여부
//        gatewayPublicKeyOut // [out] 게이트웨이 공개키
//    );
//    
//    if (callStatus == CommonAPI::CallStatus::SUCCESS) {
//        std::cout << "[Client] requestSessionKeySync => success=" 
//                  << (successOut ? "true" : "false")
//                  << ", gatewayPublicKeyOut.size=" << gatewayPublicKeyOut.size()
//                  << std::endl;
//        return 0;
//    } else {
//        std::cerr << "[Client] requestSessionKey call failed. callStatus="
//                  << (int)callStatus << std::endl;
//        return 1;
//    }
//}

int main() {
    SecurityGatewayClient client;

    // 서비스 연결
    if (!client.connectToService("gateway_service")) {
        return 1;
    }

    // requestSessionKey 테스트
    bool success = false;
    std::vector<uint8_t> gatewayPublicKey;
    bool callOk = client.requestSessionKey(
        42,             // nodeID
        123456,         // nonce
        987654,         // timestamp
        {0x11, 0x22},   // publicKey
        {0x33, 0x44},   // signature
        success,        // out
        gatewayPublicKey // out
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

