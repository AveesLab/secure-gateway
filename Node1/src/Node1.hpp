#ifndef NODE_H
#define NODE_H

#include <iostream>
#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <chrono>
#include <random>
#include <ctime>
#include <tuple>
#include <CommonAPI/CommonAPI.hpp>
#include <v1/automotive/SecurityGatewayProxy.hpp>


using namespace v1_0::automotive;

class SecurityGatewayClient {
public:
    SecurityGatewayClient();
    ~SecurityGatewayClient();

    std::shared_ptr<CommonAPI::Runtime> runtime;
    std::shared_ptr<SecurityGatewayProxy<>> myProxy;

    bool connectToService(const std::string &instanceName = "gateway_service");

    bool requestSessionKey(
        uint32_t _nodeID,
        uint64_t _nonce,
        uint64_t _timestamp,
        const std::vector<uint8_t> &_publicKey,     // RSA 공개키 등
        const std::vector<uint8_t> &_signature,       // RSA 서명
        const std::vector<uint8_t> &_ecdhPublicKey,     // 노드의 ECDH 공개키 (새로운 파라미터)
        bool &_success,                               // out: 인증 성공 여부
        std::vector<uint8_t> &_gatewayPublicKey,        // out: 게이트웨이의 공개키 (예, ECDH 공개키)
        std::vector<uint8_t> &_encryptedGroupKey        // out: 암호화된 그룹키 (예: IV+tag+ciphertext)
    );
};


#endif // NODE_H
