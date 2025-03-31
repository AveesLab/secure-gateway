#ifndef NODE_H
#define NODE_H

#include <iostream>
#include <cstdint>
#include <vector>
#include <memory>
#include <string>
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
        const std::vector<uint8_t> &_publicKey,
        const std::vector<uint8_t> &_signature,
        bool &_success,                        // out
        std::vector<uint8_t> &_gatewayPublicKey // out
    );

//    void authNode();
};


#endif // NODE_H
