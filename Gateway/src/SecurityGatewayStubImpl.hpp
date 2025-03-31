#ifndef SECURITYGATEWAYSTUBIMPL_HPP
#define SECURITYGATEWAYSTUBIMPL_HPP

#include <iostream>
#include <memory>
#include <CommonAPI/CommonAPI.hpp>
#include <v1/automotive/SecurityGatewayStubDefault.hpp>


using namespace v1_0::automotive;

class SecurityGatewayStubImpl : public v1_0::automotive::SecurityGatewayStubDefault {
public:
    SecurityGatewayStubImpl(); 
    virtual ~SecurityGatewayStubImpl();

    virtual void requestSessionKey(const std::shared_ptr<CommonAPI::ClientId> _client, uint32_t _nodeID, uint64_t _nonce, uint64_t _timestamp, std::vector< uint8_t > _publicKey, std::vector< uint8_t > _signature, requestSessionKeyReply_t _reply);

};

#endif // SECURITYGATEWAYSTUBIMPL_HPP
