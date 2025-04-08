#ifndef SECURITYGATEWAYSTUBIMPL_HPP
#define SECURITYGATEWAYSTUBIMPL_HPP

#include <chrono>
#include <thread>
#include <vector>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>
#include <CommonAPI/CommonAPI.hpp>
#include <v1/automotive/SecurityGatewayStubDefault.hpp>

using namespace v1_0::automotive;

class SecurityGatewayStubImpl : public SecurityGatewayStubDefault {
public:
    SecurityGatewayStubImpl(); 
    virtual ~SecurityGatewayStubImpl();

    // 수정된 requestSessionKey:
    // - 노드의 ECDH 공개키(_ecdhPublicKey) 추가
    // - _reply 콜백은 다음 인자를 전달합니다.
    //     1) Boolean success : 인증 및 키 교환 성공 여부
    //     2) std::vector<uint8_t> gatewayPublicKey : 게이트웨이의 ECDH 공개키
    //     3) std::vector<uint8_t> encryptedGroupKey : 세션키(공유비밀)로 암호화된 그룹키 (IV || tag || ciphertext)
    virtual void requestSessionKey(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _nodeID,
        uint64_t _nonce,
        uint64_t _timestamp,
        std::vector<uint8_t> _publicKey,
        std::vector<uint8_t> _signature,
        std::vector<uint8_t> _ecdhPublicKey, // 추가된 파라미터: 노드의 ECDH 공개키
        requestSessionKeyReply_t _reply
    );
};

#endif // SECURITYGATEWAYSTUBIMPL_HPP

