#include "SecurityGatewayStubImpl.hpp"

SecurityGatewayStubImpl::SecurityGatewayStubImpl() { }
SecurityGatewayStubImpl::~SecurityGatewayStubImpl() { }

void SecurityGatewayStubImpl::requestSessionKey(const std::shared_ptr<CommonAPI::ClientId> _client, uint32_t _nodeID, uint64_t _nonce, uint64_t _timestamp, std::vector< uint8_t > _publicKey, std::vector< uint8_t > _signature, requestSessionKeyReply_t _reply)
{
    std::cout << "[StubImpl] requestSessionKey called" << std::endl;
    std::cout << " - nodeID: " << _nodeID << ", nonce: " << _nonce 
              << ", timestamp: " << _timestamp << std::endl;
    std::cout << " - publicKey size : " << _publicKey.size() << std::endl;
    std::cout << " - signature size : " << _signature.size() << std::endl;

    // TODO: 서명 검증, Diffie-Hellman 키 교환 로직 등을 추가 구현
    // 여기서는 임시로 success = true, gatewayPublicKey = 임의값 으로 처리

    bool success = true; 
    std::vector<uint8_t> gatewayPublicKey {0xAA, 0xBB, 0xCC, 0xDD};

    // _reply()를 통해 클라이언트에게 결과 전달
    _reply(success, gatewayPublicKey);
}


int main() {

    std::cout << "[Server] Starting SecurityGateway with SOME/IP..." << std::endl;

    // CommonAPI 런타임 객체 획득
    auto runtime = CommonAPI::Runtime::get();
    
    // Stub 구현체 생성
    std::shared_ptr<SecurityGatewayStubImpl> myService =
        std::make_shared<SecurityGatewayStubImpl>();

    runtime->registerService("local", "gateway_service", myService);
    std::cout << "[Server] Service registered successfully." << std::endl;
    // Franca IDL에서 정의한 interface 이름 + Instance 이름으로 등록
    // .fdepl에서 InstanceId = "default"로 정의했다면 아래와 같이 쓸 수 있음
    //bool regSuccess = runtime->registerService(
    //    "automotive.SecurityGateway", // 인터페이스 이름
    //    "gateway_service",                    // 인스턴스 이름
    //    myService
    //);




    // 서버는 계속 동작
    while(true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}

