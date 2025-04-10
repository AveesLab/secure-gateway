/*
* This file was generated by the CommonAPI Generators.
* Used org.genivi.commonapi.core 3.2.0.v202012010850.
* Used org.franca.core 0.13.1.201807231814.
*
* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
* If a copy of the MPL was not distributed with this file, You can obtain one at
* http://mozilla.org/MPL/2.0/.
*/
#ifndef V1_AUTOMOTIVE_Security_Gateway_STUB_HPP_
#define V1_AUTOMOTIVE_Security_Gateway_STUB_HPP_

#include <functional>
#include <sstream>




#include <v1/automotive/SecurityGateway.hpp>

#if !defined (COMMONAPI_INTERNAL_COMPILATION)
#define COMMONAPI_INTERNAL_COMPILATION
#define HAS_DEFINED_COMMONAPI_INTERNAL_COMPILATION_HERE
#endif

#include <vector>


#include <CommonAPI/Stub.hpp>

#if defined (HAS_DEFINED_COMMONAPI_INTERNAL_COMPILATION_HERE)
#undef COMMONAPI_INTERNAL_COMPILATION
#undef HAS_DEFINED_COMMONAPI_INTERNAL_COMPILATION_HERE
#endif

namespace v1 {
namespace automotive {

/**
 * Receives messages from remote and handles all dispatching of deserialized calls
 * to a stub for the service SecurityGateway. Also provides means to send broadcasts
 * and attribute-changed-notifications of observable attributes as defined by this service.
 * An application developer should not need to bother with this class.
 */
class SecurityGatewayStubAdapter
    : public virtual CommonAPI::StubAdapter,
      public virtual SecurityGateway {
 public:


    virtual void deactivateManagedInstances() = 0;


protected:
    /**
     * Defines properties for storing the ClientIds of clients / proxies that have
     * subscribed to the selective broadcasts
     */

};

/**
 * Defines the necessary callbacks to handle remote set events related to the attributes
 * defined in the IDL description for SecurityGateway.
 * For each attribute two callbacks are defined:
 * - a verification callback that allows to verify the requested value and to prevent setting
 *   e.g. an invalid value ("onRemoteSet<AttributeName>").
 * - an action callback to do local work after the attribute value has been changed
 *   ("onRemote<AttributeName>Changed").
 *
 * This class and the one below are the ones an application developer needs to have
 * a look at if he wants to implement a service.
 */
class SecurityGatewayStubRemoteEvent
{
public:
    virtual ~SecurityGatewayStubRemoteEvent() { }

};

/**
 * Defines the interface that must be implemented by any class that should provide
 * the service SecurityGateway to remote clients.
 * This class and the one above are the ones an application developer needs to have
 * a look at if he wants to implement a service.
 */
class SecurityGatewayStub
    : public virtual CommonAPI::Stub<SecurityGatewayStubAdapter, SecurityGatewayStubRemoteEvent>
{
public:
    typedef std::function<void (bool _success, std::vector< uint8_t > _gatewayPublicKey, std::vector< uint8_t > _encryptedGroupKey)> requestSessionKeyReply_t;

    virtual ~SecurityGatewayStub() {}
    void lockInterfaceVersionAttribute(bool _lockAccess) { static_cast<void>(_lockAccess); }
    bool hasElement(const uint32_t _id) const {
        return (_id < 1);
    }
    virtual const CommonAPI::Version& getInterfaceVersion(std::shared_ptr<CommonAPI::ClientId> _client) = 0;

    /// This is the method that will be called on remote calls on the method requestSessionKey.
    virtual void requestSessionKey(const std::shared_ptr<CommonAPI::ClientId> _client, uint32_t _nodeID, uint64_t _nonce, uint64_t _timestamp, std::vector< uint8_t > _publicKey, std::vector< uint8_t > _signature, std::vector< uint8_t > _ecdhPublicKey, requestSessionKeyReply_t _reply) = 0;


    using CommonAPI::Stub<SecurityGatewayStubAdapter, SecurityGatewayStubRemoteEvent>::initStubAdapter;
    typedef CommonAPI::Stub<SecurityGatewayStubAdapter, SecurityGatewayStubRemoteEvent>::StubAdapterType StubAdapterType;
    typedef CommonAPI::Stub<SecurityGatewayStubAdapter, SecurityGatewayStubRemoteEvent>::RemoteEventHandlerType RemoteEventHandlerType;
    typedef SecurityGatewayStubRemoteEvent RemoteEventType;
    typedef SecurityGateway StubInterface;
};

} // namespace automotive
} // namespace v1


// Compatibility
namespace v1_0 = v1;

#endif // V1_AUTOMOTIVE_Security_Gateway_STUB_HPP_
