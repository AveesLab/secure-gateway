#ifndef NODE_H
#define NODE_H

#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <random>
#include <thread>
#include <fstream>
#include <iomanip>
#include <cstring>


/* OP‑TEE */
#include <tee_client_api.h>
#include "signature_ta.h"              // TA_SIGN_UUID, TAG_SIZE 등

/* CommonAPI / SOME‑IP */
#include <CommonAPI/CommonAPI.hpp>
#include <v1/automotive/SecurityGatewayProxy.hpp>

using v1_0::automotive::SecurityGatewayProxy;

/* ---------- SecurityGatewayClient ---------- */
class SecurityGatewayClient {
public:
    SecurityGatewayClient();
    ~SecurityGatewayClient();

    bool connectToService(const std::string& instanceName = "gateway_service");

    bool requestSessionKey(
        uint32_t                    nodeID,
        uint64_t                    nonce,
        uint64_t                    timestamp,
        const std::vector<uint8_t>& rsaPubKey,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& ecdhPubKey,
        bool&                       success,          // out
        std::vector<uint8_t>&       gatewayPubKey,    // out
        std::vector<uint8_t>&       encryptedPayload  // out
    );

    std::shared_ptr<CommonAPI::Runtime>      runtime;
    std::shared_ptr<SecurityGatewayProxy<>>  myProxy;
};

/* ---------- TA helper prototypes ---------- */
bool createRSAKey(TEEC_Session& s);
bool getRSAPublicKey(TEEC_Session& s, std::vector<uint8_t>& out);
bool signData(TEEC_Session& s, const std::vector<uint8_t>& msg, std::vector<uint8_t>& sig);

bool getECDHPublicKey(TEEC_Session& s, std::vector<uint8_t>& pub);
bool computeECDHSharedSecret(TEEC_Session& s,
                             const std::vector<uint8_t>& gwPub,
                             std::vector<uint8_t>&       secret);

bool decryptSubMasterKey(TEEC_Session& s,
                         const std::vector<uint8_t>& secret,
                         const std::vector<uint8_t>& iv,
                         std::vector<uint8_t>&       cipherText,   // in‑out
                         const std::vector<uint8_t>& tag);

constexpr size_t kIvLen = 12;        // AES‑GCM 표준 IV 길이

#endif /* NODE_H */
