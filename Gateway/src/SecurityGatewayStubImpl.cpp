#include "SecurityGatewayStubImpl.hpp"
#include "gateway_ta.h"      // CMD_* and TA_GATEWAY_UUID definitions
#include <tee_client_api.h>

static std::vector<uint8_t> serializeMessage(uint32_t nodeID, uint64_t nonce, uint64_t timestamp) {
    std::vector<uint8_t> serialized;
    for (int i = 0; i < 4; ++i)
        serialized.push_back(static_cast<uint8_t>((nodeID    >> (8 * i)) & 0xFF));
    for (int i = 0; i < 8; ++i)
        serialized.push_back(static_cast<uint8_t>((nonce     >> (8 * i)) & 0xFF));
    for (int i = 0; i < 8; ++i)
        serialized.push_back(static_cast<uint8_t>((timestamp >> (8 * i)) & 0xFF));
    return serialized;
}

SecurityGatewayStubImpl::SecurityGatewayStubImpl() { }
SecurityGatewayStubImpl::~SecurityGatewayStubImpl() { }

void SecurityGatewayStubImpl::requestSessionKey(
    const std::shared_ptr<CommonAPI::ClientId>,
    uint32_t _nodeID,
    uint64_t _nonce,
    uint64_t _timestamp,
    std::vector<uint8_t> _publicKey,
    std::vector<uint8_t> _signature,
    std::vector<uint8_t> _ecdhPublicKey,
    requestSessionKeyReply_t _reply)
{
    constexpr size_t SUB_MASTER_KEY_SIZE = 32;
    constexpr size_t TAG_SIZE            = 16;

    std::cout << "[StubImpl] requestSessionKey called\n"
              << " - nodeID: "   << _nodeID
              << ", nonce: "    << _nonce
              << ", timestamp: "<< _timestamp << "\n";

    // Only nodeID 42 allowed in this example
    if (_nodeID != 42) {
        std::cout << "[StubImpl] Node ID not accepted\n";
        _reply(false, {}, {});
        return;
    }

    // Prepare buffers up front
    auto msg               = serializeMessage(_nodeID, _nonce, _timestamp);
    std::vector<uint8_t> gwPub(100);
    std::vector<uint8_t> sharedSecret(32);
    std::vector<uint8_t> subMasterKey(SUB_MASTER_KEY_SIZE);
    std::vector<uint8_t> encryptedPayload; // will hold IV||ciphertext||tag

    // Initialize TEE context and session
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Result res;
    res = TEEC_InitializeContext(nullptr, &ctx);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[StubImpl] TEEC_InitializeContext failed: 0x"
                  << std::hex << res << "\n";
        _reply(false, {}, {});
        return;
    }
    TEEC_UUID uuid = TA_GATEWAY_UUID;
    res = TEEC_OpenSession(&ctx, &sess, &uuid,
        TEEC_LOGIN_PUBLIC, nullptr, nullptr, nullptr);
    if (res != TEEC_SUCCESS) {
        std::cerr << "[StubImpl] TEEC_OpenSession failed: 0x"
                  << std::hex << res << "\n";
        TEEC_FinalizeContext(&ctx);
        _reply(false, {}, {});
        return;
    }

    // [A] Store node RSA public key
    {
        TEEC_Operation op = {};
        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE,
            TEEC_NONE
        );
        op.params[0].value.a      = _nodeID;
        op.params[1].tmpref.buffer= _publicKey.data();
        op.params[1].tmpref.size  = _publicKey.size();
        res = TEEC_InvokeCommand(&sess, CMD_STORE_NODE_PUBKEY, &op, nullptr);
        if (res != TEEC_SUCCESS && res != TEE_ERROR_ITEM_ALREADY_EXISTS) {
            std::cerr << "[StubImpl] STORE_NODE_PUBKEY failed: 0x"
                      << std::hex << res << "\n";
            TEEC_CloseSession(&sess);
            TEEC_FinalizeContext(&ctx);
            _reply(false, {}, {});
            return;
        }
    }

    // [C] Verify signature
    {
       TEEC_Operation op = {};
        uint32_t verifyResult = 0;
        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_VALUE_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT
        );
        op.params[0].value.a       = _nodeID;
        op.params[1].tmpref.buffer = msg.data();
        op.params[1].tmpref.size   = msg.size();
        op.params[2].tmpref.buffer = _signature.data();
        op.params[2].tmpref.size   = _signature.size();
        op.params[3].tmpref.buffer = &verifyResult;
        op.params[3].tmpref.size   = sizeof(verifyResult);

        res = TEEC_InvokeCommand(&sess, CMD_VERIFY_SIGNATURE, &op, nullptr);
        if (res != TEEC_SUCCESS || verifyResult != 1) {
            std::cout << "[StubImpl] Signature verification failed\n";
            TEEC_CloseSession(&sess);
            TEEC_FinalizeContext(&ctx);
            _reply(false, {}, {});
            return;
        }
        std::cout << "[StubImpl] Signature verified\n";
    }

    // [D] Generate gateway ECDH public key
    {
        TEEC_Operation op = {};
        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE
        );
        op.params[0].tmpref.buffer = gwPub.data();
        op.params[0].tmpref.size   = gwPub.size();
        res = TEEC_InvokeCommand(&sess, CMD_GENERATE_ECDH, &op, nullptr);
        if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] GENERATE_ECDH failed: 0x"
                      << std::hex << res << "\n";
            TEEC_CloseSession(&sess);
            TEEC_FinalizeContext(&ctx);
            _reply(false, {}, {});
            return;
        }
        gwPub.resize(op.params[0].tmpref.size);
        std::cout << "[StubImpl] Gateway ECDH pubkey size: "
                  << gwPub.size() << "\n";
    }

    // [E] Compute shared secret
    {
        TEEC_Operation op = {};
        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_NONE,
            TEEC_NONE
        );
        op.params[0].tmpref.buffer = _ecdhPublicKey.data();
        op.params[0].tmpref.size   = _ecdhPublicKey.size();
        op.params[1].tmpref.buffer = sharedSecret.data();
        op.params[1].tmpref.size   = sharedSecret.size();
        res = TEEC_InvokeCommand(&sess, CMD_COMPUTE_ECDH_SHARED_SECRET, &op, nullptr);
        if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] COMPUTE_ECDH_SHARED_SECRET failed: 0x"
                      << std::hex << res << "\n";
            TEEC_CloseSession(&sess);
            TEEC_FinalizeContext(&ctx);
            _reply(false, {}, {});
            return;
        }
        sharedSecret.resize(op.params[1].tmpref.size);
        std::cout << "[StubImpl] Shared secret size: "
                  << sharedSecret.size() << "\n";
    }

    // [F] Derive sub-master key via HKDF
    {
        TEEC_Operation op = {};
        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_VALUE_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE
        );
        op.params[0].tmpref.buffer = subMasterKey.data();
        op.params[0].tmpref.size   = subMasterKey.size();
        op.params[1].value.a       = _nodeID;
        op.params[2].tmpref.buffer = msg.data();
        op.params[2].tmpref.size   = msg.size();
        res = TEEC_InvokeCommand(&sess, CMD_DERIVE_SUB_MASTER_KEY, &op, nullptr);
        if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] DERIVE_SUB_MASTER_KEY failed: 0x"
                      << std::hex << res << "\n";
            TEEC_CloseSession(&sess);
            TEEC_FinalizeContext(&ctx);
            _reply(false, {}, {});
            return;
        }
        std::cout << "[StubImpl] Derived sub-master key\n";
    }

    // [G] Encrypt sub-master key with AES-GCM
    {
        // 12-byte IV
        std::vector<uint8_t> iv(12);
        std::random_device rd;
        for (auto &b : iv) b = static_cast<uint8_t>(rd());

        // allocate ciphertext+tag buffer
        std::vector<uint8_t> out(subMasterKey.size() + TAG_SIZE);

        TEEC_Operation op = {};
        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,   // shared secret
            TEEC_MEMREF_TEMP_INPUT,   // IV
            TEEC_MEMREF_TEMP_INPUT,   // plaintext sub-master key
            TEEC_MEMREF_TEMP_INOUT    // ciphertext||tag
        );
        op.params[0].tmpref.buffer = sharedSecret.data();
        op.params[0].tmpref.size   = sharedSecret.size();
        op.params[1].tmpref.buffer = iv.data();
        op.params[1].tmpref.size   = iv.size();
        op.params[2].tmpref.buffer = subMasterKey.data();
        op.params[2].tmpref.size   = subMasterKey.size();
        op.params[3].tmpref.buffer = out.data();
        op.params[3].tmpref.size   = out.size();

        res = TEEC_InvokeCommand(&sess, CMD_ENCRYPT_SUB_MASTER_KEY, &op, nullptr);
        if (res != TEEC_SUCCESS) {
            std::cerr << "[StubImpl] ENCRYPT_SUB_MASTER_KEY failed: 0x"
                      << std::hex << res << "\n";
            TEEC_CloseSession(&sess);
            TEEC_FinalizeContext(&ctx);
            _reply(false, {}, {});
            return;
        }
        // build IV||ciphertext||tag
        encryptedPayload.reserve(iv.size() + out.size());
        encryptedPayload.insert(encryptedPayload.end(), iv.begin(), iv.end());
        encryptedPayload.insert(encryptedPayload.end(), out.begin(), out.end());
        std::cout << "[StubImpl] Encrypted sub-master key size: "
                  << encryptedPayload.size() << "\n";
    }

    // Cleanup and reply
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    _reply(true, gwPub, encryptedPayload);
}

int main() {
    std::cout << "[Server] Starting SecurityGateway with SOME/IP...\n";
    auto runtime = CommonAPI::Runtime::get();
    auto svc = std::make_shared<SecurityGatewayStubImpl>();
    runtime->registerService("local", "gateway_service", svc);
    std::cout << "[Server] Service registered.\n";
    for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}
