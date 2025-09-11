#include "SecurityGatewayStubImpl.hpp"
#include "gateway_ta.h"      // CMD_* and TA_GATEWAY_UUID definitions
#include <tee_client_api.h>
#include <sched.h>   // sched_setaffinity
#include <unistd.h>  // getpid()

// ===== Crypto++ (Normal World) =====
#include <crypto++/osrng.h>
#include <crypto++/oids.h>
#include <crypto++/eccrypto.h>
#include <crypto++/hmac.h>
#include <crypto++/sha.h>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/filters.h>
#include <crypto++/secblock.h>
#include <crypto++/files.h>

#ifndef MASTER_KEY_SIZE
#define MASTER_KEY_SIZE 32
#endif
#ifndef ECDSA_PUBKEY_UNCOMPRESSED_SIZE
#define ECDSA_PUBKEY_UNCOMPRESSED_SIZE 65
#endif
#ifndef TAG_SIZE
#define TAG_SIZE 16
#endif
#ifndef IV_LEN
#define IV_LEN 12
#endif

#ifdef __linux__
#include <sys/stat.h>
#endif

namespace cc = CryptoPP;

// ---------- 공통 타입 ----------
using Clock   = std::chrono::high_resolution_clock;
using micros  = std::chrono::microseconds;
using millis  = std::chrono::milliseconds;

/* ===================== 모드 선택 ===================== */
enum class CryptoMode { TEE, NORMAL };
// 서버는 기본적으로 TEE를 기본값으로 하되, CRYPTO_MODE=NORMAL로 스위치 가능
static constexpr CryptoMode CRYPTO_MODE_DEFAULT = CryptoMode::TEE;
static CryptoMode parseCryptoModeFromEnv() {
    const char* env = std::getenv("CRYPTO_MODE");
    if (!env) return CRYPTO_MODE_DEFAULT;
    std::string s(env);
    if (s == "TEE")    return CryptoMode::TEE;
    if (s == "NORMAL") return CryptoMode::NORMAL;
    return CRYPTO_MODE_DEFAULT;
}


// ---------- 지연시간 측정 템플릿 ----------
template<typename F>
uint64_t measureLatency(F&& func, bool &ok_out)
{
    auto t0 = Clock::now();
    ok_out  = func();        // 단계 실행
    auto t1 = Clock::now();
    return std::chrono::duration_cast<micros>(t1 - t0).count();
}

// ---------- CSV 로거 ----------
struct CsvLogger {
    std::ofstream file;
    bool header_written{false};

    CsvLogger(const std::string &path) {
        file.open(path, std::ios::app);
        if (!file.is_open()) {
            std::cerr << "[Error] Failed to open CSV file: " << path << "\n";
        }
    }

    void writeHeader() {
        if (!header_written && file.is_open()) {
            std::cout << "[Debug] CSV file opened: " << std::boolalpha << file.is_open() << "\n";
            file << "timestamp,nodeID,step,latency_us,status,size_bytes\n";
            file.flush();                  // ← 여기를 추가
            header_written = true;
        }
    }

    void log(uint32_t nodeID, const std::string &step, uint64_t latency, bool ok, size_t size = 0) {
        if (!file.is_open()) return;

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        char buf[32];
        std::strftime(buf, sizeof(buf), "%FT%T%z", std::localtime(&now));

        file << buf
             << ',' << nodeID
             << ',' << step
             << ',' << latency
             << ',' << (ok ? "success" : "fail")
             << ',' << size
             << '\n';
        file.flush();                  // ← 여기를 추가
    }
};

static void logAndPrint(CsvLogger& csv,
                        uint32_t nodeID,
                        const std::string& step,
                        uint64_t latency_us,
                        bool ok,
                        size_t size_bytes = 0) {
    // CSV 기록
    csv.log(nodeID, step, latency_us, ok, size_bytes);

    // 콘솔 출력
    std::cout << "[SEC][" << nodeID << "] "
              << step << ": " << (ok ? "OK" : "FAIL")
              << " (" << latency_us << " us";
    if (size_bytes > 0) std::cout << ", size=" << size_bytes;
    std::cout << ")\n";
}


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

/* ===================== NORMAL World 구현 ===================== */
struct GW_NW_Ctx {
    cc::AutoSeededRandomPool prng;
    cc::SecByteBlock ecdhPriv, ecdhPub; // 게이트웨이 측 ECDH 키쌍
};

// TA와 동일한 32바이트 master_key (HKDF IKM)
static const uint8_t GW_MASTER_KEY[MASTER_KEY_SIZE] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
    0x0A,0x1B,0x2C,0x3D,0x4E,0x5F,0x6A,0x7B,
    0x8C,0x9D,0xAE,0xBF,0xC0,0xD1,0xE2,0xF3
};

static bool nw_storeNodePubKey(uint32_t nodeID, const std::vector<uint8_t>& pub65) {
    try {
        if (pub65.size() != 65 || pub65[0] != 0x04) return false;
        std::string path = "gw_node_pubkey_" + std::to_string(nodeID) + ".bin";
        std::ofstream f(path, std::ios::binary);
        if (!f.is_open()) return false;
        f.write(reinterpret_cast<const char*>(pub65.data()), pub65.size());
        bool ok = f.good();
        f.close();
        #ifdef __linux__
        if (ok) ::chmod(path.c_str(), 0600);
        #endif
        return ok;
    } catch (...) { return false; }
}

static bool nw_loadNodePubKey(uint32_t nodeID, std::vector<uint8_t>& pub65) {
    try {
        std::string path = "gw_node_pubkey_" + std::to_string(nodeID) + ".bin";
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open()) return false;
        f.seekg(0, std::ios::end);
        auto n = f.tellg();
        f.seekg(0, std::ios::beg);
        if (n != 65) return false;
        pub65.resize(65);
        f.read(reinterpret_cast<char*>(pub65.data()), 65);
        return f.good();
    } catch (...) { return false; }
}

// 65B(0x04|X|Y) → ECDSA P-256 공개키 객체
static bool nw_makeECDSAPub_from_uncompressed65(const std::vector<uint8_t>& pub65,
                                                cc::ECDSA<cc::ECP, cc::SHA256>::PublicKey& out) {
    if (pub65.size() != 65 || pub65[0] != 0x04) return false;
    cc::Integer x, y;
    x.Decode(pub65.data()+1, 32);
    y.Decode(pub65.data()+33, 32);
    cc::ECP::Point Q(x, y);
    try {
        out.Initialize(cc::ASN1::secp256r1(), Q);
        cc::AutoSeededRandomPool prng;
        return out.Validate(prng, 3);
    } catch (...) { return false; }
}

static bool nw_verifySignature_withPub65(const std::vector<uint8_t>& msg,
                                         const std::vector<uint8_t>& sigDER,
                                         const std::vector<uint8_t>& pub65) {
    cc::ECDSA<cc::ECP, cc::SHA256>::PublicKey pub;
    if (!nw_makeECDSAPub_from_uncompressed65(pub65, pub)) return false;
    try {
        cc::ECDSA<cc::ECP, cc::SHA256>::Verifier verifier(pub);
        return verifier.VerifyMessage(msg.data(), msg.size(), sigDER.data(), sigDER.size());
    } catch (...) { return false; }
}

// 게이트웨이 ECDH 키쌍 생성
static bool nw_generateECDH(GW_NW_Ctx& ctx, std::vector<uint8_t>& outPub65) {
    cc::ECDH<cc::ECP>::Domain dom(cc::ASN1::secp256r1());
    ctx.ecdhPriv.CleanNew(dom.PrivateKeyLength());
    ctx.ecdhPub .CleanNew(dom.PublicKeyLength());
    dom.GenerateKeyPair(ctx.prng, ctx.ecdhPriv, ctx.ecdhPub); // void 반환
    outPub65.resize(ctx.ecdhPub.size());
    std::memcpy(outPub65.data(), ctx.ecdhPub, ctx.ecdhPub.size());
    return true;
}

// 공유 비밀 계산
static bool nw_computeSharedSecret(const GW_NW_Ctx& ctx,
                                   const std::vector<uint8_t>& peerPub65,
                                   std::vector<uint8_t>& shared32) {
    cc::ECDH<cc::ECP>::Domain dom(cc::ASN1::secp256r1());
    if (peerPub65.size() != dom.PublicKeyLength()) return false; // 65
    cc::SecByteBlock peer(peerPub65.size());
    std::memcpy(peer, peerPub65.data(), peerPub65.size());
    cc::SecByteBlock agreed(dom.AgreedValueLength()); // 32
    if (!dom.Agree(agreed, ctx.ecdhPriv, peer)) return false;
    shared32.resize(agreed.size());
    std::memcpy(shared32.data(), agreed, agreed.size());
    return true;
}

// HKDF-SHA256 (RFC 5869), salt 생략 — IKM=GW_MASTER_KEY, info=msg
static bool hkdf_sha256_master(const uint8_t* info, size_t info_len,
                               uint8_t* okm, size_t okm_len) {
    try {
        // Extract with zero salt
        cc::SecByteBlock prk(cc::SHA256::DIGESTSIZE);
        cc::SecByteBlock zeros(cc::SHA256::DIGESTSIZE); std::memset(zeros, 0, zeros.size());
        cc::HMAC<cc::SHA256> hmac_extract(zeros, zeros.size());
        hmac_extract.Update(GW_MASTER_KEY, sizeof(GW_MASTER_KEY));
        hmac_extract.Final(prk);

        // Expand
        cc::HMAC<cc::SHA256> hmac_expand(prk, prk.size());
        cc::SecByteBlock T(cc::SHA256::DIGESTSIZE);
        size_t pos = 0;
        uint8_t ctr = 1;
        while (pos < okm_len) {
            hmac_expand.Restart();
            if (pos) hmac_expand.Update(T, T.size());
            if (info && info_len) hmac_expand.Update(info, info_len);
            hmac_expand.Update(&ctr, 1);
            hmac_expand.Final(T);
            size_t to_copy = std::min((size_t)T.size(), okm_len - pos);
            std::memcpy(okm + pos, T, to_copy);
            pos += to_copy;
            ctr++;
        }
        return true;
    } catch (...) { return false; }
}

// AES-GCM 암호화: 입력 key(=sharedSecret), iv(12B), plain(=SMK 32B) → out(ct||tag)
static bool nw_gcm_encrypt_smk(const std::vector<uint8_t>& key32,
                               const std::vector<uint8_t>& iv12,
                               const std::vector<uint8_t>& plain32,
                               std::vector<uint8_t>& out_ct_tag) {
    try {
        cc::GCM<cc::AES>::Encryption enc;
        enc.SetKeyWithIV(key32.data(), key32.size(), iv12.data(), iv12.size());
        std::string ct;
        cc::AuthenticatedEncryptionFilter ef(
            enc, new cc::StringSink(ct), false, 16 /*TAG*/
        );
        cc::ArraySource as(plain32.data(), plain32.size(), true, new cc::Redirector(ef));
        out_ct_tag.assign(ct.begin(), ct.end());
        return true;
    } catch (...) { return false; }
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
    auto exec_start = Clock::now();

    // CSV 로거 준비 (프로세스 내에서 단일 객체)
    static CsvLogger csv("./gateway_latency.csv");
    csv.writeHeader();

    constexpr size_t SUB_MASTER_KEY_SIZE = 32;
    //constexpr size_t TAG_SIZE            = 16;
    //constexpr size_t IV_LEN              = 12;

    if (!(_nodeID == 42 || _nodeID == 45 || _nodeID == 46 || _nodeID == 43 ||_nodeID == 44 ||_nodeID == 82 ||_nodeID == 92 || _nodeID == 47 || _nodeID == 12 || _nodeID == 55 || _nodeID == 56 || _nodeID == 53 ||_nodeID == 54 ||_nodeID == 102 ||_nodeID == 103 || _nodeID == 99 )) {
        csv.log(_nodeID, "reject_nodeID", 0, false);
        std::cout << "[SEC][" << _nodeID << "] reject_nodeID: FAIL (unauthorized)\n";
        _reply(false, {}, {});
        return;
    }

    // 공통 메시지 직렬화
    std::vector<uint8_t> msg = serializeMessage(_nodeID, _nonce, _timestamp);

    // 모드 결정
    CryptoMode modeSel = parseCryptoModeFromEnv();

    if (modeSel == CryptoMode::TEE) {
        // ----- 기존 TEE 경로 (원본 로직 그대로) -----
        TEEC_Context ctx; TEEC_Session sess; TEEC_Result res;
        bool ok; uint64_t latency;

        latency = measureLatency([&]{ return (TEEC_InitializeContext(NULL, &ctx) == TEEC_SUCCESS); }, ok);
        if(!ok){ csv.log(_nodeID,"InitCtx",latency,false); _reply(false,{},{ }); return; }
        logAndPrint(csv, _nodeID,"InitCtx",latency,true);

        latency = measureLatency([&]{
            TEEC_UUID uuid = TA_GATEWAY_UUID;
            res = TEEC_OpenSession(&ctx,&sess,&uuid,TEEC_LOGIN_PUBLIC,NULL,NULL,NULL);
            return (res==TEEC_SUCCESS);
        }, ok);
        if(!ok){ csv.log(_nodeID,"OpenSess",latency,false); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
        logAndPrint(csv, _nodeID,"OpenSess",latency,true);

        // [A] STORE_NODE_PUBKEY
        latency = measureLatency([&]{
            TEEC_Operation op = {};
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,TEEC_MEMREF_TEMP_INPUT,0,0);
            op.params[0].value.a      = _nodeID;
            op.params[1].tmpref.buffer= _publicKey.data();
            op.params[1].tmpref.size  = _publicKey.size();
            res = TEEC_InvokeCommand(&sess, CMD_STORE_NODE_PUBKEY, &op, NULL);
            return (res==TEEC_SUCCESS || res==TEE_ERROR_ITEM_ALREADY_EXISTS);
        }, ok);
        logAndPrint(csv, _nodeID,"StoreNodePub",latency,ok,_publicKey.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }

        // [C] VERIFY_SIGNATURE
        uint32_t verifyResult=0;
        latency = measureLatency([&]{
            TEEC_Operation op = {};
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT);
            op.params[0].value.a       = _nodeID;
            op.params[1].tmpref.buffer = msg.data(); op.params[1].tmpref.size = msg.size();
            op.params[2].tmpref.buffer = _signature.data(); op.params[2].tmpref.size = _signature.size();
            op.params[3].tmpref.buffer = &verifyResult; op.params[3].tmpref.size = sizeof(verifyResult);
            res = TEEC_InvokeCommand(&sess, CMD_VERIFY_SIGNATURE, &op, NULL);
            return (res==TEEC_SUCCESS && verifyResult==1);
        }, ok);
        logAndPrint(csv, _nodeID,"VerifySig",latency,ok,_signature.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }

        // [D] GENERATE_ECDH
        std::vector<uint8_t> gwPub(100);
        latency = measureLatency([&]{
            TEEC_Operation op = {};
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,0,0,0);
            op.params[0].tmpref.buffer=gwPub.data(); op.params[0].tmpref.size=gwPub.size();
            res = TEEC_InvokeCommand(&sess, CMD_GENERATE_ECDH, &op, NULL);
            gwPub.resize(op.params[0].tmpref.size);
            return (res==TEEC_SUCCESS);
        }, ok);
        logAndPrint(csv, _nodeID,"GenECDH",latency,ok,gwPub.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }

        // [E] COMPUTE_SHARED_SECRET
        std::vector<uint8_t> sharedSecret(32);
        latency = measureLatency([&]{
            TEEC_Operation op = {};
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,0,0);
            op.params[0].tmpref.buffer = _ecdhPublicKey.data(); op.params[0].tmpref.size = _ecdhPublicKey.size();
            op.params[1].tmpref.buffer = sharedSecret.data();  op.params[1].tmpref.size = sharedSecret.size();
            res = TEEC_InvokeCommand(&sess, CMD_COMPUTE_ECDH_SHARED_SECRET, &op, NULL);
            sharedSecret.resize(op.params[1].tmpref.size);
            return (res==TEEC_SUCCESS);
        }, ok);
        logAndPrint(csv, _nodeID,"ECDHShared",latency,ok,sharedSecret.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }

        // [F] DERIVE_SUB_MASTER_KEY — TA는 IKM=master_key(고정), info=msg
        std::vector<uint8_t> subMasterKey(SUB_MASTER_KEY_SIZE);
        latency = measureLatency([&]{
            TEEC_Operation op = {};
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,TEEC_VALUE_INPUT,TEEC_MEMREF_TEMP_INPUT,0);
            op.params[0].tmpref.buffer = subMasterKey.data(); op.params[0].tmpref.size = subMasterKey.size();
            op.params[1].value.a       = _nodeID;
            op.params[2].tmpref.buffer = msg.data(); op.params[2].tmpref.size = msg.size();
            res = TEEC_InvokeCommand(&sess, CMD_DERIVE_SUB_MASTER_KEY, &op, NULL);
            return (res==TEEC_SUCCESS);
        }, ok);
        logAndPrint(csv, _nodeID,"DeriveSMK",latency,ok,subMasterKey.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }

        // [G] ENCRYPT_SUB_MASTER_KEY (AES-GCM, key=sharedSecret, iv=12B)
        std::vector<uint8_t> encryptedPayload; encryptedPayload.reserve(IV_LEN + SUB_MASTER_KEY_SIZE + TAG_SIZE);
        latency = measureLatency([&]{
            std::vector<uint8_t> iv(IV_LEN); std::random_device rd; for(auto &b:iv) b=static_cast<uint8_t>(rd());
            std::vector<uint8_t> out(subMasterKey.size()+TAG_SIZE);
            TEEC_Operation op = {};
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INOUT);
            op.params[0].tmpref.buffer = sharedSecret.data(); op.params[0].tmpref.size = sharedSecret.size();
            op.params[1].tmpref.buffer = iv.data();          op.params[1].tmpref.size = iv.size();
            op.params[2].tmpref.buffer = subMasterKey.data(); op.params[2].tmpref.size = subMasterKey.size();
            op.params[3].tmpref.buffer = out.data();         op.params[3].tmpref.size = out.size();
            res = TEEC_InvokeCommand(&sess, CMD_ENCRYPT_SUB_MASTER_KEY, &op, NULL);
            if(res!=TEEC_SUCCESS) return false;
            encryptedPayload.insert(encryptedPayload.end(), iv.begin(), iv.end());
            encryptedPayload.insert(encryptedPayload.end(), out.begin(), out.end());
            return true;
        }, ok);
        logAndPrint(csv, _nodeID,"EncryptSMK",latency,ok,encryptedPayload.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }

        // Cleanup & reply
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);

        _reply(true, gwPub, encryptedPayload);

        auto exec_end = Clock::now();
        auto exec_latency_us = std::chrono::duration_cast<micros>(exec_end - exec_start).count();

        csv.log(_nodeID, "Total", exec_latency_us, true);
        std::cout << "[SEC][" << _nodeID << "] Total: " << exec_latency_us << " us\n";
        csv.log(_nodeID,"-----",0,true);
        return;
    }
    else {
        // ==================== NORMAL 경로 (Crypto++) ====================
        GW_NW_Ctx gw;
        bool ok; uint64_t latency;

        // [A] STORE_NODE_PUBKEY (파일 저장)
        latency = measureLatency([&]{
            return nw_storeNodePubKey(_nodeID, _publicKey);
        }, ok);
        csv.log(_nodeID,"StoreNodePub",latency,ok,_publicKey.size());
        if(!ok){ _reply(false,{},{}); return; }

        // [C] VERIFY_SIGNATURE (제공된 공개키로 메시지 검증)
        std::vector<uint8_t> msg_local = msg; // (가독성)
        latency = measureLatency([&]{
            return nw_verifySignature_withPub65(msg_local, _signature, _publicKey);
        }, ok);
        csv.log(_nodeID,"VerifySig",latency,ok,_signature.size());
        if(!ok){ _reply(false,{},{}); return; }

        // [D] GENERATE_ECDH
        std::vector<uint8_t> gwPub;
        latency = measureLatency([&]{
            return nw_generateECDH(gw, gwPub);
        }, ok);
        csv.log(_nodeID,"GenECDH",latency,ok,gwPub.size());
        if(!ok){ _reply(false,{},{ }); return; }

        // [E] COMPUTE_SHARED_SECRET
        std::vector<uint8_t> sharedSecret;
        latency = measureLatency([&]{
            return nw_computeSharedSecret(gw, _ecdhPublicKey, sharedSecret);
        }, ok);
        csv.log(_nodeID,"ECDHShared",latency,ok,sharedSecret.size());
        if(!ok){ _reply(false,{},{ }); return; }

        // [F] DERIVE_SUB_MASTER_KEY — **TA와 동일 규칙**
        //    IKM = 고정 MASTER_KEY, info = serializeMessage(nodeID, nonce, timestamp)
        std::vector<uint8_t> subMasterKey(SUB_MASTER_KEY_SIZE);
        latency = measureLatency([&]{
            return hkdf_sha256_master(msg_local.data(), msg_local.size(),
                                      subMasterKey.data(), subMasterKey.size());
        }, ok);
        csv.log(_nodeID,"DeriveSMK",latency,ok,subMasterKey.size());
        if(!ok){ _reply(false,{},{ }); return; }

        // [G] ENCRYPT_SUB_MASTER_KEY (AES-GCM, key=sharedSecret, iv=12B 랜덤)
        std::vector<uint8_t> encryptedPayload;
        latency = measureLatency([&]{
            std::vector<uint8_t> iv(IV_LEN);
            cc::AutoSeededRandomPool prng;
            prng.GenerateBlock(iv.data(), iv.size());

            std::vector<uint8_t> ct_tag;
            if (!nw_gcm_encrypt_smk(sharedSecret, iv, subMasterKey, ct_tag)) return false;

            encryptedPayload.reserve(iv.size() + ct_tag.size());
            encryptedPayload.insert(encryptedPayload.end(), iv.begin(), iv.end());
            encryptedPayload.insert(encryptedPayload.end(), ct_tag.begin(), ct_tag.end());
            return true;
        }, ok);
        csv.log(_nodeID,"EncryptSMK",latency,ok,encryptedPayload.size());
        if(!ok){ _reply(false,{},{ }); return; }

        // Reply
        _reply(true, gwPub, encryptedPayload);

        auto exec_end = Clock::now();
//       auto exec_latency_ms = std::chrono::duration_cast<millis>(exec_end - exec_start).count();
//        csv.log(_nodeID, "Total", exec_latency_ms, true);
        auto exec_latency_us = std::chrono::duration_cast<micros>(exec_end - exec_start).count();
        csv.log(_nodeID, "Total", exec_latency_us, true);
        csv.log(_nodeID,"-----",0,true);
        return;
    }
}


// void SecurityGatewayStubImpl::requestSessionKey(
//     const std::shared_ptr<CommonAPI::ClientId>,
//     uint32_t _nodeID,
//     uint64_t _nonce,
//     uint64_t _timestamp,
//     std::vector<uint8_t> _publicKey,
//     std::vector<uint8_t> _signature,
//     std::vector<uint8_t> _ecdhPublicKey,
//     requestSessionKeyReply_t _reply)
//     {
//         auto exec_start = Clock::now();

//         // CSV 로거 준비 (프로세스 내에서 단일 객체)
//         static CsvLogger csv("./gateway_latency.csv");
//         csv.writeHeader();
    
//         constexpr size_t SUB_MASTER_KEY_SIZE = 32;
//         constexpr size_t TAG_SIZE            = 16;
    
// //        std::cout << "[StubImpl] requestSessionKey called\n"
// //                  << " - nodeID: "   << _nodeID
// //                  << ", nonce: "    << _nonce
// //                  << ", timestamp: "<< _timestamp << "\n";
    
//         if (!(_nodeID == 42 || _nodeID == 45 || _nodeID == 46 || _nodeID == 43 ||_nodeID == 44 ||_nodeID == 82 ||_nodeID == 92 ||_nodeID == 47)) {
//             csv.log(_nodeID, "reject_nodeID", 0, false);
//             _reply(false, {}, {});
//             return;
//         }
    
//         //----------- TEE Context & Session -----------
//         TEEC_Context ctx; TEEC_Session sess; TEEC_Result res;
//         bool ok; uint64_t latency;
    
//         latency = measureLatency([&]{ return (TEEC_InitializeContext(NULL, &ctx) == TEEC_SUCCESS); }, ok);
//         if(!ok){ csv.log(_nodeID,"InitCtx",latency,false); _reply(false,{},{ }); return; }
//         csv.log(_nodeID,"InitCtx",latency,true);
    
//         latency = measureLatency([&]{
//             TEEC_UUID uuid = TA_GATEWAY_UUID;
//             res = TEEC_OpenSession(&ctx,&sess,&uuid,TEEC_LOGIN_PUBLIC,NULL,NULL,NULL);
//             return (res==TEEC_SUCCESS);
//         }, ok);
//         if(!ok){ csv.log(_nodeID,"OpenSess",latency,false); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
//         csv.log(_nodeID,"OpenSess",latency,true);
    
//         //------ [A] STORE_NODE_PUBKEY ------
//         latency = measureLatency([&]{
//             TEEC_Operation op = {};
//             op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,TEEC_MEMREF_TEMP_INPUT,0,0);
//             op.params[0].value.a      = _nodeID;
//             op.params[1].tmpref.buffer= _publicKey.data();
//             op.params[1].tmpref.size  = _publicKey.size();
//             res = TEEC_InvokeCommand(&sess, CMD_STORE_NODE_PUBKEY, &op, NULL);
//             return (res==TEEC_SUCCESS || res==TEE_ERROR_ITEM_ALREADY_EXISTS);
//         }, ok);
//         csv.log(_nodeID,"StoreNodePub",latency,ok,_publicKey.size());
//         if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
//         //------ [C] VERIFY_SIGNATURE ------
//         std::vector<uint8_t> msg = serializeMessage(_nodeID,_nonce,_timestamp);
//         uint32_t verifyResult=0;
//         latency = measureLatency([&]{
//             TEEC_Operation op = {};
//             op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT);
//             op.params[0].value.a       = _nodeID;
//             op.params[1].tmpref.buffer = msg.data(); op.params[1].tmpref.size = msg.size();
//             op.params[2].tmpref.buffer = _signature.data(); op.params[2].tmpref.size = _signature.size();
//             op.params[3].tmpref.buffer = &verifyResult; op.params[3].tmpref.size = sizeof(verifyResult);
//             res = TEEC_InvokeCommand(&sess, CMD_VERIFY_SIGNATURE, &op, NULL);
//             return (res==TEEC_SUCCESS && verifyResult==1);
//         }, ok);
//         csv.log(_nodeID,"VerifySig",latency,ok,_signature.size());
//         if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
//         //------ [D] GENERATE_ECDH ------
//         std::vector<uint8_t> gwPub(100);
//         latency = measureLatency([&]{
//             TEEC_Operation op = {};
//             op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,0,0,0);
//             op.params[0].tmpref.buffer=gwPub.data(); op.params[0].tmpref.size=gwPub.size();
//             res = TEEC_InvokeCommand(&sess, CMD_GENERATE_ECDH, &op, NULL);
//             gwPub.resize(op.params[0].tmpref.size);
//             return (res==TEEC_SUCCESS);
//         }, ok);
//         csv.log(_nodeID,"GenECDH",latency,ok,gwPub.size());
//         if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
//         //------ [E] COMPUTE_SHARED_SECRET ------
//         std::vector<uint8_t> sharedSecret(32);
//         latency = measureLatency([&]{
//             TEEC_Operation op = {};
//             op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,0,0);
//             op.params[0].tmpref.buffer = _ecdhPublicKey.data(); op.params[0].tmpref.size = _ecdhPublicKey.size();
//             op.params[1].tmpref.buffer = sharedSecret.data();  op.params[1].tmpref.size = sharedSecret.size();
//             res = TEEC_InvokeCommand(&sess, CMD_COMPUTE_ECDH_SHARED_SECRET, &op, NULL);
//             sharedSecret.resize(op.params[1].tmpref.size);
//             return (res==TEEC_SUCCESS);
//         }, ok);
//         csv.log(_nodeID,"ECDHShared",latency,ok,sharedSecret.size());
//         if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
//         //------ [F] DERIVE_SUB_MASTER_KEY ------
//         std::vector<uint8_t> subMasterKey(SUB_MASTER_KEY_SIZE);
//         latency = measureLatency([&]{
//             TEEC_Operation op = {};
//             op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,TEEC_VALUE_INPUT,TEEC_MEMREF_TEMP_INPUT,0);
//             op.params[0].tmpref.buffer = subMasterKey.data(); op.params[0].tmpref.size = subMasterKey.size();
//             op.params[1].value.a       = _nodeID;
//             op.params[2].tmpref.buffer = msg.data(); op.params[2].tmpref.size = msg.size();
//             res = TEEC_InvokeCommand(&sess, CMD_DERIVE_SUB_MASTER_KEY, &op, NULL);
//             return (res==TEEC_SUCCESS);
//         }, ok);
//         csv.log(_nodeID,"DeriveSMK",latency,ok,subMasterKey.size());
//         if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
//         //------ [G] ENCRYPT_SUB_MASTER_KEY (AES‑GCM) ------
//         std::vector<uint8_t> encryptedPayload; encryptedPayload.reserve(12 + SUB_MASTER_KEY_SIZE + TAG_SIZE);
//         latency = measureLatency([&]{
//             // 12‑byte IV
//             std::vector<uint8_t> iv(12); std::random_device rd; for(auto &b:iv) b=static_cast<uint8_t>(rd());
//             std::vector<uint8_t> out(subMasterKey.size()+TAG_SIZE);
//             TEEC_Operation op = {};
//             op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_INOUT);
//             op.params[0].tmpref.buffer = sharedSecret.data(); op.params[0].tmpref.size = sharedSecret.size();
//             op.params[1].tmpref.buffer = iv.data();          op.params[1].tmpref.size = iv.size();
//             op.params[2].tmpref.buffer = subMasterKey.data(); op.params[2].tmpref.size = subMasterKey.size();
//             op.params[3].tmpref.buffer = out.data();         op.params[3].tmpref.size = out.size();
//             res = TEEC_InvokeCommand(&sess, CMD_ENCRYPT_SUB_MASTER_KEY, &op, NULL);
//             if(res!=TEEC_SUCCESS) return false;
//             encryptedPayload.insert(encryptedPayload.end(), iv.begin(), iv.end());
//             encryptedPayload.insert(encryptedPayload.end(), out.begin(), out.end());
//             return true;
//         }, ok);
//         csv.log(_nodeID,"EncryptSMK",latency,ok,encryptedPayload.size());
//         if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
//         // Cleanup & reply
//         TEEC_CloseSession(&sess);
//         TEEC_FinalizeContext(&ctx);
    
//         _reply(true, gwPub, encryptedPayload);

//         auto exec_end = Clock::now();
//         auto exec_latency_ms = std::chrono::duration_cast<millis>(exec_end - exec_start).count();

//         csv.log(_nodeID, "Total", exec_latency_ms, true);
//         csv.log(_nodeID,"-----",0,true); 


//     }
void set_cpu_affinity(const std::vector<int>& cores) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    for (int core_id : cores) {
        CPU_SET(core_id, &cpuset);  // 여러 코어 추가
    }

    pid_t pid = getpid(); // 현재 프로세스
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("sched_setaffinity");
    } else {
        std::cout << "[Info] Process pinned to CPU cores: ";
        for (int core_id : cores) std::cout << core_id << " ";
        std::cout << "\n";
    }
}


int main() {
//    set_cpu_affinity({1, 2, 3});  // 예: 코어 0에 고정

    std::cout << "[Server] Starting SecurityGateway with SOME/IP...\n";
    auto runtime = CommonAPI::Runtime::get();
    auto svc = std::make_shared<SecurityGatewayStubImpl>();
    runtime->registerService("local", "gateway_service", svc);
    std::cout << "[Server] Service registered.\n";
    for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}
