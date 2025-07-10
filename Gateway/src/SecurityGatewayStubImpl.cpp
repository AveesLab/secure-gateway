#include "SecurityGatewayStubImpl.hpp"
#include "gateway_ta.h"      // CMD_* and TA_GATEWAY_UUID definitions
#include <tee_client_api.h>
#include <sched.h>   // sched_setaffinity
#include <unistd.h>  // getpid()

// ---------- 공통 타입 ----------
using Clock   = std::chrono::high_resolution_clock;
using micros  = std::chrono::microseconds;
using millis  = std::chrono::milliseconds;

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
            file << "timestamp,nodeID,step,latency_ms,status,size_bytes\n";
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
        auto exec_start = Clock::now();

        // CSV 로거 준비 (프로세스 내에서 단일 객체)
        static CsvLogger csv("./gateway_latency.csv");
        csv.writeHeader();
    
        constexpr size_t SUB_MASTER_KEY_SIZE = 32;
        constexpr size_t TAG_SIZE            = 16;
    
        std::cout << "[StubImpl] requestSessionKey called\n"
                  << " - nodeID: "   << _nodeID
                  << ", nonce: "    << _nonce
                  << ", timestamp: "<< _timestamp << "\n";
    
        if (!(_nodeID == 42 || _nodeID == 52 || _nodeID == 62 || _nodeID == 72)) {
            csv.log(_nodeID, "reject_nodeID", 0, false);
            _reply(false, {}, {});
            return;
        }
    
        //----------- TEE Context & Session -----------
        TEEC_Context ctx; TEEC_Session sess; TEEC_Result res;
        bool ok; uint64_t latency;
    
        latency = measureLatency([&]{ return (TEEC_InitializeContext(NULL, &ctx) == TEEC_SUCCESS); }, ok);
        if(!ok){ csv.log(_nodeID,"InitCtx",latency,false); _reply(false,{},{ }); return; }
        csv.log(_nodeID,"InitCtx",latency,true);
    
        latency = measureLatency([&]{
            TEEC_UUID uuid = TA_GATEWAY_UUID;
            res = TEEC_OpenSession(&ctx,&sess,&uuid,TEEC_LOGIN_PUBLIC,NULL,NULL,NULL);
            return (res==TEEC_SUCCESS);
        }, ok);
        if(!ok){ csv.log(_nodeID,"OpenSess",latency,false); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
        csv.log(_nodeID,"OpenSess",latency,true);
    
        //------ [A] STORE_NODE_PUBKEY ------
        latency = measureLatency([&]{
            TEEC_Operation op = {};
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,TEEC_MEMREF_TEMP_INPUT,0,0);
            op.params[0].value.a      = _nodeID;
            op.params[1].tmpref.buffer= _publicKey.data();
            op.params[1].tmpref.size  = _publicKey.size();
            res = TEEC_InvokeCommand(&sess, CMD_STORE_NODE_PUBKEY, &op, NULL);
            return (res==TEEC_SUCCESS || res==TEE_ERROR_ITEM_ALREADY_EXISTS);
        }, ok);
        csv.log(_nodeID,"StoreNodePub",latency,ok,_publicKey.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
        //------ [C] VERIFY_SIGNATURE ------
        std::vector<uint8_t> msg = serializeMessage(_nodeID,_nonce,_timestamp);
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
        csv.log(_nodeID,"VerifySig",latency,ok,_signature.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
        //------ [D] GENERATE_ECDH ------
        std::vector<uint8_t> gwPub(100);
        latency = measureLatency([&]{
            TEEC_Operation op = {};
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,0,0,0);
            op.params[0].tmpref.buffer=gwPub.data(); op.params[0].tmpref.size=gwPub.size();
            res = TEEC_InvokeCommand(&sess, CMD_GENERATE_ECDH, &op, NULL);
            gwPub.resize(op.params[0].tmpref.size);
            return (res==TEEC_SUCCESS);
        }, ok);
        csv.log(_nodeID,"GenECDH",latency,ok,gwPub.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
        //------ [E] COMPUTE_SHARED_SECRET ------
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
        csv.log(_nodeID,"ECDHShared",latency,ok,sharedSecret.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
        //------ [F] DERIVE_SUB_MASTER_KEY ------
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
        csv.log(_nodeID,"DeriveSMK",latency,ok,subMasterKey.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
        //------ [G] ENCRYPT_SUB_MASTER_KEY (AES‑GCM) ------
        std::vector<uint8_t> encryptedPayload; encryptedPayload.reserve(12 + SUB_MASTER_KEY_SIZE + TAG_SIZE);
        latency = measureLatency([&]{
            // 12‑byte IV
            std::vector<uint8_t> iv(12); std::random_device rd; for(auto &b:iv) b=static_cast<uint8_t>(rd());
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
        csv.log(_nodeID,"EncryptSMK",latency,ok,encryptedPayload.size());
        if(!ok){ TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx); _reply(false,{},{ }); return; }
    
        // Cleanup & reply
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
    
        _reply(true, gwPub, encryptedPayload);

        auto exec_end = Clock::now();
        auto exec_latency_ms = std::chrono::duration_cast<millis>(exec_end - exec_start).count();

        csv.log(_nodeID, "Total", exec_latency_ms, true);
        csv.log(_nodeID,"-----",0,true); 


    }
void set_cpu_affinity(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pid_t pid = getpid(); // 현재 프로세스
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("sched_setaffinity");
    } else {
        std::cout << "[Info] Process pinned to CPU core " << core_id << "\n";
    }
}

int main() {
    //set_cpu_affinity(11);  // 예: 코어 0에 고정

    std::cout << "[Server] Starting SecurityGateway with SOME/IP...\n";
    auto runtime = CommonAPI::Runtime::get();
    auto svc = std::make_shared<SecurityGatewayStubImpl>();
    runtime->registerService("local", "gateway_service", svc);
    std::cout << "[Server] Service registered.\n";
    for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}
