#include "Node1.hpp"
#include "signature_ta.h" // TA UUID, 명령어 ID 및 상수 정의 포함 가정
#include <tee_client_api.h>
#include <sched.h>   // sched_setaffinity
#include <unistd.h>  // getpid()

// -----------------------------------------------------------------------------
// 설정 값
// -----------------------------------------------------------------------------
constexpr int  ITERATIONS_FOR_MAIN_LOOP = 100; // 반복 횟수
constexpr bool ENABLE_SMK_REQUEST      = true; // SMK 교환 지연 측정 실행 여부
constexpr bool ENABLE_ECU_DERIVATION   = false; // ECU 키 파생 지연 측정 실행 여부

constexpr bool SINGLE_KEY_DERIVATION_MODE = false; 
constexpr uint32_t TARGET_KEY_SECURITY_LEVEL   = SEC_LEVEL_AES_GCM_256_KEY; 
constexpr size_t   TARGET_KEY_EXPECTED_LENGTH  = 32; // 바이트 단위
const std::string  TARGET_KEY_NAME_FOR_CSV     = "AES256"; //"CMAC_AES128"; 

constexpr size_t AES_GCM_IV_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;

// 1) 측정 헬퍼 함수
template<typename F>
uint64_t measureLatency(F&& func) {
    auto t0 = std::chrono::high_resolution_clock::now();
    func();
    auto t1 = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
}

// 2) 유틸 함수
uint64_t generateNonce() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    return gen();
}
uint64_t getTimestamp() {
    return static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now()));
}
std::vector<uint8_t> serializeMessage(uint32_t id, uint64_t nonce, uint64_t ts) {
    std::vector<uint8_t> v;
    v.reserve(sizeof(id) + sizeof(nonce) + sizeof(ts));
    for (int i = 0; i < 4; ++i) v.push_back((id >> 8*i) & 0xFF);
    for (int i = 0; i < 8; ++i) v.push_back((nonce >> 8*i) & 0xFF);
    for (int i = 0; i < 8; ++i) v.push_back((ts >> 8*i) & 0xFF);
    return v;
}

// 3) SecurityGatewayClient – SOME/IP 프록시 (업로드된 파일 내용과 동일)
SecurityGatewayClient::SecurityGatewayClient()  { std::cout << "[Node1.cpp Client] SecurityGatewayClient created.\n"; }
SecurityGatewayClient::~SecurityGatewayClient() { std::cout << "[Node1.cpp Client] SecurityGatewayClient destroyed.\n"; }

bool SecurityGatewayClient::connectToService(const std::string& instanceName) {
    runtime = CommonAPI::Runtime::get();
    if (!runtime) { std::cerr << "[Node1.cpp Client] CommonAPI Runtime get failed\n"; return false; }
    myProxy = runtime->buildProxy<SecurityGatewayProxy>("local", instanceName);
    if (!myProxy) { std::cerr << "[Node1.cpp Client] SecurityGatewayProxy creation failed\n"; return false; }
    std::cout << "[Node1.cpp Client] Waiting for gateway service '" << instanceName << "'...\n";
    while (!myProxy->isAvailable())
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "[Node1.cpp Client] Service '" << instanceName << "' available!\n";
    return true;
}

bool SecurityGatewayClient::requestSessionKey(
        uint32_t nodeID, uint64_t nonce, uint64_t ts,
        const std::vector<uint8_t>& _nodePubKey, // ECDSA 공개키 전달
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& ecdhPub,
        bool& success,
        std::vector<uint8_t>& gwPub,
        std::vector<uint8_t>& encPayload) {
    if (!myProxy) { std::cerr << "[Node1.cpp Client] Proxy not ready for requestSessionKey\n"; return false; }

    CommonAPI::CallStatus cs;
    std::cout << "[Node1.cpp Client] Sending requestSessionKey to Gateway: NodeID=" << nodeID
              << ", NodePubKeySz=" << _nodePubKey.size() // ECDSA 공개키 크기
              << ", SigSz=" << signature.size()
              << ", NodeEcdhPubSz=" << ecdhPub.size()
              << std::endl;

    myProxy->requestSessionKey(nodeID, nonce, ts,
                               _nodePubKey, signature, ecdhPub,
                               cs, success, gwPub, encPayload);

    if (cs == CommonAPI::CallStatus::SUCCESS) {
        std::cout << "[Node1.cpp Client] requestSessionKey SOME/IP call returned => GatewaySuccess=" << (success?"Y":"N")
                  << ",  GatewayEcdhPub size=" << gwPub.size()
                  << ",  EncryptedSMKPayload size="   << encPayload.size() << '\n';
        return true;
    }
    std::cerr << "[Node1.cpp Client] requestSessionKey SOME/IP call failed. CallStatus: " << static_cast<int>(cs) << "\n";
    success = false;
    return false;
}

// 4) TEEC helper 함수들 – Node TA와 통신 (업로드된 파일 내용 기반으로 ECDSA 용으로 유지)
// ECDSA 키 생성
bool createECDSAKey(TEEC_Session& s) { // 함수명 ECDSA로 유지
    TEEC_Operation op{}; op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,0,0,0);
    // CMD_GENKEY는 이제 TA에서 ECDSA 키를 생성
    TEEC_Result r = TEEC_InvokeCommand(&s, CMD_GENKEY, &op, NULL);
    if (r) { std::cerr << "[TA] CMD_GENKEY (ECDSA) fail:0x"<<std::hex<<r<<"\n"; return false; }
    std::cout << "[TA] ECDSA Key generated via CMD_GENKEY.\n";
    return true;
}

// ECDSA 공개키 읽기
bool getECDSAPublicKey(TEEC_Session& s, std::vector<uint8_t>& out) { // 함수명 ECDSA로 유지
    TEEC_Operation op{};
    // ECDSA P-256 공개키 (0x04 + X + Y)는 65 바이트
    std::vector<uint8_t> buf(ECDSA_PUBKEY_UNCOMPRESSED_SIZE); 
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,0,0,0);
    op.params[0].tmpref.buffer = buf.data(); 
    op.params[0].tmpref.size = buf.size();

    // CMD_GET_PUBKEY는 이제 TA에서 ECDSA 공개키를 반환
    TEEC_Result r = TEEC_InvokeCommand(&s, CMD_GET_PUBKEY, &op, NULL);
    if (r) { std::cerr << "[TA] CMD_GET_PUBKEY (ECDSA) fail:0x"<<std::hex<<r<<"\n"; return false; }
    out.assign(buf.begin(), buf.begin()+op.params[0].tmpref.size);
    std::cout << "[TA] ECDSA Public Key retrieved, size: " << out.size() << "\n";
    return true;
}

// ECDSA 서명 생성
bool signDataECDSA(TEEC_Session& s, const std::vector<uint8_t>& msg, // 함수명 ECDSA로 명시
              std::vector<uint8_t>& sig) {
    TEEC_Operation op{};
    // ECDSA_SIGNATURE_MAX_SIZE 는 signature_ta.h 에 72로 정의
    std::vector<uint8_t> buf(ECDSA_SIGNATURE_MAX_SIZE); 
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,0,0);
    op.params[0].tmpref.buffer = const_cast<uint8_t*>(msg.data());
    op.params[0].tmpref.size   = msg.size();
    op.params[1].tmpref.buffer = buf.data();
    op.params[1].tmpref.size   = buf.size();

    TEEC_Result r = TEEC_InvokeCommand(&s, CMD_SIGN, &op, NULL);
    if (r) { std::cerr << "[Node1.cpp TA] CMD_SIGN (ECDSA) failed: 0x"<<std::hex<<r<<std::dec<<"\n"; return false; }
    sig.assign(buf.begin(), buf.begin()+op.params[1].tmpref.size);
    std::cout << "[Node1.cpp TA] Data signed (ECDSA), signature size: " << sig.size() << "\n";
    return true;
}

// Node 자신의 ECDH 공개키 생성 (SECP256R1)
bool getMyECDHPublicKey(TEEC_Session& s, std::vector<uint8_t>& pub) {
    TEEC_Operation op{};
    std::vector<uint8_t> buf(100); // ECDH 공개키(SECP256R1, 65 bytes)에 충분한 크기
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,0,0,0);
    op.params[0].tmpref.buffer = buf.data(); op.params[0].tmpref.size = buf.size();
    TEEC_Result r = TEEC_InvokeCommand(&s, CMD_GENERATE_ECDH, &op, NULL);
    if (r) { std::cerr << "[TA] CMD_GENERATE_ECDH fail:0x"<<std::hex<<r<<"\n"; return false; }
    pub.assign(buf.begin(), buf.begin()+op.params[0].tmpref.size);
    return true;
}

// Gateway의 ECDH 공개키를 사용하여 공유 비밀 계산 (SECP256R1)
bool computeMyECDHSharedSecret(TEEC_Session& s,
                               const std::vector<uint8_t>& peerGwEcdhPubKey,
                               std::vector<uint8_t>& secret) {
    TEEC_Operation op{};
    std::vector<uint8_t> buf(32); // SECP256R1 공유 비밀은 32 bytes
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,0,0);
    op.params[0].tmpref.buffer = const_cast<uint8_t*>(peerGwEcdhPubKey.data());
    op.params[0].tmpref.size   = peerGwEcdhPubKey.size();
    op.params[1].tmpref.buffer = buf.data();
    op.params[1].tmpref.size   = buf.size();
    TEEC_Result r = TEEC_InvokeCommand(&s, CMD_COMPUTE_ECDH_SHARED_SECRET, &op, NULL);
    if (r) { std::cerr << "[Node1.cpp TA] CMD_COMPUTE_ECDH_SHARED_SECRET (Node) failed: 0x"<<std::hex<<r<<std::dec<<"\n"; return false; }
    secret.assign(buf.begin(), buf.begin()+op.params[1].tmpref.size);
    std::cout << "[Node1.cpp TA] My (Node) ECDH Shared Secret computed, size: " << secret.size() << "\n";
    return true;
}

// Gateway로부터 받은 SMK 복호화 및 TA 내 저장 요청
bool decryptSMK(TEEC_Session& sess,
                 const std::vector<uint8_t>& sessionKey,
                 const std::vector<uint8_t>& iv,
                 const std::vector<uint8_t>& cipherAndTag,
                 std::vector<uint8_t>& outPlain) {
    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,    // 세션키
        TEEC_MEMREF_TEMP_INPUT,    // IV
        TEEC_MEMREF_TEMP_INOUT,    // 암호문+태그 -> 평문
        TEEC_NONE);
    op.params[0].tmpref.buffer = const_cast<uint8_t*>(sessionKey.data());
    op.params[0].tmpref.size   = sessionKey.size();
    op.params[1].tmpref.buffer = const_cast<uint8_t*>(iv.data());
    op.params[1].tmpref.size   = iv.size();
    // in/out 버퍼 복사
    std::vector<uint8_t> buf = cipherAndTag;
    op.params[2].tmpref.buffer = buf.data();
    op.params[2].tmpref.size   = buf.size();

    TEEC_Result r = TEEC_InvokeCommand(&sess,
                                       CMD_DECRYPT_SUB_MASTER_KEY,
                                       &op, nullptr);
    if (r != TEEC_SUCCESS) return false;
    outPlain.assign(buf.begin(), buf.begin() + op.params[2].tmpref.size);
    std::cout << "decryptSMK success " << "\n";

    return true;
}

bool storeSMK(TEEC_Session& sess,
               const std::vector<uint8_t>& plain) {
    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, 0,0,0);
    op.params[0].tmpref.buffer = const_cast<uint8_t*>(plain.data());
    op.params[0].tmpref.size   = plain.size();
    TEEC_Result r = TEEC_InvokeCommand(&sess,
                                       CMD_STORE_SMK,
                                       &op, nullptr);

    std::cout << "storeSMK success " << "\n";                                   
    return (r == TEEC_SUCCESS);
}

// ECU 키 파생을 위한 TA 호출 함수
bool deriveECUKeyFromTA(TEEC_Session& s,
                        uint32_t ecu_id,
                        uint32_t security_level,
                        size_t expected_key_len, 
                        std::vector<uint8_t>& derived_key_out) {
    TEEC_Operation op{};
    std::vector<uint8_t> key_buf(expected_key_len); 

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].value.a = ecu_id;
    op.params[1].value.b = security_level;
    op.params[2].tmpref.buffer = key_buf.data();
    op.params[2].tmpref.size   = key_buf.size();

    std::cout << "[Node1.cpp CA] Requesting TA to derive ECU key: ECU_ID=" << ecu_id 
              << ", SecLevel=" << security_level << ", BufferSizeGivenToTA=" << key_buf.size() << std::endl;

    TEEC_Result r = TEEC_InvokeCommand(&s, CMD_DERIVE_ECU_KEY, &op, NULL);
    if (r) {
        std::cerr << "[Node1.cpp TA] CMD_DERIVE_ECU_KEY failed: 0x" << std::hex << r << std::dec << std::endl;
        if (r == TEEC_ERROR_SHORT_BUFFER) {
            std::cerr << "[Node1.cpp TA] CMD_DERIVE_ECU_KEY reported TEE_ERROR_SHORT_BUFFER. TA Required size: " 
                      << op.params[2].tmpref.size << std::endl;
        }
        return false;
    }

    if (op.params[2].tmpref.size != expected_key_len) {
        std::cerr << "[Node1.cpp CA] Derived ECU key size mismatch from TA. Expected: " << expected_key_len
                  << ", Got from TA: " << op.params[2].tmpref.size << std::endl;
    }
    derived_key_out.assign(key_buf.begin(), key_buf.begin() + op.params[2].tmpref.size);
    std::cout << "[Node1.cpp CA] ECU Key derived by TA. Actual size returned by TA: " << derived_key_out.size() << std::endl;
    return true;
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


// main 함수
int main() {
    set_cpu_affinity(10);  // 예: 코어 0에 고정

    using Clock = std::chrono::high_resolution_clock;
    using micros = std::chrono::microseconds;

    // 1) CSV 파일 준비
    std::string csv_filename = ENABLE_ECU_DERIVATION && !SINGLE_KEY_DERIVATION_MODE
        ? "latency_results_all_operations_2.csv"
        : "latency_results_single_key_" + TARGET_KEY_NAME_FOR_CSV + ".csv";
    std::ofstream csv_file(csv_filename);
    if (!csv_file.is_open()) {
        std::cerr << "Failed to open CSV file: " << csv_filename << "\n";
        return 1;
    }
    csv_file << "iteration,operation_type,ecu_id,sec_level,key_len_bytes,latency_us,status\n";

//    auto exec_start = Clock::now();

    // 2) TEE 컨텍스트 및 세션 초기화
    TEEC_Context teec_ctx{};
    TEEC_Session teec_sess{};
    TEEC_UUID ta_uuid = TA_SIGN_UUID;
    TEEC_Result teec_res = TEEC_InitializeContext(NULL, &teec_ctx);
    if (teec_res != TEEC_SUCCESS) {
        std::cerr << "TEEC_InitializeContext failed: 0x" << std::hex << teec_res << std::dec << std::endl;
        csv_file.close();
        return 1;
    }

    teec_res = TEEC_OpenSession(&teec_ctx, &teec_sess, &ta_uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (teec_res != TEEC_SUCCESS) {
        std::cerr << "TEEC_OpenSession failed: 0x" << std::hex << teec_res << std::dec << std::endl;
        TEEC_FinalizeContext(&teec_ctx);
        csv_file.close();
        return 1;
    }

    // 3) SOME/IP 프록시 연결 (SMK 요청이 활성화된 경우)
    SecurityGatewayClient gwClient;
    if (ENABLE_SMK_REQUEST && !gwClient.connectToService("gateway_service")) {
        std::cerr << "Failed to connect to gateway_service\n";
        TEEC_CloseSession(&teec_sess);
        TEEC_FinalizeContext(&teec_ctx);
        return 1;
    }

    // 4) 메인 측정 루프
    for (int iter = 0; iter < ITERATIONS_FOR_MAIN_LOOP; ++iter) {
        std::cout << "--- Iteration " << iter << " ---\n";
        auto total_start = Clock::now();

        if(ENABLE_SMK_REQUEST){
            bool ok = false;
            uint64_t lat = 0;

            // 4.1 ECDSA 키 생성
            lat = measureLatency([&]{ ok = createECDSAKey(teec_sess); });
            csv_file << iter << ",SMK_createECDSAKey,-,-,-," << lat << "," << (ok ? "success" : "fail") << "\n";
            if (!ok) continue;

            // 4.2 ECDSA 공개키 읽기
            std::vector<uint8_t> pubKey;
            lat = measureLatency([&]{ ok = getECDSAPublicKey(teec_sess, pubKey); });
            csv_file << iter << ",SMK_getECDSAPublicKey,-,-," << pubKey.size() << "," << lat << "," << (ok ? "success" : "fail") << "\n";
            if (!ok) continue;

            // 4.3 서명
            uint64_t nonce = generateNonce();
            uint64_t ts    = getTimestamp();
            auto msg       = serializeMessage(55, nonce, ts);
            std::vector<uint8_t> signature;
            lat = measureLatency([&]{ ok = signDataECDSA(teec_sess, msg, signature); });
            csv_file << iter << ",SMK_signDataECDSA,-,-," << signature.size() << "," << lat << "," << (ok ? "success" : "fail") << "\n";
            if (!ok) continue;

            // 4.4 ECDH 공개키 생성
            std::vector<uint8_t> myEcdhPub;
            lat = measureLatency([&]{ ok = getMyECDHPublicKey(teec_sess, myEcdhPub); });
            csv_file << iter << ",SMK_getMyECDHPublicKey,-,-," << myEcdhPub.size() << "," << lat << "," << (ok ? "success" : "fail") << "\n";
            if (!ok) continue;

            // 4.5 Gateway 세션키 요청
            std::vector<uint8_t> gwEcdhPub, encSmkPayload;
            bool gwLogicOk = false;
            lat = measureLatency([&]{
                ok = gwClient.requestSessionKey(
                    55, nonce, ts,
                    pubKey, signature, myEcdhPub,
                    gwLogicOk, gwEcdhPub, encSmkPayload
                ) && gwLogicOk;
            });
            csv_file << iter << ",SMK_requestSessionKeyToGateway,-,-," << encSmkPayload.size() << "," << lat << "," << (ok ? "success" : "fail") << "\n";
            if (!ok) continue;

            // 4.6 ECDH 공유 비밀 계산
            std::vector<uint8_t> sessionKey;
            lat = measureLatency([&]{ ok = computeMyECDHSharedSecret(teec_sess, gwEcdhPub, sessionKey); });
            csv_file << iter << ",SMK_computeMyECDHSharedSecret,-,-," << sessionKey.size() << "," << lat << "," << (ok ? "success" : "fail") << "\n";
            if (!ok) continue;

            // 4.7a SMK 복호화만
            std::vector<uint8_t> iv(encSmkPayload.begin(), encSmkPayload.begin() + AES_GCM_IV_SIZE);
            std::vector<uint8_t> cipherAndTag(encSmkPayload.begin() + AES_GCM_IV_SIZE, encSmkPayload.end());
            std::vector<uint8_t> plainSMK;
            lat = measureLatency([&]{ ok = decryptSMK(teec_sess, sessionKey, iv, cipherAndTag, plainSMK); });
            csv_file << iter << ",SMK_decrypt_only,-,-," << plainSMK.size() << "," << lat << "," << (ok ? "success" : "fail") << "\n";
            if (!ok) continue;

            // 4.7b SMK 저장만
            lat = measureLatency([&]{ ok = storeSMK(teec_sess, plainSMK); });
            csv_file << iter << ",SMK_store_only,-,-," << plainSMK.size() << "," << lat << "," << (ok ? "success" : "fail") << "\n";
            if (!ok) continue;
        }
        

        // 4.8 ECU 키 파생 (옵션)
        if (ENABLE_ECU_DERIVATION) {
            uint32_t base_id = 1000 + iter * 100;
            if (!SINGLE_KEY_DERIVATION_MODE) {
                struct Test { const char* name; uint32_t lvl; size_t len; uint32_t off; };
                constexpr Test tests[] = {
                    {"CMAC_AES128",       SEC_LEVEL_CMAC_AES128_KEY,       16, 1},
                    {"HMAC_SHA256",       SEC_LEVEL_HMAC_SHA256_KEY,       32, 2},
                    {"AES_ENC_128",       SEC_LEVEL_AES_ENC_128_KEY,       16, 3},
                    {"AES_ENC_256",       SEC_LEVEL_AES_ENC_256_KEY,       32, 4},
                    {"AES_GCM_128",       SEC_LEVEL_AES_GCM_128_KEY,       16, 5},
                    {"AES_GCM_256",       SEC_LEVEL_AES_GCM_256_KEY,       32, 6},
                };
                for (auto &t : tests) {
                    std::vector<uint8_t> derived;
                    bool ok2 = false;
                    uint64_t lat2 = measureLatency([&]{
                        ok2 = deriveECUKeyFromTA(teec_sess,
                                                base_id + t.off,
                                                t.lvl,
                                                t.len,
                                                derived);
                    });
                    csv_file
                        << iter
                        << ",deriveECUKey_" << t.name
                        << "," << (base_id + t.off)
                        << "," << t.lvl
                        << "," << derived.size()
                        << "," << lat2
                        << "," << (ok2 ? "success" : "fail")
                        << "\n";
                }
            } else {
                uint32_t ecu_id = 1000 + iter * 100 + TARGET_KEY_SECURITY_LEVEL;
                std::vector<uint8_t> derived;
                bool ok2 = false;
                uint64_t lat2 = measureLatency([&]{
                    ok2 = deriveECUKeyFromTA(teec_sess,
                                            ecu_id,
                                            TARGET_KEY_SECURITY_LEVEL,
                                            TARGET_KEY_EXPECTED_LENGTH,
                                            derived);
                });
                csv_file
                    << iter
                    << ",deriveECUKey_" << TARGET_KEY_NAME_FOR_CSV
                    << "," << ecu_id
                    << "," << TARGET_KEY_SECURITY_LEVEL
                    << "," << derived.size()
                    << "," << lat2
                    << "," << (ok2 ? "success" : "fail")
                    << "\n";
            }
        }
        else {
            // 파생 비활성화 시 건너뜀
            csv_file
            << iter
            << ",ECU_Key_Derivation_Flow,-,-,-,0,skipped_by_config"
            << "\n";
        }
        std::cout << "--- End of Main Iteration " << iter << " ---\n";

        auto total_end = Clock::now();
        auto total_duration_us = std::chrono::duration_cast<micros>(total_end - total_start).count();

        csv_file << "TOTAL,TotalExecutionTime,-,-,-,"  << total_duration_us << ",success\n";
    }


    csv_file.close();
    TEEC_CloseSession(&teec_sess);
    TEEC_FinalizeContext(&teec_ctx);

    std::cout << "\nLatency measurements saved to latency_ecdsa_and_ecu_keys.csv\n";
    return 0;
    }
