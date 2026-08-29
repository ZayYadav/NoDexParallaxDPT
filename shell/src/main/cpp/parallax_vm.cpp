#include "parallax_vm.h"

#include "parallax.h"
#include "parallax_crypto.h"
#include "parallax_risk.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr uint8_t OP_NOP = 0;
constexpr uint8_t OP_CONST = 1;
constexpr uint8_t OP_MOVE = 2;
constexpr uint8_t OP_NEG = 3;
constexpr uint8_t OP_NOT = 4;
constexpr uint8_t OP_BYTE = 5;
constexpr uint8_t OP_CHAR = 6;
constexpr uint8_t OP_SHORT = 7;
constexpr uint8_t OP_ADD = 10;
constexpr uint8_t OP_SUB = 11;
constexpr uint8_t OP_MUL = 12;
constexpr uint8_t OP_DIV = 13;
constexpr uint8_t OP_REM = 14;
constexpr uint8_t OP_AND = 15;
constexpr uint8_t OP_OR = 16;
constexpr uint8_t OP_XOR = 17;
constexpr uint8_t OP_SHL = 18;
constexpr uint8_t OP_SHR = 19;
constexpr uint8_t OP_USHR = 20;
constexpr uint8_t OP_ADD_LIT = 21;
constexpr uint8_t OP_RSUB_LIT = 22;
constexpr uint8_t OP_MUL_LIT = 23;
constexpr uint8_t OP_DIV_LIT = 24;
constexpr uint8_t OP_REM_LIT = 25;
constexpr uint8_t OP_AND_LIT = 26;
constexpr uint8_t OP_OR_LIT = 27;
constexpr uint8_t OP_XOR_LIT = 28;
constexpr uint8_t OP_SHL_LIT = 29;
constexpr uint8_t OP_SHR_LIT = 30;
constexpr uint8_t OP_USHR_LIT = 31;
constexpr uint8_t OP_GOTO = 40;
constexpr uint8_t OP_IF_EQZ = 41;
constexpr uint8_t OP_IF_NEZ = 42;
constexpr uint8_t OP_IF_LTZ = 43;
constexpr uint8_t OP_IF_GEZ = 44;
constexpr uint8_t OP_IF_GTZ = 45;
constexpr uint8_t OP_IF_LEZ = 46;
constexpr uint8_t OP_IF_EQ = 47;
constexpr uint8_t OP_IF_NE = 48;
constexpr uint8_t OP_IF_LT = 49;
constexpr uint8_t OP_IF_GE = 50;
constexpr uint8_t OP_IF_GT = 51;
constexpr uint8_t OP_IF_LE = 52;
constexpr uint8_t OP_RETURN = 60;
constexpr uint8_t OP_RETURN_VOID = 61;

constexpr size_t kEnvelopeHeader = 4 + 4 + 12;
constexpr size_t kMaxVmPayload = 8u * 1024u * 1024u;
constexpr uint32_t kMaxPrograms = 4096;
constexpr uint32_t kMaxOpsPerProgram = 65536;

struct VmOp {
    uint8_t opcode = 0;
    uint8_t a = 0;
    uint8_t b = 0;
    uint8_t c = 0;
    int32_t imm = 0;
    uint32_t target = 0;
};

struct VmProgram {
    uint16_t registerCount = 0;
    uint8_t parameterCount = 0;
    bool returnsValue = false;
    std::vector<VmOp> ops;
};

std::unordered_map<uint32_t, VmProgram> g_programs;
std::mutex g_vm_mutex;
bool g_vm_load_attempted = false;
bool g_vm_payload_present = false;

extern uint8_t PARALLAX_UNKNOWN_DATA[];

static uint16_t readBe16(const uint8_t *p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8u) |
                                 static_cast<uint16_t>(p[1]));
}

static uint32_t readBe32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24u) |
           (static_cast<uint32_t>(p[1]) << 16u) |
           (static_cast<uint32_t>(p[2]) << 8u) |
           static_cast<uint32_t>(p[3]);
}

static int32_t readBeI32(const uint8_t *p) {
    return static_cast<int32_t>(readBe32(p));
}

static bool need(size_t cursor, size_t amount, size_t total) {
    return amount <= total && cursor <= total - amount;
}

static bool validRegister(const VmProgram &program, uint8_t reg) {
    return reg < program.registerCount;
}

static bool validateOp(const VmProgram &program, const VmOp &op) {
    switch (op.opcode) {
        case OP_NOP:
        case OP_GOTO:
        case OP_RETURN_VOID:
            break;
        case OP_CONST:
        case OP_RETURN:
        case OP_IF_EQZ:
        case OP_IF_NEZ:
        case OP_IF_LTZ:
        case OP_IF_GEZ:
        case OP_IF_GTZ:
        case OP_IF_LEZ:
            if (!validRegister(program, op.a)) return false;
            break;
        case OP_MOVE:
        case OP_NEG:
        case OP_NOT:
        case OP_BYTE:
        case OP_CHAR:
        case OP_SHORT:
        case OP_ADD_LIT:
        case OP_RSUB_LIT:
        case OP_MUL_LIT:
        case OP_DIV_LIT:
        case OP_REM_LIT:
        case OP_AND_LIT:
        case OP_OR_LIT:
        case OP_XOR_LIT:
        case OP_SHL_LIT:
        case OP_SHR_LIT:
        case OP_USHR_LIT:
        case OP_IF_EQ:
        case OP_IF_NE:
        case OP_IF_LT:
        case OP_IF_GE:
        case OP_IF_GT:
        case OP_IF_LE:
            if (!validRegister(program, op.a) || !validRegister(program, op.b)) return false;
            break;
        case OP_ADD:
        case OP_SUB:
        case OP_MUL:
        case OP_DIV:
        case OP_REM:
        case OP_AND:
        case OP_OR:
        case OP_XOR:
        case OP_SHL:
        case OP_SHR:
        case OP_USHR:
            if (!validRegister(program, op.a) || !validRegister(program, op.b)
                    || !validRegister(program, op.c)) return false;
            break;
        default:
            return false;
    }

    if (op.opcode == OP_GOTO ||
        (op.opcode >= OP_IF_EQZ && op.opcode <= OP_IF_LE)) {
        if (op.target >= program.ops.size()) return false;
    }
    return true;
}

static bool parseRawPayload(const std::vector<uint8_t> &raw) {
    if (raw.size() < 8 || memcmp(raw.data(), "PVR1", 4) != 0) return false;
    size_t cursor = 4;
    uint32_t count = readBe32(raw.data() + cursor);
    cursor += 4;
    if (count == 0 || count > kMaxPrograms) return false;

    std::unordered_map<uint32_t, VmProgram> parsed;
    parsed.reserve(count);
    for (uint32_t n = 0; n < count; ++n) {
        if (!need(cursor, 12, raw.size())) return false;
        uint32_t methodId = readBe32(raw.data() + cursor); cursor += 4;
        VmProgram program;
        program.registerCount = readBe16(raw.data() + cursor); cursor += 2;
        program.parameterCount = raw[cursor++];
        uint8_t returns = raw[cursor++];
        uint32_t opCount = readBe32(raw.data() + cursor); cursor += 4;

        if (methodId == 0 || program.registerCount == 0 || program.registerCount > 255
                || program.parameterCount > 4 || program.parameterCount > program.registerCount
                || returns > 1 || opCount == 0 || opCount > kMaxOpsPerProgram
                || parsed.find(methodId) != parsed.end()) {
            return false;
        }
        program.returnsValue = returns != 0;
        if (!need(cursor, static_cast<size_t>(opCount) * 12u, raw.size())) return false;
        program.ops.reserve(opCount);
        for (uint32_t i = 0; i < opCount; ++i) {
            VmOp op;
            op.opcode = raw[cursor++];
            op.a = raw[cursor++];
            op.b = raw[cursor++];
            op.c = raw[cursor++];
            op.imm = readBeI32(raw.data() + cursor); cursor += 4;
            op.target = readBe32(raw.data() + cursor); cursor += 4;
            program.ops.push_back(op);
        }
        for (const VmOp &op : program.ops) {
            if (!validateOp(program, op)) return false;
        }
        parsed.emplace(methodId, std::move(program));
    }
    if (cursor != raw.size()) return false;
    g_programs.swap(parsed);
    return true;
}

static void markPayloadFailure() {
    g_programs.clear();
    reportSecurityRisk(PARALLAX_SECURITY_PAYLOAD_TAMPER_BIT);
}

static bool ensureLoaded(JNIEnv *env) {
    if (g_vm_load_attempted) return !g_vm_payload_present || !g_programs.empty();
    loadHighValueVm(env);
    return !g_vm_payload_present || !g_programs.empty();
}

static bool throwArithmetic(JNIEnv *env) {
    jclass cls = env->FindClass("java/lang/ArithmeticException");
    if (cls != nullptr) env->ThrowNew(cls, "/ by zero");
    return false;
}

static bool execute(JNIEnv *env, uint32_t methodId, const jint *args, size_t argc,
                    bool expectValue, jint *result) {
    if (!ensureLoaded(env) || !g_vm_payload_present) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return false;
    }
    auto it = g_programs.find(methodId);
    if (it == g_programs.end()) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return false;
    }
    const VmProgram &program = it->second;
    if (program.parameterCount != argc || program.returnsValue != expectValue) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return false;
    }

    std::vector<int32_t> regs(program.registerCount, 0);
    const size_t paramBase = program.registerCount - program.parameterCount;
    for (size_t i = 0; i < argc; ++i) regs[paramBase + i] = static_cast<int32_t>(args[i]);

    size_t pc = 0;
    size_t steps = 0;
    const size_t stepLimit = std::max<size_t>(4096, program.ops.size() * 256u);
    while (pc < program.ops.size() && steps++ < stepLimit) {
        const VmOp &op = program.ops[pc];
        auto next = [&pc]() { ++pc; };
        switch (op.opcode) {
            case OP_NOP: next(); break;
            case OP_CONST: regs[op.a] = op.imm; next(); break;
            case OP_MOVE: regs[op.a] = regs[op.b]; next(); break;
            case OP_NEG: regs[op.a] = static_cast<int32_t>(0u - static_cast<uint32_t>(regs[op.b])); next(); break;
            case OP_NOT: regs[op.a] = ~regs[op.b]; next(); break;
            case OP_BYTE: regs[op.a] = static_cast<int8_t>(regs[op.b]); next(); break;
            case OP_CHAR: regs[op.a] = static_cast<uint16_t>(regs[op.b]); next(); break;
            case OP_SHORT: regs[op.a] = static_cast<int16_t>(regs[op.b]); next(); break;
            case OP_ADD: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) + static_cast<uint32_t>(regs[op.c])); next(); break;
            case OP_SUB: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) - static_cast<uint32_t>(regs[op.c])); next(); break;
            case OP_MUL: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) * static_cast<uint32_t>(regs[op.c])); next(); break;
            case OP_DIV: {
                int32_t rhs = regs[op.c];
                if (rhs == 0) return throwArithmetic(env);
                int32_t lhs = regs[op.b];
                regs[op.a] = (lhs == std::numeric_limits<int32_t>::min() && rhs == -1)
                        ? std::numeric_limits<int32_t>::min() : lhs / rhs;
                next(); break;
            }
            case OP_REM: {
                int32_t rhs = regs[op.c];
                if (rhs == 0) return throwArithmetic(env);
                int32_t lhs = regs[op.b];
                regs[op.a] = (lhs == std::numeric_limits<int32_t>::min() && rhs == -1) ? 0 : lhs % rhs;
                next(); break;
            }
            case OP_AND: regs[op.a] = regs[op.b] & regs[op.c]; next(); break;
            case OP_OR: regs[op.a] = regs[op.b] | regs[op.c]; next(); break;
            case OP_XOR: regs[op.a] = regs[op.b] ^ regs[op.c]; next(); break;
            case OP_SHL: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) << (regs[op.c] & 31)); next(); break;
            case OP_SHR: regs[op.a] = regs[op.b] >> (regs[op.c] & 31); next(); break;
            case OP_USHR: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) >> (regs[op.c] & 31)); next(); break;
            case OP_ADD_LIT: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) + static_cast<uint32_t>(op.imm)); next(); break;
            case OP_RSUB_LIT: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(op.imm) - static_cast<uint32_t>(regs[op.b])); next(); break;
            case OP_MUL_LIT: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) * static_cast<uint32_t>(op.imm)); next(); break;
            case OP_DIV_LIT: {
                if (op.imm == 0) return throwArithmetic(env);
                int32_t lhs = regs[op.b];
                regs[op.a] = (lhs == std::numeric_limits<int32_t>::min() && op.imm == -1)
                        ? std::numeric_limits<int32_t>::min() : lhs / op.imm;
                next(); break;
            }
            case OP_REM_LIT: {
                if (op.imm == 0) return throwArithmetic(env);
                int32_t lhs = regs[op.b];
                regs[op.a] = (lhs == std::numeric_limits<int32_t>::min() && op.imm == -1) ? 0 : lhs % op.imm;
                next(); break;
            }
            case OP_AND_LIT: regs[op.a] = regs[op.b] & op.imm; next(); break;
            case OP_OR_LIT: regs[op.a] = regs[op.b] | op.imm; next(); break;
            case OP_XOR_LIT: regs[op.a] = regs[op.b] ^ op.imm; next(); break;
            case OP_SHL_LIT: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) << (op.imm & 31)); next(); break;
            case OP_SHR_LIT: regs[op.a] = regs[op.b] >> (op.imm & 31); next(); break;
            case OP_USHR_LIT: regs[op.a] = static_cast<int32_t>(static_cast<uint32_t>(regs[op.b]) >> (op.imm & 31)); next(); break;
            case OP_GOTO: pc = op.target; break;
            case OP_IF_EQZ: pc = regs[op.a] == 0 ? op.target : pc + 1; break;
            case OP_IF_NEZ: pc = regs[op.a] != 0 ? op.target : pc + 1; break;
            case OP_IF_LTZ: pc = regs[op.a] < 0 ? op.target : pc + 1; break;
            case OP_IF_GEZ: pc = regs[op.a] >= 0 ? op.target : pc + 1; break;
            case OP_IF_GTZ: pc = regs[op.a] > 0 ? op.target : pc + 1; break;
            case OP_IF_LEZ: pc = regs[op.a] <= 0 ? op.target : pc + 1; break;
            case OP_IF_EQ: pc = regs[op.a] == regs[op.b] ? op.target : pc + 1; break;
            case OP_IF_NE: pc = regs[op.a] != regs[op.b] ? op.target : pc + 1; break;
            case OP_IF_LT: pc = regs[op.a] < regs[op.b] ? op.target : pc + 1; break;
            case OP_IF_GE: pc = regs[op.a] >= regs[op.b] ? op.target : pc + 1; break;
            case OP_IF_GT: pc = regs[op.a] > regs[op.b] ? op.target : pc + 1; break;
            case OP_IF_LE: pc = regs[op.a] <= regs[op.b] ? op.target : pc + 1; break;
            case OP_RETURN:
                if (!expectValue) return false;
                if (result != nullptr) *result = static_cast<jint>(regs[op.a]);
                return true;
            case OP_RETURN_VOID:
                return !expectValue;
            default:
                reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
                return false;
        }
    }
    reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
    return false;
}

static jint invokeInt(JNIEnv *env, jint methodId, const jint *args, size_t argc) {
    jint result = 0;
    if (!execute(env, static_cast<uint32_t>(methodId), args, argc, true, &result)) return 0;
    return result;
}

static void invokeVoid(JNIEnv *env, jint methodId, const jint *args, size_t argc) {
    (void) execute(env, static_cast<uint32_t>(methodId), args, argc, false, nullptr);
}

} // namespace

void loadHighValueVm(JNIEnv *env) {
    std::lock_guard<std::mutex> lock(g_vm_mutex);
    if (g_vm_load_attempted) return;
    g_vm_load_attempted = true;

    void *packageAddr = nullptr;
    size_t packageSize = 0;
    load_package(env, &packageAddr, &packageSize);
    if (packageAddr == nullptr || packageSize == 0) return;

    auto entry = read_zip_file_entry(packageAddr, packageSize, AY_OBFUSCATE("assets/Parallax.vm"));
    if (!entry.has_value()) {
        unload_package(packageAddr, packageSize);
        return; // Optional tier not enabled for this APK.
    }
    g_vm_payload_present = true;
    auto [data, size] = entry.value();
    std::unique_ptr<uint8_t[]> guard(data);

    bool ok = false;
    do {
        if (size <= kEnvelopeHeader + 16 || size > kMaxVmPayload
                || memcmp(data, "PVM1", 4) != 0) break;
        uint32_t rawLength = readBe32(data + 4);
        if (rawLength == 0 || rawLength > kMaxVmPayload) break;

        const uint8_t *nonce = data + 8;
        const uint8_t *ciphertext = data + kEnvelopeHeader;
        size_t ciphertextSize = size - kEnvelopeHeader;

        std::string keyLabel = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/encryption/v1/"))
                + AY_OBFUSCATE(PARALLAX_BUILD_KEY);
        auto payloadKey = hmac_sha256(PARALLAX_UNKNOWN_DATA, 16,
                reinterpret_cast<const uint8_t *>(keyLabel.data()), keyLabel.size());
        if (payloadKey.size() != 32) break;
        std::string aadString = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/payload/v1/"))
                + std::to_string(rawLength);
        auto raw = aes_gcm_decrypt(payloadKey.data(), 256, nonce, 12,
                reinterpret_cast<const uint8_t *>(aadString.data()), aadString.size(),
                ciphertext, ciphertextSize);
        secure_zero(payloadKey.data(), payloadKey.size());
        if (raw.size() != rawLength) {
            secure_zero(raw.data(), raw.size());
            break;
        }
        ok = parseRawPayload(raw);
        secure_zero(raw.data(), raw.size());
    } while (false);

    unload_package(packageAddr, packageSize);
    if (!ok) markPayloadFailure();
}

jint highValueVmI0(JNIEnv *env, jclass, jint methodId) {
    return invokeInt(env, methodId, nullptr, 0);
}
jint highValueVmI1(JNIEnv *env, jclass, jint methodId, jint a0) {
    const jint args[] = {a0}; return invokeInt(env, methodId, args, 1);
}
jint highValueVmI2(JNIEnv *env, jclass, jint methodId, jint a0, jint a1) {
    const jint args[] = {a0, a1}; return invokeInt(env, methodId, args, 2);
}
jint highValueVmI3(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2) {
    const jint args[] = {a0, a1, a2}; return invokeInt(env, methodId, args, 3);
}
jint highValueVmI4(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2, jint a3) {
    const jint args[] = {a0, a1, a2, a3}; return invokeInt(env, methodId, args, 4);
}

void highValueVmV0(JNIEnv *env, jclass, jint methodId) {
    invokeVoid(env, methodId, nullptr, 0);
}
void highValueVmV1(JNIEnv *env, jclass, jint methodId, jint a0) {
    const jint args[] = {a0}; invokeVoid(env, methodId, args, 1);
}
void highValueVmV2(JNIEnv *env, jclass, jint methodId, jint a0, jint a1) {
    const jint args[] = {a0, a1}; invokeVoid(env, methodId, args, 2);
}
void highValueVmV3(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2) {
    const jint args[] = {a0, a1, a2}; invokeVoid(env, methodId, args, 3);
}
void highValueVmV4(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2, jint a3) {
    const jint args[] = {a0, a1, a2, a3}; invokeVoid(env, methodId, args, 4);
}
