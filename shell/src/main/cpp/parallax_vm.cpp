#include "parallax_vm.h"

#include "parallax.h"
#include "parallax_crypto.h"
#include "parallax_risk.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Defined in parallax.cpp and patched by the packer with the same 16-byte build secret
// used to seal Parallax.vm. Keep this declaration at GLOBAL scope: declaring it inside the
// anonymous namespace would create a different internal-linkage symbol.
extern uint8_t PARALLAX_UNKNOWN_DATA[];

namespace {

enum : uint8_t {
    OP_NOP = 0, OP_CONST = 1, OP_MOVE = 2, OP_NEG = 3, OP_NOT = 4,
    OP_BYTE = 5, OP_CHAR = 6, OP_SHORT = 7,
    OP_ADD = 10, OP_SUB = 11, OP_MUL = 12, OP_DIV = 13, OP_REM = 14,
    OP_AND = 15, OP_OR = 16, OP_XOR = 17, OP_SHL = 18, OP_SHR = 19, OP_USHR = 20,
    OP_ADD_LIT = 21, OP_RSUB_LIT = 22, OP_MUL_LIT = 23, OP_DIV_LIT = 24,
    OP_REM_LIT = 25, OP_AND_LIT = 26, OP_OR_LIT = 27, OP_XOR_LIT = 28,
    OP_SHL_LIT = 29, OP_SHR_LIT = 30, OP_USHR_LIT = 31,
    OP_GOTO = 40, OP_IF_EQZ = 41, OP_IF_NEZ = 42, OP_IF_LTZ = 43,
    OP_IF_GEZ = 44, OP_IF_GTZ = 45, OP_IF_LEZ = 46, OP_IF_EQ = 47,
    OP_IF_NE = 48, OP_IF_LT = 49, OP_IF_GE = 50, OP_IF_GT = 51, OP_IF_LE = 52,
    OP_RETURN = 60, OP_RETURN_VOID = 61
};

constexpr size_t kEnvelopeHeader = 20; // magic + raw length + 12-byte nonce
constexpr size_t kMaxVmPayload = 8u * 1024u * 1024u;
constexpr uint32_t kMaxPrograms = 4096;
constexpr uint32_t kMaxOpsPerProgram = 65536;

struct VmOp {
    uint8_t opcode = 0, a = 0, b = 0, c = 0;
    int32_t imm = 0;
    uint32_t target = 0;
};

struct VmProgram {
    uint16_t registers = 0;
    uint8_t parameters = 0;
    bool returnsValue = false;
    std::vector<VmOp> ops;
};

std::unordered_map<uint32_t, VmProgram> g_programs;
std::mutex g_load_mutex;
bool g_load_attempted = false;
bool g_payload_present = false;

static uint16_t be16(const uint8_t *p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8u) | p[1]);
}

static uint32_t be32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24u)
           | (static_cast<uint32_t>(p[1]) << 16u)
           | (static_cast<uint32_t>(p[2]) << 8u)
           | static_cast<uint32_t>(p[3]);
}

static bool hasBytes(size_t cursor, size_t amount, size_t total) {
    return cursor <= total && amount <= total - cursor;
}

static bool regOk(const VmProgram &p, uint8_t r) {
    return r < p.registers;
}

static bool validate(const VmProgram &p, const VmOp &op) {
    switch (op.opcode) {
        case OP_NOP: case OP_GOTO: case OP_RETURN_VOID:
            break;
        case OP_CONST: case OP_RETURN:
        case OP_IF_EQZ: case OP_IF_NEZ: case OP_IF_LTZ:
        case OP_IF_GEZ: case OP_IF_GTZ: case OP_IF_LEZ:
            if (!regOk(p, op.a)) return false;
            break;
        case OP_MOVE: case OP_NEG: case OP_NOT: case OP_BYTE: case OP_CHAR: case OP_SHORT:
        case OP_ADD_LIT: case OP_RSUB_LIT: case OP_MUL_LIT: case OP_DIV_LIT:
        case OP_REM_LIT: case OP_AND_LIT: case OP_OR_LIT: case OP_XOR_LIT:
        case OP_SHL_LIT: case OP_SHR_LIT: case OP_USHR_LIT:
        case OP_IF_EQ: case OP_IF_NE: case OP_IF_LT: case OP_IF_GE: case OP_IF_GT: case OP_IF_LE:
            if (!regOk(p, op.a) || !regOk(p, op.b)) return false;
            break;
        case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV: case OP_REM:
        case OP_AND: case OP_OR: case OP_XOR: case OP_SHL: case OP_SHR: case OP_USHR:
            if (!regOk(p, op.a) || !regOk(p, op.b) || !regOk(p, op.c)) return false;
            break;
        default:
            return false;
    }
    if ((op.opcode == OP_GOTO || (op.opcode >= OP_IF_EQZ && op.opcode <= OP_IF_LE))
            && op.target >= p.ops.size()) return false;
    return true;
}

static bool parsePayload(const std::vector<uint8_t> &raw) {
    if (raw.size() < 8 || memcmp(raw.data(), "PVR1", 4) != 0) return false;
    size_t cursor = 4;
    uint32_t count = be32(raw.data() + cursor); cursor += 4;
    if (count == 0 || count > kMaxPrograms) return false;

    std::unordered_map<uint32_t, VmProgram> parsed;
    parsed.reserve(count);
    for (uint32_t n = 0; n < count; ++n) {
        if (!hasBytes(cursor, 12, raw.size())) return false;
        uint32_t id = be32(raw.data() + cursor); cursor += 4;
        VmProgram p;
        p.registers = be16(raw.data() + cursor); cursor += 2;
        p.parameters = raw[cursor++];
        uint8_t returnFlag = raw[cursor++];
        uint32_t opCount = be32(raw.data() + cursor); cursor += 4;
        if (id == 0 || p.registers == 0 || p.registers > 255 || p.parameters > 4
                || p.parameters > p.registers || returnFlag > 1 || opCount == 0
                || opCount > kMaxOpsPerProgram || parsed.find(id) != parsed.end()) return false;
        p.returnsValue = returnFlag != 0;
        if (!hasBytes(cursor, static_cast<size_t>(opCount) * 12u, raw.size())) return false;
        p.ops.reserve(opCount);
        for (uint32_t i = 0; i < opCount; ++i) {
            VmOp op;
            op.opcode = raw[cursor++]; op.a = raw[cursor++]; op.b = raw[cursor++]; op.c = raw[cursor++];
            op.imm = static_cast<int32_t>(be32(raw.data() + cursor)); cursor += 4;
            op.target = be32(raw.data() + cursor); cursor += 4;
            p.ops.push_back(op);
        }
        for (const VmOp &op : p.ops) if (!validate(p, op)) return false;
        parsed.emplace(id, std::move(p));
    }
    if (cursor != raw.size()) return false;
    g_programs.swap(parsed);
    return true;
}

static void tamper() {
    g_programs.clear();
    reportSecurityRisk(PARALLAX_SECURITY_PAYLOAD_TAMPER_BIT);
}

static bool arithmeticException(JNIEnv *env) {
    jclass cls = env->FindClass("java/lang/ArithmeticException");
    if (cls != nullptr) env->ThrowNew(cls, "/ by zero");
    return false;
}

static bool run(JNIEnv *env, uint32_t id, const jint *args, size_t argc,
                bool expectValue, jint *out) {
    loadHighValueVm(env);
    if (!g_payload_present) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return false;
    }
    auto found = g_programs.find(id);
    if (found == g_programs.end()) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return false;
    }
    const VmProgram &p = found->second;
    if (p.parameters != argc || p.returnsValue != expectValue) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return false;
    }

    std::vector<int32_t> r(p.registers, 0);
    size_t parameterBase = p.registers - p.parameters;
    for (size_t i = 0; i < argc; ++i) r[parameterBase + i] = static_cast<int32_t>(args[i]);

    size_t pc = 0;
    size_t steps = 0;
    const size_t limit = std::max<size_t>(4096u, p.ops.size() * 256u);
    while (pc < p.ops.size() && steps++ < limit) {
        const VmOp &op = p.ops[pc];
        switch (op.opcode) {
            case OP_NOP: ++pc; break;
            case OP_CONST: r[op.a] = op.imm; ++pc; break;
            case OP_MOVE: r[op.a] = r[op.b]; ++pc; break;
            case OP_NEG: r[op.a] = static_cast<int32_t>(0u - static_cast<uint32_t>(r[op.b])); ++pc; break;
            case OP_NOT: r[op.a] = ~r[op.b]; ++pc; break;
            case OP_BYTE: r[op.a] = static_cast<int8_t>(r[op.b]); ++pc; break;
            case OP_CHAR: r[op.a] = static_cast<uint16_t>(r[op.b]); ++pc; break;
            case OP_SHORT: r[op.a] = static_cast<int16_t>(r[op.b]); ++pc; break;
            case OP_ADD: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) + static_cast<uint32_t>(r[op.c])); ++pc; break;
            case OP_SUB: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) - static_cast<uint32_t>(r[op.c])); ++pc; break;
            case OP_MUL: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) * static_cast<uint32_t>(r[op.c])); ++pc; break;
            case OP_DIV: {
                int32_t rhs = r[op.c]; if (rhs == 0) return arithmeticException(env);
                int32_t lhs = r[op.b];
                r[op.a] = (lhs == std::numeric_limits<int32_t>::min() && rhs == -1)
                        ? std::numeric_limits<int32_t>::min() : lhs / rhs;
                ++pc; break;
            }
            case OP_REM: {
                int32_t rhs = r[op.c]; if (rhs == 0) return arithmeticException(env);
                int32_t lhs = r[op.b];
                r[op.a] = (lhs == std::numeric_limits<int32_t>::min() && rhs == -1) ? 0 : lhs % rhs;
                ++pc; break;
            }
            case OP_AND: r[op.a] = r[op.b] & r[op.c]; ++pc; break;
            case OP_OR: r[op.a] = r[op.b] | r[op.c]; ++pc; break;
            case OP_XOR: r[op.a] = r[op.b] ^ r[op.c]; ++pc; break;
            case OP_SHL: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) << (r[op.c] & 31)); ++pc; break;
            case OP_SHR: r[op.a] = r[op.b] >> (r[op.c] & 31); ++pc; break;
            case OP_USHR: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) >> (r[op.c] & 31)); ++pc; break;
            case OP_ADD_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) + static_cast<uint32_t>(op.imm)); ++pc; break;
            case OP_RSUB_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(op.imm) - static_cast<uint32_t>(r[op.b])); ++pc; break;
            case OP_MUL_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) * static_cast<uint32_t>(op.imm)); ++pc; break;
            case OP_DIV_LIT: {
                if (op.imm == 0) return arithmeticException(env);
                int32_t lhs = r[op.b];
                r[op.a] = (lhs == std::numeric_limits<int32_t>::min() && op.imm == -1)
                        ? std::numeric_limits<int32_t>::min() : lhs / op.imm;
                ++pc; break;
            }
            case OP_REM_LIT: {
                if (op.imm == 0) return arithmeticException(env);
                int32_t lhs = r[op.b];
                r[op.a] = (lhs == std::numeric_limits<int32_t>::min() && op.imm == -1) ? 0 : lhs % op.imm;
                ++pc; break;
            }
            case OP_AND_LIT: r[op.a] = r[op.b] & op.imm; ++pc; break;
            case OP_OR_LIT: r[op.a] = r[op.b] | op.imm; ++pc; break;
            case OP_XOR_LIT: r[op.a] = r[op.b] ^ op.imm; ++pc; break;
            case OP_SHL_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) << (op.imm & 31)); ++pc; break;
            case OP_SHR_LIT: r[op.a] = r[op.b] >> (op.imm & 31); ++pc; break;
            case OP_USHR_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) >> (op.imm & 31)); ++pc; break;
            case OP_GOTO: pc = op.target; break;
            case OP_IF_EQZ: pc = r[op.a] == 0 ? op.target : pc + 1; break;
            case OP_IF_NEZ: pc = r[op.a] != 0 ? op.target : pc + 1; break;
            case OP_IF_LTZ: pc = r[op.a] < 0 ? op.target : pc + 1; break;
            case OP_IF_GEZ: pc = r[op.a] >= 0 ? op.target : pc + 1; break;
            case OP_IF_GTZ: pc = r[op.a] > 0 ? op.target : pc + 1; break;
            case OP_IF_LEZ: pc = r[op.a] <= 0 ? op.target : pc + 1; break;
            case OP_IF_EQ: pc = r[op.a] == r[op.b] ? op.target : pc + 1; break;
            case OP_IF_NE: pc = r[op.a] != r[op.b] ? op.target : pc + 1; break;
            case OP_IF_LT: pc = r[op.a] < r[op.b] ? op.target : pc + 1; break;
            case OP_IF_GE: pc = r[op.a] >= r[op.b] ? op.target : pc + 1; break;
            case OP_IF_GT: pc = r[op.a] > r[op.b] ? op.target : pc + 1; break;
            case OP_IF_LE: pc = r[op.a] <= r[op.b] ? op.target : pc + 1; break;
            case OP_RETURN:
                if (!expectValue) return false;
                if (out != nullptr) *out = static_cast<jint>(r[op.a]);
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

static jint callInt(JNIEnv *env, jint id, const jint *args, size_t argc) {
    jint result = 0;
    return run(env, static_cast<uint32_t>(id), args, argc, true, &result) ? result : 0;
}

static void callVoid(JNIEnv *env, jint id, const jint *args, size_t argc) {
    (void) run(env, static_cast<uint32_t>(id), args, argc, false, nullptr);
}

} // namespace

void loadHighValueVm(JNIEnv *env) {
    std::lock_guard<std::mutex> guard(g_load_mutex);
    if (g_load_attempted) return;
    g_load_attempted = true;

    void *apk = nullptr;
    size_t apkSize = 0;
    load_package(env, &apk, &apkSize);
    if (apk == nullptr || apkSize == 0) return;

    auto entry = read_zip_file_entry(apk, apkSize, AY_OBFUSCATE("assets/Parallax.vm"));
    if (!entry.has_value()) {
        unload_package(apk, apkSize);
        return; // Feature is optional for APKs protected without --high-value-methods.
    }
    g_payload_present = true;
    auto [entryData, entrySize] = entry.value();
    std::unique_ptr<uint8_t[]> entryOwner(entryData);

    bool ok = false;
    do {
        if (entrySize <= kEnvelopeHeader + 16 || entrySize > kMaxVmPayload
                || memcmp(entryData, "PVM1", 4) != 0) break;
        uint32_t rawSize = be32(entryData + 4);
        if (rawSize == 0 || rawSize > kMaxVmPayload) break;

        std::string label = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/encryption/v1/"))
                + AY_OBFUSCATE(PARALLAX_BUILD_KEY);
        auto key = hmac_sha256(PARALLAX_UNKNOWN_DATA, 16,
                reinterpret_cast<const uint8_t *>(label.data()), label.size());
        if (key.size() != 32) break;
        std::string aadText = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/payload/v1/"))
                + std::to_string(rawSize);
        auto raw = aes_gcm_decrypt(key.data(), 256, entryData + 8, 12,
                reinterpret_cast<const uint8_t *>(aadText.data()), aadText.size(),
                entryData + kEnvelopeHeader, entrySize - kEnvelopeHeader);
        secure_zero(key.data(), key.size());
        if (raw.size() != rawSize) {
            secure_zero(raw.data(), raw.size());
            break;
        }
        ok = parsePayload(raw);
        secure_zero(raw.data(), raw.size());
    } while (false);

    unload_package(apk, apkSize);
    if (!ok) tamper();
}

jint highValueVmI0(JNIEnv *env, jclass, jint id) { return callInt(env, id, nullptr, 0); }
jint highValueVmI1(JNIEnv *env, jclass, jint id, jint a0) { const jint a[]{a0}; return callInt(env,id,a,1); }
jint highValueVmI2(JNIEnv *env, jclass, jint id, jint a0, jint a1) { const jint a[]{a0,a1}; return callInt(env,id,a,2); }
jint highValueVmI3(JNIEnv *env, jclass, jint id, jint a0, jint a1, jint a2) { const jint a[]{a0,a1,a2}; return callInt(env,id,a,3); }
jint highValueVmI4(JNIEnv *env, jclass, jint id, jint a0, jint a1, jint a2, jint a3) { const jint a[]{a0,a1,a2,a3}; return callInt(env,id,a,4); }
void highValueVmV0(JNIEnv *env, jclass, jint id) { callVoid(env,id,nullptr,0); }
void highValueVmV1(JNIEnv *env, jclass, jint id, jint a0) { const jint a[]{a0}; callVoid(env,id,a,1); }
void highValueVmV2(JNIEnv *env, jclass, jint id, jint a0, jint a1) { const jint a[]{a0,a1}; callVoid(env,id,a,2); }
void highValueVmV3(JNIEnv *env, jclass, jint id, jint a0, jint a1, jint a2) { const jint a[]{a0,a1,a2}; callVoid(env,id,a,3); }
void highValueVmV4(JNIEnv *env, jclass, jint id, jint a0, jint a1, jint a2, jint a3) { const jint a[]{a0,a1,a2,a3}; callVoid(env,id,a,4); }
