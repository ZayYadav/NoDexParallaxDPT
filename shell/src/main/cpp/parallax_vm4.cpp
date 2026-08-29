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
#include <unordered_set>
#include <vector>

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

constexpr size_t kEnvelopeHeader = 20; // PVM4 + raw length + 12-byte nonce
constexpr size_t kMaxVmPayload = 16u * 1024u * 1024u;
constexpr uint32_t kMaxPrograms = 4096;
constexpr uint32_t kMaxCellsPerProgram = 196608;
constexpr size_t kCellSerializedSize = 28;

struct EncodedCell {
    uint32_t stateEncoded = 0;
    uint8_t opEncoded = 0, aEncoded = 0, bEncoded = 0, cEncoded = 0;
    uint32_t immEncoded = 0;
    uint32_t nextEncoded = 0;
    uint32_t branchEncoded = 0;
    uint32_t guard = 0;
    uint32_t noise = 0;
};

struct DecodedCell {
    uint32_t state = 0;
    uint8_t opcode = 0, a = 0, b = 0, c = 0;
    int32_t imm = 0;
    uint32_t next = 0;
    uint32_t branch = 0;
};

struct VmProgram {
    uint32_t id = 0;
    uint16_t registers = 0;
    uint8_t parameters = 0;
    bool returnsValue = false;
    uint8_t parameterSlots[4] = {0xff, 0xff, 0xff, 0xff};
    uint32_t entryState = 0;
    uint32_t mask = 0;
    uint8_t opXor = 0, opBias = 0, regXor = 0;
    std::vector<EncodedCell> cells;
    std::unordered_map<uint32_t, size_t> stateToIndex;
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

static uint32_t rotl32(uint32_t value, unsigned amount) {
    amount &= 31u;
    return amount == 0 ? value : (value << amount) | (value >> (32u - amount));
}

static uint32_t rotr32(uint32_t value, unsigned amount) {
    amount &= 31u;
    return amount == 0 ? value : (value >> amount) | (value << (32u - amount));
}

static uint32_t expectedGuard(const VmProgram &p, const EncodedCell &cell) {
    uint32_t packed = (static_cast<uint32_t>(cell.opEncoded) << 24u)
            | (static_cast<uint32_t>(cell.aEncoded) << 16u)
            | (static_cast<uint32_t>(cell.bEncoded) << 8u)
            | static_cast<uint32_t>(cell.cEncoded);
    uint32_t value = 0x6D2B79F5u ^ p.id;
    value = rotl32(value ^ cell.stateEncoded, 5u) + 0x9E3779B9u;
    value = rotl32(value ^ packed, 7u) + cell.immEncoded;
    value = rotl32(value ^ cell.nextEncoded, 11u) + cell.branchEncoded;
    return rotl32(value ^ cell.noise, 13u) + p.mask;
}

static bool decodeCell(const VmProgram &p, const EncodedCell &cell, DecodedCell *out) {
    if (out == nullptr || expectedGuard(p, cell) != cell.guard) return false;
    out->state = cell.stateEncoded ^ p.mask;
    uint8_t biased = static_cast<uint8_t>(cell.opEncoded ^ p.opXor);
    out->opcode = static_cast<uint8_t>(biased - p.opBias);
    out->a = static_cast<uint8_t>(cell.aEncoded ^ p.regXor);
    out->b = static_cast<uint8_t>(cell.bEncoded ^ p.regXor);
    out->c = static_cast<uint8_t>(cell.cEncoded ^ p.regXor);
    unsigned rotate = 5u + (p.mask & 15u);
    out->imm = static_cast<int32_t>(rotr32(cell.immEncoded, rotate) ^ p.mask);
    out->next = cell.nextEncoded ^ rotl32(p.mask, 5u);
    out->branch = cell.branchEncoded ^ rotl32(p.mask, 13u);
    return true;
}

static bool isConditional(uint8_t opcode) {
    return opcode >= OP_IF_EQZ && opcode <= OP_IF_LE;
}

static bool isReturn(uint8_t opcode) {
    return opcode == OP_RETURN || opcode == OP_RETURN_VOID;
}

static bool regOk(const VmProgram &p, uint8_t reg) {
    return reg < p.registers;
}

static bool validateOperands(const VmProgram &p, const DecodedCell &op) {
    switch (op.opcode) {
        case OP_NOP: case OP_GOTO: case OP_RETURN_VOID:
            return true;
        case OP_CONST: case OP_RETURN:
        case OP_IF_EQZ: case OP_IF_NEZ: case OP_IF_LTZ:
        case OP_IF_GEZ: case OP_IF_GTZ: case OP_IF_LEZ:
            return regOk(p, op.a);
        case OP_MOVE: case OP_NEG: case OP_NOT: case OP_BYTE: case OP_CHAR: case OP_SHORT:
        case OP_ADD_LIT: case OP_RSUB_LIT: case OP_MUL_LIT: case OP_DIV_LIT:
        case OP_REM_LIT: case OP_AND_LIT: case OP_OR_LIT: case OP_XOR_LIT:
        case OP_SHL_LIT: case OP_SHR_LIT: case OP_USHR_LIT:
        case OP_IF_EQ: case OP_IF_NE: case OP_IF_LT: case OP_IF_GE: case OP_IF_GT: case OP_IF_LE:
            return regOk(p, op.a) && regOk(p, op.b);
        case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV: case OP_REM:
        case OP_AND: case OP_OR: case OP_XOR: case OP_SHL: case OP_SHR: case OP_USHR:
            return regOk(p, op.a) && regOk(p, op.b) && regOk(p, op.c);
        default:
            return false;
    }
}

static bool parsePayload(const std::vector<uint8_t> &raw) {
    if (raw.size() < 8 || memcmp(raw.data(), "PVR4", 4) != 0) return false;
    size_t cursor = 4;
    uint32_t programCount = be32(raw.data() + cursor); cursor += 4;
    if (programCount == 0 || programCount > kMaxPrograms) return false;

    std::unordered_map<uint32_t, VmProgram> parsed;
    parsed.reserve(programCount);

    for (uint32_t n = 0; n < programCount; ++n) {
        if (!hasBytes(cursor, 28, raw.size())) return false;
        VmProgram p;
        p.id = be32(raw.data() + cursor); cursor += 4;
        p.registers = be16(raw.data() + cursor); cursor += 2;
        p.parameters = raw[cursor++];
        uint8_t returnFlag = raw[cursor++];
        for (size_t i = 0; i < 4; ++i) p.parameterSlots[i] = raw[cursor++];
        p.entryState = be32(raw.data() + cursor); cursor += 4;
        uint32_t cellCount = be32(raw.data() + cursor); cursor += 4;
        p.mask = be32(raw.data() + cursor); cursor += 4;
        p.opXor = raw[cursor++];
        p.opBias = raw[cursor++];
        p.regXor = raw[cursor++];
        uint8_t layerCount = raw[cursor++];

        if (p.id == 0 || p.registers == 0 || p.registers > 255
                || p.parameters > 4 || p.parameters > p.registers
                || returnFlag > 1 || p.entryState == 0 || p.mask == 0
                || layerCount != 4 || cellCount == 0 || cellCount > kMaxCellsPerProgram
                || parsed.find(p.id) != parsed.end()) return false;
        p.returnsValue = returnFlag != 0;

        std::unordered_set<uint8_t> slots;
        for (size_t i = 0; i < p.parameters; ++i) {
            if (p.parameterSlots[i] >= p.registers || !slots.insert(p.parameterSlots[i]).second) {
                return false;
            }
        }

        if (!hasBytes(cursor, static_cast<size_t>(cellCount) * kCellSerializedSize, raw.size())) {
            return false;
        }
        p.cells.reserve(cellCount);
        p.stateToIndex.reserve(cellCount * 2u);
        for (uint32_t i = 0; i < cellCount; ++i) {
            EncodedCell cell;
            cell.stateEncoded = be32(raw.data() + cursor); cursor += 4;
            cell.opEncoded = raw[cursor++];
            cell.aEncoded = raw[cursor++];
            cell.bEncoded = raw[cursor++];
            cell.cEncoded = raw[cursor++];
            cell.immEncoded = be32(raw.data() + cursor); cursor += 4;
            cell.nextEncoded = be32(raw.data() + cursor); cursor += 4;
            cell.branchEncoded = be32(raw.data() + cursor); cursor += 4;
            cell.guard = be32(raw.data() + cursor); cursor += 4;
            cell.noise = be32(raw.data() + cursor); cursor += 4;

            DecodedCell decoded;
            if (!decodeCell(p, cell, &decoded) || decoded.state == 0
                    || !validateOperands(p, decoded)
                    || p.stateToIndex.find(decoded.state) != p.stateToIndex.end()) return false;
            p.stateToIndex.emplace(decoded.state, p.cells.size());
            p.cells.push_back(cell);
        }

        if (p.stateToIndex.find(p.entryState) == p.stateToIndex.end()) return false;
        for (const EncodedCell &cell : p.cells) {
            DecodedCell op;
            if (!decodeCell(p, cell, &op)) return false;
            if (op.opcode == OP_GOTO) {
                if (op.next != 0 || op.branch == 0
                        || p.stateToIndex.find(op.branch) == p.stateToIndex.end()) return false;
            } else if (isConditional(op.opcode)) {
                if (op.next == 0 || op.branch == 0
                        || p.stateToIndex.find(op.next) == p.stateToIndex.end()
                        || p.stateToIndex.find(op.branch) == p.stateToIndex.end()) return false;
            } else if (isReturn(op.opcode)) {
                if (op.next != 0 || op.branch != 0) return false;
            } else {
                if (op.next == 0 || op.branch != 0
                        || p.stateToIndex.find(op.next) == p.stateToIndex.end()) return false;
            }
        }
        parsed.emplace(p.id, std::move(p));
    }

    if (cursor != raw.size()) return false;
    g_programs.swap(parsed);
    return true;
}

static void tamper(jint bit = PARALLAX_SECURITY_PAYLOAD_TAMPER_BIT) {
    g_programs.clear();
    reportSecurityRisk(bit);
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
    for (size_t i = 0; i < argc; ++i) {
        r[p.parameterSlots[i]] = static_cast<int32_t>(args[i]);
    }

    uint32_t state = p.entryState;
    size_t steps = 0;
    const size_t limit = std::max<size_t>(4096u, p.cells.size() * 256u);
    while (state != 0 && steps++ < limit) {
        auto stateIt = p.stateToIndex.find(state);
        if (stateIt == p.stateToIndex.end()) {
            tamper(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
            return false;
        }
        const EncodedCell &encoded = p.cells[stateIt->second];
        DecodedCell op;
        if (!decodeCell(p, encoded, &op) || op.state != state || !validateOperands(p, op)) {
            tamper(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
            return false;
        }

        switch (op.opcode) {
            case OP_NOP: state = op.next; break;
            case OP_CONST: r[op.a] = op.imm; state = op.next; break;
            case OP_MOVE: r[op.a] = r[op.b]; state = op.next; break;
            case OP_NEG: r[op.a] = static_cast<int32_t>(0u - static_cast<uint32_t>(r[op.b])); state = op.next; break;
            case OP_NOT: r[op.a] = ~r[op.b]; state = op.next; break;
            case OP_BYTE: r[op.a] = static_cast<int8_t>(r[op.b]); state = op.next; break;
            case OP_CHAR: r[op.a] = static_cast<uint16_t>(r[op.b]); state = op.next; break;
            case OP_SHORT: r[op.a] = static_cast<int16_t>(r[op.b]); state = op.next; break;
            case OP_ADD: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) + static_cast<uint32_t>(r[op.c])); state = op.next; break;
            case OP_SUB: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) - static_cast<uint32_t>(r[op.c])); state = op.next; break;
            case OP_MUL: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) * static_cast<uint32_t>(r[op.c])); state = op.next; break;
            case OP_DIV: {
                int32_t rhs = r[op.c]; if (rhs == 0) return arithmeticException(env);
                int32_t lhs = r[op.b];
                r[op.a] = (lhs == std::numeric_limits<int32_t>::min() && rhs == -1)
                        ? std::numeric_limits<int32_t>::min() : lhs / rhs;
                state = op.next; break;
            }
            case OP_REM: {
                int32_t rhs = r[op.c]; if (rhs == 0) return arithmeticException(env);
                int32_t lhs = r[op.b];
                r[op.a] = (lhs == std::numeric_limits<int32_t>::min() && rhs == -1) ? 0 : lhs % rhs;
                state = op.next; break;
            }
            case OP_AND: r[op.a] = r[op.b] & r[op.c]; state = op.next; break;
            case OP_OR: r[op.a] = r[op.b] | r[op.c]; state = op.next; break;
            case OP_XOR: r[op.a] = r[op.b] ^ r[op.c]; state = op.next; break;
            case OP_SHL: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) << (r[op.c] & 31)); state = op.next; break;
            case OP_SHR: r[op.a] = r[op.b] >> (r[op.c] & 31); state = op.next; break;
            case OP_USHR: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) >> (r[op.c] & 31)); state = op.next; break;
            case OP_ADD_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) + static_cast<uint32_t>(op.imm)); state = op.next; break;
            case OP_RSUB_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(op.imm) - static_cast<uint32_t>(r[op.b])); state = op.next; break;
            case OP_MUL_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) * static_cast<uint32_t>(op.imm)); state = op.next; break;
            case OP_DIV_LIT: {
                if (op.imm == 0) return arithmeticException(env);
                int32_t lhs = r[op.b];
                r[op.a] = (lhs == std::numeric_limits<int32_t>::min() && op.imm == -1)
                        ? std::numeric_limits<int32_t>::min() : lhs / op.imm;
                state = op.next; break;
            }
            case OP_REM_LIT: {
                if (op.imm == 0) return arithmeticException(env);
                int32_t lhs = r[op.b];
                r[op.a] = (lhs == std::numeric_limits<int32_t>::min() && op.imm == -1) ? 0 : lhs % op.imm;
                state = op.next; break;
            }
            case OP_AND_LIT: r[op.a] = r[op.b] & op.imm; state = op.next; break;
            case OP_OR_LIT: r[op.a] = r[op.b] | op.imm; state = op.next; break;
            case OP_XOR_LIT: r[op.a] = r[op.b] ^ op.imm; state = op.next; break;
            case OP_SHL_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) << (op.imm & 31)); state = op.next; break;
            case OP_SHR_LIT: r[op.a] = r[op.b] >> (op.imm & 31); state = op.next; break;
            case OP_USHR_LIT: r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(r[op.b]) >> (op.imm & 31)); state = op.next; break;
            case OP_GOTO: state = op.branch; break;
            case OP_IF_EQZ: state = r[op.a] == 0 ? op.branch : op.next; break;
            case OP_IF_NEZ: state = r[op.a] != 0 ? op.branch : op.next; break;
            case OP_IF_LTZ: state = r[op.a] < 0 ? op.branch : op.next; break;
            case OP_IF_GEZ: state = r[op.a] >= 0 ? op.branch : op.next; break;
            case OP_IF_GTZ: state = r[op.a] > 0 ? op.branch : op.next; break;
            case OP_IF_LEZ: state = r[op.a] <= 0 ? op.branch : op.next; break;
            case OP_IF_EQ: state = r[op.a] == r[op.b] ? op.branch : op.next; break;
            case OP_IF_NE: state = r[op.a] != r[op.b] ? op.branch : op.next; break;
            case OP_IF_LT: state = r[op.a] < r[op.b] ? op.branch : op.next; break;
            case OP_IF_GE: state = r[op.a] >= r[op.b] ? op.branch : op.next; break;
            case OP_IF_GT: state = r[op.a] > r[op.b] ? op.branch : op.next; break;
            case OP_IF_LE: state = r[op.a] <= r[op.b] ? op.branch : op.next; break;
            case OP_RETURN:
                if (!expectValue) return false;
                if (out != nullptr) *out = static_cast<jint>(r[op.a]);
                return true;
            case OP_RETURN_VOID:
                return !expectValue;
            default:
                tamper(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
                return false;
        }
    }
    tamper(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
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
        return;
    }
    g_payload_present = true;
    auto [entryData, entrySize] = entry.value();
    std::unique_ptr<uint8_t[]> entryOwner(entryData);

    bool ok = false;
    do {
        if (entrySize <= kEnvelopeHeader + 16 || entrySize > kMaxVmPayload
                || memcmp(entryData, "PVM4", 4) != 0) break;
        uint32_t rawSize = be32(entryData + 4);
        if (rawSize == 0 || rawSize > kMaxVmPayload) break;

        const char *buildKey = AY_OBFUSCATE(PARALLAX_BUILD_KEY);
        std::string label = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/encryption/v4/"))
                + buildKey;
        auto key = hmac_sha256(PARALLAX_UNKNOWN_DATA, 16,
                reinterpret_cast<const uint8_t *>(label.data()), label.size());
        if (key.size() != 32) break;
        std::string aadText = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/payload/v4/"))
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
