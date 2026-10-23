#include "parallax_vm.h"

#include "parallax.h"
#include "parallax_crypto.h"
#include "parallax_risk.h"

#include <algorithm>
#include <array>
#include <cmath>
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
    OP_RETURN = 60, OP_RETURN_VOID = 61,
    OP_CONST_WIDE = 62, OP_MOVE_WIDE = 63,
    OP_ADD_LONG = 64, OP_SUB_LONG = 65, OP_MUL_LONG = 66, OP_DIV_LONG = 67,
    OP_REM_LONG = 68, OP_AND_LONG = 69, OP_OR_LONG = 70, OP_XOR_LONG = 71,
    OP_SHL_LONG = 72, OP_SHR_LONG = 73, OP_USHR_LONG = 74,
    OP_NEG_LONG = 75, OP_NOT_LONG = 76, OP_CMP_LONG = 77,
    OP_INT_TO_LONG = 78, OP_LONG_TO_INT = 79, OP_RETURN_LONG = 80,
    OP_ADD_FLOAT = 81, OP_SUB_FLOAT = 82, OP_MUL_FLOAT = 83, OP_DIV_FLOAT = 84,
    OP_REM_FLOAT = 85, OP_NEG_FLOAT = 86, OP_CMPL_FLOAT = 87, OP_CMPG_FLOAT = 88,
    OP_INT_TO_FLOAT = 89, OP_LONG_TO_FLOAT = 90, OP_FLOAT_TO_INT = 91,
    OP_FLOAT_TO_LONG = 92, OP_FLOAT_TO_DOUBLE = 93,
    OP_ADD_DOUBLE = 94, OP_SUB_DOUBLE = 95, OP_MUL_DOUBLE = 96, OP_DIV_DOUBLE = 97,
    OP_REM_DOUBLE = 98, OP_NEG_DOUBLE = 99, OP_CMPL_DOUBLE = 100, OP_CMPG_DOUBLE = 101,
    OP_INT_TO_DOUBLE = 102, OP_LONG_TO_DOUBLE = 103, OP_DOUBLE_TO_INT = 104,
    OP_DOUBLE_TO_LONG = 105, OP_DOUBLE_TO_FLOAT = 106
};

enum : uint8_t {
    RET_VOID = 0, RET_INT = 1, RET_LONG = 2, RET_FLOAT = 3, RET_DOUBLE = 4,
    PARAM_INT = 0, PARAM_LONG = 1, PARAM_FLOAT = 2, PARAM_DOUBLE = 3
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
    uint32_t id = 0;
    uint16_t registers = 0;
    uint8_t parameters = 0;
    uint8_t parameterRegisters = 0;
    uint8_t parameterTypes = 0;
    uint8_t returnType = RET_VOID;
    bool returnsValue = false;
    bool doubleArguments = false;
    uint32_t opCount = 0;
    std::array<uint8_t, 8> opNonce{};
    std::array<uint8_t, 16> opTag{};
    std::vector<uint8_t> encodedOps;
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

struct ScopedWipe {
    void *data;
    size_t size;
    ScopedWipe(void *data, size_t size) : data(data), size(size) {}
    ~ScopedWipe() { if (data != nullptr && size != 0) secure_zero(data, size); }
};

static bool constantTimeEqual(const uint8_t *lhs, const uint8_t *rhs, size_t length) {
    uint8_t diff = 0;
    for (size_t i = 0; i < length; ++i) diff |= static_cast<uint8_t>(lhs[i] ^ rhs[i]);
    return diff == 0;
}

static void putBe32(uint8_t *p, uint32_t value) {
    p[0] = static_cast<uint8_t>(value >> 24u);
    p[1] = static_cast<uint8_t>(value >> 16u);
    p[2] = static_cast<uint8_t>(value >> 8u);
    p[3] = static_cast<uint8_t>(value);
}

static bool regOk(const VmProgram &p, uint8_t r) {
    return r < p.registers;
}

static bool wideRegOk(const VmProgram &p, uint8_t r) {
    return static_cast<uint16_t>(r) + 1u < p.registers;
}

static bool validate(const VmProgram &p, const VmOp &op, size_t opCount) {
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
        case OP_CONST_WIDE: case OP_MOVE_WIDE: case OP_NEG_LONG: case OP_NOT_LONG:
        case OP_RETURN_LONG:
            if (!wideRegOk(p, op.a)) return false;
            if (op.opcode != OP_CONST_WIDE && !wideRegOk(p, op.b)) return false;
            break;
        case OP_INT_TO_LONG:
            if (!wideRegOk(p, op.a) || !regOk(p, op.b)) return false;
            break;
        case OP_LONG_TO_INT:
            if (!regOk(p, op.a) || !wideRegOk(p, op.b)) return false;
            break;
        case OP_CMP_LONG:
            if (!regOk(p, op.a) || !wideRegOk(p, op.b) || !wideRegOk(p, op.c)) return false;
            break;
        case OP_NEG_FLOAT:
            if (!regOk(p, op.a) || !regOk(p, op.b)) return false;
            break;
        case OP_ADD_FLOAT: case OP_SUB_FLOAT: case OP_MUL_FLOAT: case OP_DIV_FLOAT:
        case OP_REM_FLOAT: case OP_CMPL_FLOAT: case OP_CMPG_FLOAT:
            if (!regOk(p, op.a) || !regOk(p, op.b) || !regOk(p, op.c)) return false;
            break;
        case OP_INT_TO_FLOAT: case OP_FLOAT_TO_INT:
            if (!regOk(p, op.a) || !regOk(p, op.b)) return false;
            break;
        case OP_LONG_TO_FLOAT:
            if (!regOk(p, op.a) || !wideRegOk(p, op.b)) return false;
            break;
        case OP_FLOAT_TO_LONG:
            if (!wideRegOk(p, op.a) || !regOk(p, op.b)) return false;
            break;
        case OP_FLOAT_TO_DOUBLE:
            if (!wideRegOk(p, op.a) || !regOk(p, op.b)) return false;
            break;
        case OP_NEG_DOUBLE:
            if (!wideRegOk(p, op.a) || !wideRegOk(p, op.b)) return false;
            break;
        case OP_ADD_DOUBLE: case OP_SUB_DOUBLE: case OP_MUL_DOUBLE: case OP_DIV_DOUBLE:
        case OP_REM_DOUBLE:
            if (!wideRegOk(p, op.a) || !wideRegOk(p, op.b) || !wideRegOk(p, op.c)) return false;
            break;
        case OP_CMPL_DOUBLE: case OP_CMPG_DOUBLE:
            if (!regOk(p, op.a) || !wideRegOk(p, op.b) || !wideRegOk(p, op.c)) return false;
            break;
        case OP_INT_TO_DOUBLE:
            if (!wideRegOk(p, op.a) || !regOk(p, op.b)) return false;
            break;
        case OP_LONG_TO_DOUBLE:
            if (!wideRegOk(p, op.a) || !wideRegOk(p, op.b)) return false;
            break;
        case OP_DOUBLE_TO_INT:
            if (!regOk(p, op.a) || !wideRegOk(p, op.b)) return false;
            break;
        case OP_DOUBLE_TO_LONG:
            if (!wideRegOk(p, op.a) || !wideRegOk(p, op.b)) return false;
            break;
        case OP_DOUBLE_TO_FLOAT:
            if (!regOk(p, op.a) || !wideRegOk(p, op.b)) return false;
            break;
        case OP_ADD_LONG: case OP_SUB_LONG: case OP_MUL_LONG: case OP_DIV_LONG:
        case OP_REM_LONG: case OP_AND_LONG: case OP_OR_LONG: case OP_XOR_LONG:
            if (!wideRegOk(p, op.a) || !wideRegOk(p, op.b) || !wideRegOk(p, op.c)) return false;
            break;
        case OP_SHL_LONG: case OP_SHR_LONG: case OP_USHR_LONG:
            if (!wideRegOk(p, op.a) || !wideRegOk(p, op.b) || !regOk(p, op.c)) return false;
            break;
        default:
            return false;
    }
    if ((op.opcode == OP_GOTO || (op.opcode >= OP_IF_EQZ && op.opcode <= OP_IF_LE))
            && op.target >= opCount) return false;
    return true;
}

static std::vector<uint8_t> deriveProgramKey(const VmProgram &p) {
    const char *buildKey = AY_OBFUSCATE(PARALLAX_BUILD_KEY);
    std::string baseLabel = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/ops/v1/"))
            + buildKey;
    std::vector<uint8_t> baseKey = hmac_sha256(PARALLAX_UNKNOWN_DATA, 16,
            reinterpret_cast<const uint8_t *>(baseLabel.data()), baseLabel.size());
    ScopedWipe baseWipe(baseKey.data(), baseKey.size());
    if (baseKey.size() != 32) return {};

    std::string programLabel = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/ops/program/v1/"))
            + std::to_string(p.id);
    std::vector<uint8_t> programKey = hmac_sha256(baseKey.data(), baseKey.size(),
            reinterpret_cast<const uint8_t *>(programLabel.data()), programLabel.size());
    if (programKey.size() != 32) {
        if (!programKey.empty()) secure_zero(programKey.data(), programKey.size());
        return {};
    }
    return programKey;
}

static bool verifyProgramTag(const VmProgram &p, const std::vector<uint8_t> &programKey) {
    const std::string tagLabel = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/ops/tag/v1/"));
    std::vector<uint8_t> tagInput;
    tagInput.reserve(tagLabel.size() + p.opNonce.size() + p.encodedOps.size());
    tagInput.insert(tagInput.end(), tagLabel.begin(), tagLabel.end());
    tagInput.insert(tagInput.end(), p.opNonce.begin(), p.opNonce.end());
    tagInput.insert(tagInput.end(), p.encodedOps.begin(), p.encodedOps.end());
    ScopedWipe tagInputWipe(tagInput.data(), tagInput.size());

    std::vector<uint8_t> expectedTag = hmac_sha256(programKey.data(), programKey.size(),
            tagInput.data(), tagInput.size());
    ScopedWipe tagWipe(expectedTag.data(), expectedTag.size());
    return expectedTag.size() >= p.opTag.size()
           && constantTimeEqual(expectedTag.data(), p.opTag.data(), p.opTag.size());
}

static bool decodeOp(const VmProgram &p, const std::vector<uint8_t> &programKey,
                     uint32_t index, VmOp &op) {
    if (index >= p.opCount) return false;
    const size_t start = static_cast<size_t>(index) * 12u;
    std::array<uint8_t, 12> plain{};
    ScopedWipe plainWipe(plain.data(), plain.size());

    for (size_t done = 0; done < plain.size();) {
        const size_t absolute = start + done;
        const uint32_t counter = static_cast<uint32_t>(absolute / 32u);
        const size_t inBlock = absolute % 32u;

        std::array<uint8_t, 12> blockInput{};
        std::copy(p.opNonce.begin(), p.opNonce.end(), blockInput.begin());
        putBe32(blockInput.data() + 8, counter);
        std::vector<uint8_t> block = hmac_sha256(programKey.data(), programKey.size(),
                blockInput.data(), blockInput.size());
        ScopedWipe blockWipe(block.data(), block.size());
        if (block.empty()) return false;

        const size_t take = std::min(plain.size() - done, block.size() - inBlock);
        for (size_t i = 0; i < take; ++i) {
            plain[done + i] = static_cast<uint8_t>(
                    p.encodedOps[start + done + i] ^ block[inBlock + i]);
        }
        done += take;
    }

    op.opcode = plain[0]; op.a = plain[1]; op.b = plain[2]; op.c = plain[3];
    op.imm = static_cast<int32_t>(be32(plain.data() + 4));
    op.target = be32(plain.data() + 8);
    return true;
}

static bool parsePayload(const std::vector<uint8_t> &raw) {
    if (raw.size() < 8 || memcmp(raw.data(), "PVR3", 4) != 0) return false;
    size_t cursor = 4;
    uint32_t count = be32(raw.data() + cursor); cursor += 4;
    if (count == 0 || count > kMaxPrograms) return false;

    std::unordered_map<uint32_t, VmProgram> parsed;
    parsed.reserve(count);
    for (uint32_t n = 0; n < count; ++n) {
        if (!hasBytes(cursor, 14, raw.size())) return false;
        uint32_t id = be32(raw.data() + cursor); cursor += 4;
        VmProgram p;
        p.id = id;
        p.registers = be16(raw.data() + cursor); cursor += 2;
        p.parameters = raw[cursor++];
        p.parameterRegisters = raw[cursor++];
        p.parameterTypes = raw[cursor++];
        uint8_t returnFlags = raw[cursor++];
        p.doubleArguments = (returnFlags & 0x80u) != 0;
        p.returnType = static_cast<uint8_t>(returnFlags & 0x7fu);
        uint32_t opCount = be32(raw.data() + cursor); cursor += 4;
        if (id == 0 || p.registers == 0 || p.registers > 255 || p.parameters > 4
                || p.parameterRegisters > p.registers || p.returnType > RET_DOUBLE
                || opCount == 0 || opCount > kMaxOpsPerProgram
                || parsed.find(id) != parsed.end()) return false;
        uint32_t width = 0;
        for (uint32_t i = 0; i < p.parameters; ++i) {
            uint8_t kind = (p.parameterTypes >> (i * 2u)) & 0x3u;
            if (kind == PARAM_INT || kind == PARAM_FLOAT) width += 1;
            else if (kind == PARAM_LONG || kind == PARAM_DOUBLE) width += 2;
            else return false;
            if (p.doubleArguments && kind == PARAM_LONG) return false;
        }
        if (width != p.parameterRegisters) return false;
        p.returnsValue = p.returnType != RET_VOID;

        const size_t encodedSize = static_cast<size_t>(opCount) * 12u;
        if (!hasBytes(cursor, p.opNonce.size() + p.opTag.size() + encodedSize, raw.size())) {
            return false;
        }
        std::copy(raw.begin() + cursor, raw.begin() + cursor + p.opNonce.size(),
                p.opNonce.begin());
        cursor += p.opNonce.size();
        std::copy(raw.begin() + cursor, raw.begin() + cursor + p.opTag.size(),
                p.opTag.begin());
        cursor += p.opTag.size();
        p.encodedOps.assign(raw.begin() + cursor, raw.begin() + cursor + encodedSize);
        cursor += encodedSize;
        p.opCount = opCount;

        std::vector<uint8_t> programKey = deriveProgramKey(p);
        ScopedWipe keyWipe(programKey.data(), programKey.size());
        if (programKey.size() != 32 || !verifyProgramTag(p, programKey)) return false;
        for (uint32_t i = 0; i < opCount; ++i) {
            VmOp op;
            ScopedWipe opWipe(&op, sizeof op);
            if (!decodeOp(p, programKey, i, op)
                    || !validate(p, op, opCount)) return false;
        }
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

static uint64_t getLong(const std::vector<int32_t> &r, uint8_t reg) {
    uint64_t low = static_cast<uint32_t>(r[reg]);
    uint64_t high = static_cast<uint32_t>(r[static_cast<size_t>(reg) + 1]);
    return low | (high << 32u);
}

static void setLong(std::vector<int32_t> &r, uint8_t reg, uint64_t value) {
    r[reg] = static_cast<int32_t>(static_cast<uint32_t>(value));
    r[static_cast<size_t>(reg) + 1] = static_cast<int32_t>(static_cast<uint32_t>(value >> 32u));
}

static float floatFromBits(uint32_t bits) {
    float value;
    std::memcpy(&value, &bits, sizeof value);
    return value;
}

static uint32_t bitsFromFloat(float value) {
    uint32_t bits;
    std::memcpy(&bits, &value, sizeof bits);
    return bits;
}

static double doubleFromBits(uint64_t bits) {
    double value;
    std::memcpy(&value, &bits, sizeof value);
    return value;
}

static uint64_t bitsFromDouble(double value) {
    uint64_t bits;
    std::memcpy(&bits, &value, sizeof bits);
    return bits;
}

static int32_t javaFloatToInt(float value) {
    if (std::isnan(value)) return 0;
    if (value >= 2147483647.0f) return std::numeric_limits<int32_t>::max();
    if (value <= -2147483648.0f) return std::numeric_limits<int32_t>::min();
    return static_cast<int32_t>(value);
}

static int64_t javaFloatToLong(float value) {
    if (std::isnan(value)) return 0;
    if (value >= 9223372036854775808.0f) return std::numeric_limits<int64_t>::max();
    if (value <= -9223372036854775808.0f) return std::numeric_limits<int64_t>::min();
    return static_cast<int64_t>(value);
}

static int32_t javaDoubleToInt(double value) {
    if (std::isnan(value)) return 0;
    if (value >= 2147483647.0) return std::numeric_limits<int32_t>::max();
    if (value <= -2147483648.0) return std::numeric_limits<int32_t>::min();
    return static_cast<int32_t>(value);
}

static int64_t javaDoubleToLong(double value) {
    if (std::isnan(value)) return 0;
    if (value >= 9223372036854775808.0) return std::numeric_limits<int64_t>::max();
    if (value <= -9223372036854775808.0) return std::numeric_limits<int64_t>::min();
    return static_cast<int64_t>(value);
}

static int32_t compareFloat(float lhs, float rhs, bool nanIsGreater) {
    if (std::isnan(lhs) || std::isnan(rhs)) return nanIsGreater ? 1 : -1;
    return lhs > rhs ? 1 : (lhs < rhs ? -1 : 0);
}

static int32_t compareDouble(double lhs, double rhs, bool nanIsGreater) {
    if (std::isnan(lhs) || std::isnan(rhs)) return nanIsGreater ? 1 : -1;
    return lhs > rhs ? 1 : (lhs < rhs ? -1 : 0);
}

static bool run(JNIEnv *env, uint32_t id, const uint64_t *args, size_t argc,
                bool expectValue, uint64_t *out) {
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

    std::vector<uint8_t> programKey = deriveProgramKey(p);
    ScopedWipe keyWipe(programKey.data(), programKey.size());
    if (programKey.size() != 32 || !verifyProgramTag(p, programKey)) {
        tamper();
        return false;
    }

    std::vector<int32_t> r(p.registers, 0);
    size_t parameterBase = p.registers - p.parameterRegisters;
    size_t parameterOffset = 0;
    for (size_t i = 0; i < argc; ++i) {
        uint8_t kind = (p.parameterTypes >> (i * 2u)) & 0x3u;
        if (p.doubleArguments) {
            double value = doubleFromBits(args[i]);
            if (kind == PARAM_DOUBLE) {
                setLong(r, static_cast<uint8_t>(parameterBase + parameterOffset), args[i]);
                parameterOffset += 2;
            } else if (kind == PARAM_FLOAT) {
                r[parameterBase + parameterOffset] =
                        static_cast<int32_t>(bitsFromFloat(static_cast<float>(value)));
                parameterOffset += 1;
            } else if (kind == PARAM_INT) {
                r[parameterBase + parameterOffset] = javaDoubleToInt(value);
                parameterOffset += 1;
            } else {
                reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
                return false;
            }
        } else if (kind == PARAM_LONG || kind == PARAM_DOUBLE) {
            setLong(r, static_cast<uint8_t>(parameterBase + parameterOffset), args[i]);
            parameterOffset += 2;
        } else {
            r[parameterBase + parameterOffset] =
                    static_cast<int32_t>(static_cast<uint32_t>(args[i]));
            parameterOffset += 1;
        }
    }

    size_t pc = 0;
    size_t steps = 0;
    const size_t limit = std::max<size_t>(4096u, static_cast<size_t>(p.opCount) * 256u);
    while (pc < p.opCount && steps++ < limit) {
        VmOp op;
        ScopedWipe opWipe(&op, sizeof op);
        if (!decodeOp(p, programKey, static_cast<uint32_t>(pc), op)) {
            tamper();
            return false;
        }
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
            case OP_CONST_WIDE:
                setLong(r, op.a, static_cast<uint64_t>(static_cast<uint32_t>(op.imm))
                        | (static_cast<uint64_t>(op.target) << 32u));
                ++pc; break;
            case OP_MOVE_WIDE: {
                uint64_t value = getLong(r, op.b);
                setLong(r, op.a, value);
                ++pc; break;
            }
            case OP_NEG_LONG:
                setLong(r, op.a, static_cast<uint64_t>(0) - getLong(r, op.b)); ++pc; break;
            case OP_NOT_LONG:
                setLong(r, op.a, ~getLong(r, op.b)); ++pc; break;
            case OP_INT_TO_LONG:
                setLong(r, op.a, static_cast<uint64_t>(static_cast<int64_t>(r[op.b]))); ++pc; break;
            case OP_LONG_TO_INT:
                r[op.a] = static_cast<int32_t>(static_cast<uint32_t>(getLong(r, op.b))); ++pc; break;
            case OP_ADD_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(floatFromBits(
                        static_cast<uint32_t>(r[op.b])) + floatFromBits(
                        static_cast<uint32_t>(r[op.c])))); ++pc; break;
            case OP_SUB_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(floatFromBits(
                        static_cast<uint32_t>(r[op.b])) - floatFromBits(
                        static_cast<uint32_t>(r[op.c])))); ++pc; break;
            case OP_MUL_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(floatFromBits(
                        static_cast<uint32_t>(r[op.b])) * floatFromBits(
                        static_cast<uint32_t>(r[op.c])))); ++pc; break;
            case OP_DIV_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(floatFromBits(
                        static_cast<uint32_t>(r[op.b])) / floatFromBits(
                        static_cast<uint32_t>(r[op.c])))); ++pc; break;
            case OP_REM_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(std::fmod(
                        floatFromBits(static_cast<uint32_t>(r[op.b])),
                        floatFromBits(static_cast<uint32_t>(r[op.c]))))); ++pc; break;
            case OP_NEG_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(
                        -floatFromBits(static_cast<uint32_t>(r[op.b])))); ++pc; break;
            case OP_CMPL_FLOAT:
                r[op.a] = compareFloat(floatFromBits(static_cast<uint32_t>(r[op.b])),
                        floatFromBits(static_cast<uint32_t>(r[op.c])), false); ++pc; break;
            case OP_CMPG_FLOAT:
                r[op.a] = compareFloat(floatFromBits(static_cast<uint32_t>(r[op.b])),
                        floatFromBits(static_cast<uint32_t>(r[op.c])), true); ++pc; break;
            case OP_INT_TO_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(static_cast<float>(r[op.b]))); ++pc; break;
            case OP_LONG_TO_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(
                        static_cast<float>(static_cast<int64_t>(getLong(r, op.b))))); ++pc; break;
            case OP_FLOAT_TO_INT:
                r[op.a] = javaFloatToInt(floatFromBits(static_cast<uint32_t>(r[op.b]))); ++pc; break;
            case OP_FLOAT_TO_LONG:
                setLong(r, op.a, static_cast<uint64_t>(javaFloatToLong(
                        floatFromBits(static_cast<uint32_t>(r[op.b]))))); ++pc; break;
            case OP_FLOAT_TO_DOUBLE:
                setLong(r, op.a, bitsFromDouble(static_cast<double>(
                        floatFromBits(static_cast<uint32_t>(r[op.b]))))); ++pc; break;
            case OP_ADD_DOUBLE:
                setLong(r, op.a, bitsFromDouble(doubleFromBits(getLong(r, op.b))
                        + doubleFromBits(getLong(r, op.c)))); ++pc; break;
            case OP_SUB_DOUBLE:
                setLong(r, op.a, bitsFromDouble(doubleFromBits(getLong(r, op.b))
                        - doubleFromBits(getLong(r, op.c)))); ++pc; break;
            case OP_MUL_DOUBLE:
                setLong(r, op.a, bitsFromDouble(doubleFromBits(getLong(r, op.b))
                        * doubleFromBits(getLong(r, op.c)))); ++pc; break;
            case OP_DIV_DOUBLE:
                setLong(r, op.a, bitsFromDouble(doubleFromBits(getLong(r, op.b))
                        / doubleFromBits(getLong(r, op.c)))); ++pc; break;
            case OP_REM_DOUBLE:
                setLong(r, op.a, bitsFromDouble(std::fmod(doubleFromBits(getLong(r, op.b)),
                        doubleFromBits(getLong(r, op.c))))); ++pc; break;
            case OP_NEG_DOUBLE:
                setLong(r, op.a, bitsFromDouble(-doubleFromBits(getLong(r, op.b)))); ++pc; break;
            case OP_CMPL_DOUBLE:
                r[op.a] = compareDouble(doubleFromBits(getLong(r, op.b)),
                        doubleFromBits(getLong(r, op.c)), false); ++pc; break;
            case OP_CMPG_DOUBLE:
                r[op.a] = compareDouble(doubleFromBits(getLong(r, op.b)),
                        doubleFromBits(getLong(r, op.c)), true); ++pc; break;
            case OP_INT_TO_DOUBLE:
                setLong(r, op.a, bitsFromDouble(static_cast<double>(r[op.b]))); ++pc; break;
            case OP_LONG_TO_DOUBLE:
                setLong(r, op.a, bitsFromDouble(static_cast<double>(
                        static_cast<int64_t>(getLong(r, op.b))))); ++pc; break;
            case OP_DOUBLE_TO_INT:
                r[op.a] = javaDoubleToInt(doubleFromBits(getLong(r, op.b))); ++pc; break;
            case OP_DOUBLE_TO_LONG:
                setLong(r, op.a, static_cast<uint64_t>(
                        javaDoubleToLong(doubleFromBits(getLong(r, op.b))))); ++pc; break;
            case OP_DOUBLE_TO_FLOAT:
                r[op.a] = static_cast<int32_t>(bitsFromFloat(static_cast<float>(
                        doubleFromBits(getLong(r, op.b))))); ++pc; break;
            case OP_CMP_LONG: {
                int64_t lhs = static_cast<int64_t>(getLong(r, op.b));
                int64_t rhs = static_cast<int64_t>(getLong(r, op.c));
                r[op.a] = (lhs > rhs) ? 1 : ((lhs < rhs) ? -1 : 0);
                ++pc; break;
            }
            case OP_ADD_LONG:
                setLong(r, op.a, getLong(r, op.b) + getLong(r, op.c)); ++pc; break;
            case OP_SUB_LONG:
                setLong(r, op.a, getLong(r, op.b) - getLong(r, op.c)); ++pc; break;
            case OP_MUL_LONG:
                setLong(r, op.a, getLong(r, op.b) * getLong(r, op.c)); ++pc; break;
            case OP_DIV_LONG: {
                int64_t rhs = static_cast<int64_t>(getLong(r, op.c));
                if (rhs == 0) return arithmeticException(env);
                int64_t lhs = static_cast<int64_t>(getLong(r, op.b));
                if (lhs == std::numeric_limits<int64_t>::min() && rhs == -1) {
                    setLong(r, op.a, static_cast<uint64_t>(lhs));
                } else {
                    setLong(r, op.a, static_cast<uint64_t>(lhs / rhs));
                }
                ++pc; break;
            }
            case OP_REM_LONG: {
                int64_t rhs = static_cast<int64_t>(getLong(r, op.c));
                if (rhs == 0) return arithmeticException(env);
                int64_t lhs = static_cast<int64_t>(getLong(r, op.b));
                setLong(r, op.a, (lhs == std::numeric_limits<int64_t>::min() && rhs == -1)
                        ? 0 : static_cast<uint64_t>(lhs % rhs));
                ++pc; break;
            }
            case OP_AND_LONG:
                setLong(r, op.a, getLong(r, op.b) & getLong(r, op.c)); ++pc; break;
            case OP_OR_LONG:
                setLong(r, op.a, getLong(r, op.b) | getLong(r, op.c)); ++pc; break;
            case OP_XOR_LONG:
                setLong(r, op.a, getLong(r, op.b) ^ getLong(r, op.c)); ++pc; break;
            case OP_SHL_LONG: {
                uint32_t count = static_cast<uint32_t>(r[op.c]) & 63u;
                setLong(r, op.a, getLong(r, op.b) << count); ++pc; break;
            }
            case OP_SHR_LONG: {
                uint32_t count = static_cast<uint32_t>(r[op.c]) & 63u;
                setLong(r, op.a, static_cast<uint64_t>(static_cast<int64_t>(getLong(r, op.b))
                        >> count)); ++pc; break;
            }
            case OP_USHR_LONG: {
                uint32_t count = static_cast<uint32_t>(r[op.c]) & 63u;
                setLong(r, op.a, getLong(r, op.b) >> count); ++pc; break;
            }
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
                if (out != nullptr) *out = static_cast<uint32_t>(r[op.a]);
                return true;
            case OP_RETURN_LONG:
                if (!expectValue) return false;
                if (out != nullptr) *out = getLong(r, op.a);
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

static jint callInt(JNIEnv *env, jint id, const uint64_t *args, size_t argc) {
    uint64_t result = 0;
    return run(env, static_cast<uint32_t>(id), args, argc, true, &result)
            ? static_cast<jint>(static_cast<uint32_t>(result)) : 0;
}

static jlong callLong(JNIEnv *env, jint id, const uint64_t *args, size_t argc) {
    uint64_t result = 0;
    return run(env, static_cast<uint32_t>(id), args, argc, true, &result)
            ? static_cast<jlong>(result) : 0;
}

static jfloat callFloat(JNIEnv *env, jint id, const uint64_t *args, size_t argc) {
    uint64_t result = 0;
    if (!run(env, static_cast<uint32_t>(id), args, argc, true, &result)) return 0.0f;
    return floatFromBits(static_cast<uint32_t>(result));
}

static jdouble callDouble(JNIEnv *env, jint id, const uint64_t *args, size_t argc) {
    uint64_t result = 0;
    if (!run(env, static_cast<uint32_t>(id), args, argc, true, &result)) return 0.0;
    auto found = g_programs.find(static_cast<uint32_t>(id));
    if (found == g_programs.end()) return 0.0;
    switch (found->second.returnType) {
        case RET_INT: return static_cast<double>(static_cast<int32_t>(result));
        case RET_FLOAT: return static_cast<double>(floatFromBits(static_cast<uint32_t>(result)));
        case RET_LONG: return static_cast<double>(static_cast<int64_t>(result));
        case RET_DOUBLE: return doubleFromBits(result);
        default: return 0.0;
    }
}

static void callVoid(JNIEnv *env, jint id, const uint64_t *args, size_t argc) {
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
                || memcmp(entryData, "PVM2", 4) != 0) break;
        uint32_t rawSize = be32(entryData + 4);
        if (rawSize == 0 || rawSize > kMaxVmPayload) break;

        const char *buildKey = AY_OBFUSCATE(PARALLAX_BUILD_KEY);
        std::string label = std::string(AY_OBFUSCATE("Parallax/highvalue/vm/encryption/v1/"))
                + buildKey;
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
jint highValueVmI1(JNIEnv *env, jclass, jint id, jint a0) { const uint64_t a[]{(uint64_t)(uint32_t)a0}; return callInt(env,id,a,1); }
jint highValueVmI2(JNIEnv *env, jclass, jint id, jint a0, jint a1) { const uint64_t a[]{(uint64_t)(uint32_t)a0,(uint64_t)(uint32_t)a1}; return callInt(env,id,a,2); }
jint highValueVmI3(JNIEnv *env, jclass, jint id, jint a0, jint a1, jint a2) { const uint64_t a[]{(uint64_t)(uint32_t)a0,(uint64_t)(uint32_t)a1,(uint64_t)(uint32_t)a2}; return callInt(env,id,a,3); }
jint highValueVmI4(JNIEnv *env, jclass, jint id, jint a0, jint a1, jint a2, jint a3) { const uint64_t a[]{(uint64_t)(uint32_t)a0,(uint64_t)(uint32_t)a1,(uint64_t)(uint32_t)a2,(uint64_t)(uint32_t)a3}; return callInt(env,id,a,4); }
void highValueVmV0(JNIEnv *env, jclass, jint id) { callVoid(env,id,nullptr,0); }
void highValueVmV1(JNIEnv *env, jclass, jint id, jint a0) { const uint64_t a[]{(uint64_t)(uint32_t)a0}; callVoid(env,id,a,1); }
void highValueVmV2(JNIEnv *env, jclass, jint id, jint a0, jint a1) { const uint64_t a[]{(uint64_t)(uint32_t)a0,(uint64_t)(uint32_t)a1}; callVoid(env,id,a,2); }
void highValueVmV3(JNIEnv *env, jclass, jint id, jint a0, jint a1, jint a2) { const uint64_t a[]{(uint64_t)(uint32_t)a0,(uint64_t)(uint32_t)a1,(uint64_t)(uint32_t)a2}; callVoid(env,id,a,3); }
void highValueVmV4(JNIEnv *env, jclass, jint id, jint a0, jint a1, jint a2, jint a3) { const uint64_t a[]{(uint64_t)(uint32_t)a0,(uint64_t)(uint32_t)a1,(uint64_t)(uint32_t)a2,(uint64_t)(uint32_t)a3}; callVoid(env,id,a,4); }

jlong highValueVmJ0(JNIEnv *env, jclass, jint id) { return callLong(env, id, nullptr, 0); }
jlong highValueVmJ1(JNIEnv *env, jclass, jint id, jlong a0) { const uint64_t a[]{(uint64_t)a0}; return callLong(env,id,a,1); }
jlong highValueVmJ2(JNIEnv *env, jclass, jint id, jlong a0, jlong a1) { const uint64_t a[]{(uint64_t)a0,(uint64_t)a1}; return callLong(env,id,a,2); }
jlong highValueVmJ3(JNIEnv *env, jclass, jint id, jlong a0, jlong a1, jlong a2) { const uint64_t a[]{(uint64_t)a0,(uint64_t)a1,(uint64_t)a2}; return callLong(env,id,a,3); }
jlong highValueVmJ4(JNIEnv *env, jclass, jint id, jlong a0, jlong a1, jlong a2, jlong a3) { const uint64_t a[]{(uint64_t)a0,(uint64_t)a1,(uint64_t)a2,(uint64_t)a3}; return callLong(env,id,a,4); }
void highValueVmVJ0(JNIEnv *env, jclass, jint id) { callVoid(env,id,nullptr,0); }
void highValueVmVJ1(JNIEnv *env, jclass, jint id, jlong a0) { const uint64_t a[]{(uint64_t)a0}; callVoid(env,id,a,1); }
void highValueVmVJ2(JNIEnv *env, jclass, jint id, jlong a0, jlong a1) { const uint64_t a[]{(uint64_t)a0,(uint64_t)a1}; callVoid(env,id,a,2); }
void highValueVmVJ3(JNIEnv *env, jclass, jint id, jlong a0, jlong a1, jlong a2) { const uint64_t a[]{(uint64_t)a0,(uint64_t)a1,(uint64_t)a2}; callVoid(env,id,a,3); }
void highValueVmVJ4(JNIEnv *env, jclass, jint id, jlong a0, jlong a1, jlong a2, jlong a3) { const uint64_t a[]{(uint64_t)a0,(uint64_t)a1,(uint64_t)a2,(uint64_t)a3}; callVoid(env,id,a,4); }

jfloat highValueVmF0(JNIEnv *env, jclass, jint id) { return callFloat(env, id, nullptr, 0); }
jfloat highValueVmF1(JNIEnv *env, jclass, jint id, jfloat a0) { const uint64_t a[]{bitsFromFloat(a0)}; return callFloat(env,id,a,1); }
jfloat highValueVmF2(JNIEnv *env, jclass, jint id, jfloat a0, jfloat a1) { const uint64_t a[]{bitsFromFloat(a0),bitsFromFloat(a1)}; return callFloat(env,id,a,2); }
jfloat highValueVmF3(JNIEnv *env, jclass, jint id, jfloat a0, jfloat a1, jfloat a2) { const uint64_t a[]{bitsFromFloat(a0),bitsFromFloat(a1),bitsFromFloat(a2)}; return callFloat(env,id,a,3); }
jfloat highValueVmF4(JNIEnv *env, jclass, jint id, jfloat a0, jfloat a1, jfloat a2, jfloat a3) { const uint64_t a[]{bitsFromFloat(a0),bitsFromFloat(a1),bitsFromFloat(a2),bitsFromFloat(a3)}; return callFloat(env,id,a,4); }
void highValueVmVF0(JNIEnv *env, jclass, jint id) { callVoid(env,id,nullptr,0); }
void highValueVmVF1(JNIEnv *env, jclass, jint id, jfloat a0) { const uint64_t a[]{bitsFromFloat(a0)}; callVoid(env,id,a,1); }
void highValueVmVF2(JNIEnv *env, jclass, jint id, jfloat a0, jfloat a1) { const uint64_t a[]{bitsFromFloat(a0),bitsFromFloat(a1)}; callVoid(env,id,a,2); }
void highValueVmVF3(JNIEnv *env, jclass, jint id, jfloat a0, jfloat a1, jfloat a2) { const uint64_t a[]{bitsFromFloat(a0),bitsFromFloat(a1),bitsFromFloat(a2)}; callVoid(env,id,a,3); }
void highValueVmVF4(JNIEnv *env, jclass, jint id, jfloat a0, jfloat a1, jfloat a2, jfloat a3) { const uint64_t a[]{bitsFromFloat(a0),bitsFromFloat(a1),bitsFromFloat(a2),bitsFromFloat(a3)}; callVoid(env,id,a,4); }

jdouble highValueVmD0(JNIEnv *env, jclass, jint id) { return callDouble(env, id, nullptr, 0); }
jdouble highValueVmD1(JNIEnv *env, jclass, jint id, jdouble a0) { const uint64_t a[]{bitsFromDouble(a0)}; return callDouble(env,id,a,1); }
jdouble highValueVmD2(JNIEnv *env, jclass, jint id, jdouble a0, jdouble a1) { const uint64_t a[]{bitsFromDouble(a0),bitsFromDouble(a1)}; return callDouble(env,id,a,2); }
jdouble highValueVmD3(JNIEnv *env, jclass, jint id, jdouble a0, jdouble a1, jdouble a2) { const uint64_t a[]{bitsFromDouble(a0),bitsFromDouble(a1),bitsFromDouble(a2)}; return callDouble(env,id,a,3); }
jdouble highValueVmD4(JNIEnv *env, jclass, jint id, jdouble a0, jdouble a1, jdouble a2, jdouble a3) { const uint64_t a[]{bitsFromDouble(a0),bitsFromDouble(a1),bitsFromDouble(a2),bitsFromDouble(a3)}; return callDouble(env,id,a,4); }
void highValueVmVd0(JNIEnv *env, jclass, jint id) { callVoid(env,id,nullptr,0); }
void highValueVmVd1(JNIEnv *env, jclass, jint id, jdouble a0) { const uint64_t a[]{bitsFromDouble(a0)}; callVoid(env,id,a,1); }
void highValueVmVd2(JNIEnv *env, jclass, jint id, jdouble a0, jdouble a1) { const uint64_t a[]{bitsFromDouble(a0),bitsFromDouble(a1)}; callVoid(env,id,a,2); }
void highValueVmVd3(JNIEnv *env, jclass, jint id, jdouble a0, jdouble a1, jdouble a2) { const uint64_t a[]{bitsFromDouble(a0),bitsFromDouble(a1),bitsFromDouble(a2)}; callVoid(env,id,a,3); }
void highValueVmVd4(JNIEnv *env, jclass, jint id, jdouble a0, jdouble a1, jdouble a2, jdouble a3) { const uint64_t a[]{bitsFromDouble(a0),bitsFromDouble(a1),bitsFromDouble(a2),bitsFromDouble(a3)}; callVoid(env,id,a,4); }