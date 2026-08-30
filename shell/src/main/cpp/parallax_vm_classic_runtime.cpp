#include "parallax_util.h"
#include "parallax_vm.h"

// Compile the legacy PVM1 interpreter as a private runtime. Its payload lives beside the
// PVM4 payload under a different reserved asset name so both tiers can coexist in one APK.
static std::optional<std::tuple<uint8_t*, size_t>> readClassicVmAsset(
        void *zipAddr, off_t zipSize, const char *entryName);

#define loadHighValueVm loadHighValueVmClassic
#define highValueVmI0 highValueVmClassicI0
#define highValueVmI1 highValueVmClassicI1
#define highValueVmI2 highValueVmClassicI2
#define highValueVmI3 highValueVmClassicI3
#define highValueVmI4 highValueVmClassicI4
#define highValueVmV0 highValueVmClassicV0
#define highValueVmV1 highValueVmClassicV1
#define highValueVmV2 highValueVmClassicV2
#define highValueVmV3 highValueVmClassicV3
#define highValueVmV4 highValueVmClassicV4
#define read_zip_file_entry readClassicVmAsset

#include "parallax_vm.cpp"

#undef read_zip_file_entry
#undef highValueVmV4
#undef highValueVmV3
#undef highValueVmV2
#undef highValueVmV1
#undef highValueVmV0
#undef highValueVmI4
#undef highValueVmI3
#undef highValueVmI2
#undef highValueVmI1
#undef highValueVmI0
#undef loadHighValueVm

static std::optional<std::tuple<uint8_t*, size_t>> readClassicVmAsset(
        void *zipAddr, off_t zipSize, const char *entryName) {
    (void) entryName;
    return read_zip_file_entry(zipAddr, zipSize, AY_OBFUSCATE("assets/Parallax.vmc"));
}
