#include "parallax_vm.h"

// Compile PVM4 behind private names. parallax_vm_dispatch.cpp owns the stable public ABI
// consumed by the JNI export bridge and selects the correct runtime from the method id.
// parallax_vm4.cpp invokes its loader before the definition appears, so expose the private
// renamed declaration before macro-including the implementation.
void loadHighValueVm4(JNIEnv *env);

#define loadHighValueVm loadHighValueVm4
#define highValueVmI0 highValueVm4I0
#define highValueVmI1 highValueVm4I1
#define highValueVmI2 highValueVm4I2
#define highValueVmI3 highValueVm4I3
#define highValueVmI4 highValueVm4I4
#define highValueVmV0 highValueVm4V0
#define highValueVmV1 highValueVm4V1
#define highValueVmV2 highValueVm4V2
#define highValueVmV3 highValueVm4V3
#define highValueVmV4 highValueVm4V4

#include "parallax_vm4.cpp"

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
