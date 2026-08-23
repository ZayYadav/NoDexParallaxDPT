#include <sys/prctl.h>
#include <sys/resource.h>

// Apply process-level dump hardening as soon as the shell library is loaded.
// Rooted devices are blocked separately by the Java entrypoint guard.
__attribute__((constructor))
static void parallax_harden_process() {
#ifndef DEBUG
    (void) prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    struct rlimit core_limit = {0, 0};
    (void) setrlimit(RLIMIT_CORE, &core_limit);
#endif
}
