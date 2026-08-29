package com.parallax.shell;

/**
 * Tiny pre-pack integrity gate target.
 *
 * Synthetic gates are injected into safe classes in the original app DEX before DPT
 * extracts/hollows method bodies. Their randomized challenge constants therefore move
 * into the authenticated encrypted method vault instead of remaining as a useful static
 * verifier in the final hollow DEX.
 */
public final class ParallaxGate {
    private static volatile int flow = 0x13579BDF;

    private ParallaxGate() {
    }

    public static void g(int a, int b, int c, int expected) {
        int value = Integer.rotateLeft(a ^ 0x5A17D3C9, b & 31);
        value ^= Integer.rotateRight(b + 0x6D2B79F5, 11);
        value += c ^ 0x9E3779B9;

        // Keep a state dependency so the gate remains a real runtime operation after R8.
        flow = Integer.rotateLeft(flow ^ value, 3) + 0x7F4A7C15;

        if (value != expected) {
            // Defensive response only: latch this protected app as tampered.
            ParallaxKiSettingKarwaDo.scheduleExit(0);
            return;
        }

        // Native layer performs the deterministic signing/integrity check.
        ParallaxKiSettingKarwaDo.clinit();
    }
}
