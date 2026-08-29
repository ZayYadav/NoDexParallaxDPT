package com.parallax.shell;

/**
 * Tiny pre-pack integrity gate target. Release mapping renames this class to Parallax3.
 * Synthetic gate bodies are injected before DPT extraction and therefore move into the
 * authenticated encrypted method vault rather than remaining useful in the static DEX.
 */
public final class ParallaxGate {
    private static volatile int flow = 0x13579BDF;

    private ParallaxGate() {
    }

    private static int opaque(int real, int decoy) {
        int x = flow;
        x = Integer.rotateLeft(x ^ 0x6D2B79F5, 5) + 0x7F4A7C15;
        flow = x;
        // x*(x+1) is always even. The decoy edge is deliberately opaque to a simple
        // straight-line decompiler but deterministic at runtime.
        return ((x * (x + 1)) & 1) == 0 ? real : decoy;
    }

    public static void g(int a, int b, int c, int expected) {
        int state = opaque(0x21, 0x71);
        int value = 0;
        for (;;) {
            switch (state) {
                case 0x21:
                    value = Integer.rotateLeft(a ^ 0x5A17D3C9, b & 31);
                    state = opaque(0x32, 0x72);
                    break;
                case 0x32:
                    value ^= Integer.rotateRight(b + 0x6D2B79F5, 11);
                    state = opaque(0x43, 0x73);
                    break;
                case 0x43:
                    value += c ^ 0x9E3779B9;
                    flow = Integer.rotateLeft(flow ^ value, 3) + 0x7F4A7C15;
                    state = value == expected ? opaque(0x54, 0x74) : opaque(0x65, 0x75);
                    break;
                case 0x54:
                    // Native layer performs deterministic signing/integrity validation.
                    ParallaxKiSettingKarwaDo.clinit();
                    return;
                case 0x65:
                    // Defensive response only: fail-close this protected app process.
                    ParallaxKiSettingKarwaDo.scheduleExit(0);
                    return;
                case 0x71:
                    state = 0x21;
                    break;
                case 0x72:
                    state = 0x32;
                    break;
                case 0x73:
                    state = 0x43;
                    break;
                case 0x74:
                    state = 0x54;
                    break;
                case 0x75:
                    state = 0x65;
                    break;
                default:
                    ParallaxKiSettingKarwaDo.scheduleExit(0);
                    return;
            }
        }
    }
}
