import com.sun.jna.NativeLibrary;
import org.exploit.ed25519.Ed25519;
import org.exploit.sodium.Sodium;
import org.exploit.tss.TSS;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class Ed25519Test {
    static {
        NativeLibrary.addSearchPath("gmp", "/opt/homebrew/Cellar/gmp/6.3.0/lib");
        TSS.loadLibraries();
    }

    @Test
    void testGenerateKeyPair() {
        var kp = Ed25519.generateKeyPair();
        assertNotNull(kp);
        assertEquals(Sodium.crypto_sign_ed25519_PUBLICKEYBYTES, kp.getPublicKey().length);
        assertEquals(Sodium.crypto_sign_ed25519_SEEDBYTES, kp.getSecretKey().length);
    }

    @Test
    void testSeedKeyPairDeterministic() {
        var seed = new byte[Sodium.crypto_sign_ed25519_SEEDBYTES];
        Arrays.fill(seed, (byte) 0x42);
        var kp1 = Ed25519.fromSeed(seed);
        var kp2 = Ed25519.fromSeed(seed);
        assertArrayEquals(kp1.getPublicKey(), kp2.getPublicKey());
        assertArrayEquals(kp1.getSecretKey(), kp2.getSecretKey());
    }

    @Test
    void testSignVerifyDetached() {
        var kp = Ed25519.generateKeyPair();
        var message = "hello world".getBytes(StandardCharsets.UTF_8);
        var signature = Ed25519.signDetached(message, kp.getSecretKey());
        assertEquals(Sodium.crypto_sign_ed25519_BYTES, signature.length);
        assertTrue(Ed25519.verifyDetached(message, signature, kp.getPublicKey()));
    }

    @Test
    void testSignOpenFull() {
        var kp = Ed25519.generateKeyPair();
        var message = "full sign test".getBytes(StandardCharsets.UTF_8);
        var signed = Ed25519.sign(message, kp.getSecretKey());
        assertTrue(signed.length >= message.length + Sodium.crypto_sign_ed25519_BYTES);
        var opened = Ed25519.open(signed, kp.getPublicKey());
        assertArrayEquals(message, opened);
    }

    @Test
    void testInvalidSignature() {
        var kp1 = Ed25519.generateKeyPair();
        var kp2 = Ed25519.generateKeyPair();
        var message = "payload".getBytes(StandardCharsets.UTF_8);
        var signature = Ed25519.signDetached(message, kp1.getSecretKey());
        assertFalse(Ed25519.verifyDetached(message, signature, kp2.getPublicKey()));
    }
}