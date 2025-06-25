import com.sun.jna.NativeLibrary;
import org.exploit.secp256k1.Secp256k1;
import org.exploit.tss.TSS;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class Secp256k1Test {
    private static final SecureRandom RNG = new SecureRandom();

    static {
        NativeLibrary.addSearchPath("gmp", "/opt/homebrew/Cellar/gmp/6.3.0/lib");
        TSS.loadLibraries();
    }

    @Test
    void keyPairGeneration() {
        var kp = Secp256k1.generateKeyPair();
        assertNotNull(kp);
        assertEquals(33, kp.getPublicKey().length);
        assertEquals(32, kp.getSecretKey().length);
    }

    @RepeatedTest(10)
    void recoverableSignAndVerify() {
        var kp = Secp256k1.generateKeyPair();
        var msg = new byte[32];
        RNG.nextBytes(msg);
        var sig65 = Secp256k1.signRecoverable(msg, kp.getSecretKey());
        assertEquals(65, sig65.length);
        assertTrue(Secp256k1.verifyRecoverable(msg, sig65, kp.getPublicKey()));
    }

    @Test
    void recoverableVerifyFailsWithWrongKey() {
        var kp1 = Secp256k1.generateKeyPair();
        var kp2 = Secp256k1.generateKeyPair();
        var msg = new byte[32];
        RNG.nextBytes(msg);
        var sig65 = Secp256k1.signRecoverable(msg, kp1.getSecretKey());
        assertFalse(Secp256k1.verifyRecoverable(msg, sig65, kp2.getPublicKey()));
    }

    @Test
    void xonlyConsistency() {
        var kp = Secp256k1.generateKeyPair();
        var x1 = Secp256k1.xonlyFromSecret(kp.getSecretKey());
        var x2 = Secp256k1.xonlyFromSecret(kp.getSecretKey());
        assertArrayEquals(x1.getBytes(), x2.getBytes());
        assertEquals(x1.getParity(), x2.getParity());
    }

    @Test
    void pubConsistency() {
        var kp = Secp256k1.generateKeyPair();
        var pub1 = Secp256k1.getPublicKey(kp.getSecretKey());

        assertArrayEquals(kp.getPublicKey(), pub1);
    }

    @RepeatedTest(10)
    void schnorrSignAndVerify() {
        var kp = Secp256k1.generateKeyPair();
        var msg = new byte[32];
        RNG.nextBytes(msg);
        var sig64 = Secp256k1.schnorrSign(msg, kp.getSecretKey());
        assertEquals(64, sig64.length);
        var xpk = Secp256k1.xonlyFromSecret(kp.getSecretKey());
        assertTrue(Secp256k1.schnorrVerify(msg, sig64, xpk.getBytes()));
    }

    @Test
    void schnorrVerifyFailsWithWrongKey() {
        var kp1 = Secp256k1.generateKeyPair();
        var kp2 = Secp256k1.generateKeyPair();
        var msg = new byte[32];
        RNG.nextBytes(msg);

        var sig64 = Secp256k1.schnorrSign(msg, kp1.getSecretKey());
        var xpk2 = Secp256k1.xonlyFromSecret(kp2.getSecretKey());
        assertFalse(Secp256k1.schnorrVerify(msg, sig64, xpk2.getBytes()));
    }

    @RepeatedTest(10)
    void taprootSignAndVerifyKeyPath() {
        var kp = Secp256k1.generateKeyPair();
        var msg = new byte[32];
        RNG.nextBytes(msg);

        var sig = Secp256k1.taprootSign(msg, kp.getSecretKey(), new byte[32]);
        var xonly = Secp256k1.xonlyFromSecret(kp.getSecretKey()).getBytes();

        assertTrue(Secp256k1.taprootVerify(msg, sig, xonly, new byte[32]));
    }

    @Test
    void taprootVerifyFailsWithWrongKey() {
        var kp1 = Secp256k1.generateKeyPair();
        var kp2 = Secp256k1.generateKeyPair();
        var msg = new byte[32];
        RNG.nextBytes(msg);

        var sig = Secp256k1.taprootSign(msg, kp1.getSecretKey(), new byte[0]);
        var wrongXonly = Secp256k1.xonlyFromSecret(kp2.getSecretKey()).getBytes();

        assertFalse(Secp256k1.taprootVerify(msg, sig, wrongXonly, new byte[0]));
    }

    @RepeatedTest(10)
    void taprootWithScriptPathTweak() {
        var kp = Secp256k1.generateKeyPair();
        var msg = new byte[32];
        RNG.nextBytes(msg);

        var merkleRoot = new byte[32];
        RNG.nextBytes(merkleRoot);

        var sig = Secp256k1.taprootSign(msg, kp.getSecretKey(), merkleRoot);
        var xonly = Secp256k1.xonlyFromSecret(kp.getSecretKey()).getBytes();

        assertTrue(Secp256k1.taprootVerify(msg, sig, xonly, merkleRoot));
    }
}