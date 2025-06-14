import com.sun.jna.NativeLibrary;
import org.exploit.sodium.Sodium;
import org.exploit.sodium.cipher.ChaCha20Poly1305Cipher;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class ChaCha20Poly1305CipherTest {
    private static final SecureRandom rnd = new SecureRandom();

    private byte[] randomKey() {
        var k = new byte[Sodium.INSTANCE.crypto_aead_xchacha20poly1305_ietf_keybytes()];
        rnd.nextBytes(k);
        return k;
    }

    static {
        NativeLibrary.addSearchPath("sodium", "/opt/homebrew/Cellar/libsodium/1.0.20/lib");
    }

    @Test
    void roundTripWithAssociatedData() {
        var cipher = ChaCha20Poly1305Cipher.getInstance();
        var key = randomKey();
        var plaintext = "Hello AEAD".getBytes(StandardCharsets.UTF_8);
        var aad = "ExtraData".getBytes(StandardCharsets.UTF_8);

        var ct = cipher.encrypt(plaintext, aad, key);
        assertNotNull(ct);
        assertTrue(ct.length > plaintext.length);

        var pt = cipher.decrypt(ct, aad, key);
        assertArrayEquals(plaintext, pt);
    }

    @Test
    void roundTripWithoutAssociatedData() {
        var cipher = ChaCha20Poly1305Cipher.getInstance();
        var key = randomKey();
        var plaintext = "No AAD Test".getBytes(StandardCharsets.UTF_8);

        var ct = cipher.encrypt(plaintext, null, key);
        var pt = cipher.decrypt(ct, null, key);
        assertArrayEquals(plaintext, pt);
    }

    @Test
    void decryptWithWrongAADFails() {
        var cipher = ChaCha20Poly1305Cipher.getInstance();
        var key = randomKey();
        var pt = "Data".getBytes(StandardCharsets.UTF_8);
        var aad = "AAD".getBytes(StandardCharsets.UTF_8);
        var ct = cipher.encrypt(pt, aad, key);

        assertThrows(IllegalStateException.class, () ->
            cipher.decrypt(ct, "BAD".getBytes(StandardCharsets.UTF_8), key)
        );
    }

    @Test
    void decryptWithWrongKeyFails() {
        var cipher = ChaCha20Poly1305Cipher.getInstance();
        var key1 = randomKey();
        var key2 = randomKey();
        var pt = "Secret".getBytes(StandardCharsets.UTF_8);
        var ct = cipher.encrypt(pt, null, key1);
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(ct, null, key2));
    }

    @Test
    void invalidKeyLengthThrows() {
        var cipher = ChaCha20Poly1305Cipher.getInstance();
        var badKey = new byte[16];
        assertThrows(IllegalArgumentException.class, () ->
            cipher.encrypt(new byte[0], null, badKey)
        );
        assertThrows(IllegalArgumentException.class, () ->
            cipher.decrypt(new byte[0], null, badKey)
        );
    }
}
