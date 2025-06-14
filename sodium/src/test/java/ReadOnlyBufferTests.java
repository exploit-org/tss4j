import com.sun.jna.NativeLibrary;
import org.exploit.sodium.ReadOnlyBuffer;
import org.exploit.sodium.Sodium;
import org.junit.jupiter.api.Test;

import java.nio.ReadOnlyBufferException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class ReadOnlyBufferTests {
    static {
        NativeLibrary.addSearchPath("sodium", "/opt/homebrew/Cellar/libsodium/1.0.20/lib");
    }

    @Test
    void dataAreCopiedAndSourceIsZeroed() {
        var src = new byte[32];
        Sodium.INSTANCE.randombytes_buf(src, src.length);

        var srcSnapshot = src.clone();
        try (var buf = new ReadOnlyBuffer(src)) {
            assertArrayEquals(src, new byte[32], "source array not zeroed");

            var copy = buf.read();
            assertArrayEquals(srcSnapshot, copy,
                    "data mismatch between src and copy");

            Arrays.fill(copy, (byte) 0);
            var copy2 = buf.read();
            assertArrayEquals(srcSnapshot, copy2,
                    "secure memory mutated unexpectedly");
        }
    }

    @Test
    void readOnlyBufferActsReadOnly() {
        var key = new byte[16];
        Sodium.INSTANCE.randombytes_buf(key, key.length);

        var firstByte = key[0];

        try (var sec = new ReadOnlyBuffer(key)) {
            var ro = sec.asReadOnlyByteBuffer();
            assertTrue(ro.isReadOnly());

            assertEquals(firstByte, ro.get(0));
            assertThrows(ReadOnlyBufferException.class,
                    () -> ro.put(0, (byte) 1));
        }
    }

    @Test
    void operationsAfterCloseThrow() {
        var key = new byte[8];
        var buf = new ReadOnlyBuffer(key);
        buf.close();

        assertThrows(IllegalStateException.class, buf::read,
                "read() should fail after close");
        assertThrows(IllegalStateException.class, buf::asReadOnlyByteBuffer,
                "asReadOnlyByteBuffer() should fail after close");
    }
}
