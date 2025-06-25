import org.exploit.sodium.ReadOnlyBuffer;
import org.exploit.sodium.Sodium;
import org.exploit.tss.TSS;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ReadOnlyBufferException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class ReadOnlyBufferTests {
    static {
        TSS.loadLibraries();
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

    @ParameterizedTest
    @ValueSource(ints = {1, 3, 5, 7, 15, 33})
    void readOnlyBufferActsReadOnly_oddSizes(int size) {
        byte[] key = new byte[size];
        Sodium.INSTANCE.randombytes_buf(key, key.length);
        byte first = key[0];

        try (var sec = new ReadOnlyBuffer(key)) {
            var ro = sec.asReadOnlyByteBuffer();
            assertTrue(ro.isReadOnly(), "Buffer not read-only for size=" + size);

            assertEquals(first, ro.get(0),
                    "Data mismatch at index 0 for size=" + size);
            assertThrows(ReadOnlyBufferException.class,
                    () -> ro.put(0, (byte) 1),
                    "put should throw for size=" + size);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 3, 5, 7, 15, 33})
    void operationsAfterCloseThrow_oddSizes(int size) {
        byte[] key = new byte[size];
        try (var buf = new ReadOnlyBuffer(key)) {
            buf.close();
            assertThrows(IllegalStateException.class, buf::read,
                    "read() should fail after close for size=" + size);
            assertThrows(IllegalStateException.class, buf::asReadOnlyByteBuffer,
                    "asReadOnlyByteBuffer() should fail after close for size=" + size);
        }
    }
}
