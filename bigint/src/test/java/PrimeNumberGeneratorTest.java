import org.exploit.gmp.BigInt;
import org.exploit.gmp.util.PrimeNumberGenerator;
import org.exploit.tss.TSS;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class PrimeNumberGeneratorTest {
    @BeforeEach
    void setUp() {
        TSS.loadLibraries();
    }

    @Test
    void generatePrime_hasCorrectBitLengthAndIsPrime() {
        var bits = 512;
        var p = PrimeNumberGenerator.generate(bits);

        assertEquals(bits, p.bitLength(), "bit length mismatch");
        assertTrue(PrimeNumberGenerator.isPrime(p.toJavaInt()), "not prime");
    }

    @RepeatedTest(3)
    void generateBlumPrime_isPrimeAndClass3mod4() {
        var bits = 512;
        var p = PrimeNumberGenerator.generateBlum(bits);

        assertEquals(bits, p.bitLength(), "bit length mismatch");
        assertTrue(PrimeNumberGenerator.isPrime(p.toJavaInt()), "not prime");
        assertEquals(3L, p.and(BigInt.valueOf(3)).longValue(), "p ≡ 3 (mod 4) required");
    }

    @Test
    void generateBlumPair_distinct_primes_class3mod4() {
        var bits = 1024;
        var pair = PrimeNumberGenerator.generateBlumPair(bits);
        var p = pair.p();
        var q = pair.q();

        assertNotEquals(p, q, "p must differ from q");
        assertEquals(bits / 2, p.bitLength(), "p bit length mismatch");
        assertEquals(bits / 2, q.bitLength(), "q bit length mismatch");

        assertTrue(PrimeNumberGenerator.isPrime(p.toJavaInt()), "p not prime");
        assertTrue(PrimeNumberGenerator.isPrime(q.toJavaInt()), "q not prime");

        assertEquals(3L, p.and(BigInt.valueOf(3)).longValue(), "p ≡ 3 (mod 4) required");
        assertEquals(3L, q.and(BigInt.valueOf(3)).longValue(), "q ≡ 3 (mod 4) required");
    }

    @Test
    void generateBlumPrime_parallelDoesNotBreak() {
        var bits = 512;
        var p = PrimeNumberGenerator.generateBlum(bits, Math.max(2, Runtime.getRuntime().availableProcessors() / 2));

        assertTrue(PrimeNumberGenerator.isPrime(p.toJavaInt()), "not prime");
        assertEquals(3L, p.and(BigInt.valueOf(3)).longValue(), "p ≡ 3 (mod 4) required");
    }
}