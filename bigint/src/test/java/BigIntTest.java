import com.sun.jna.NativeLibrary;
import org.exploit.gmp.BigInt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class BigIntTest {
    private static final SecureRandom RND = new SecureRandom();

    @BeforeEach
    public void setUp() {
        NativeLibrary.addSearchPath("gmp", "/opt/homebrew/Cellar/gmp/6.3.0/lib");
    }

    @Test
    public void testConstructorFromString() {
        var num = new BigInt("123456789", 10);
        assertEquals("123456789", num.toString());
    }

    @Test
    void fixedModInverse() {
        var a = BigInt.valueOf(3);
        var m = BigInt.valueOf(11);
        var inv = a.modInverse(m);
        assertEquals(BigInt.valueOf(4), inv, "3^{-1} mod 11 should be 4");
        assertEquals(BigInt.ONE, a.multiply(inv).mod(m));
    }

    @RepeatedTest(50)
    void randomModInverse() {
        BigInt m;
        do {
            m = new BigInt(256, RND);
        } while (m.signum() == 0);

        BigInt a;
        do {
            a = new BigInt(256, RND).mod(m);
        } while (!a.gcd(m).equals(BigInt.ONE));

        var inv = a.modInverse(m);

        assertEquals(BigInt.ONE, a.multiply(inv).mod(m));
    }

    @Test
    void modInverseNonCoprime() {
        var a = BigInt.valueOf(2);
        var m = BigInt.valueOf(6);
        assertThrows(ArithmeticException.class, () -> a.modInverse(m));
    }

    @Test
    void modInverseNegativeModulus() {
        var a = BigInt.valueOf(3);
        var m = BigInt.valueOf(-11);
        assertThrows(ArithmeticException.class, () -> a.modInverse(m));
    }

    @RepeatedTest(20)
    void negateProperties() {
        var x = new BigInt(256, RND);
        var y = x.negate();

        assertEquals(BigInt.ZERO, x.add(y));
        assertEquals(BigInt.ZERO, y.add(x));

        if (x.signum() != 0) {
            assertEquals(-x.signum(), y.signum());
        }
    }

    @Test
    void negateZeroConstant() {
        assertEquals(BigInt.ZERO, BigInt.ZERO.negate());
    }

    @Test
    public void testConstructorFromByteArray() {
        byte[] bytes = {1, 2, 3, 4};
        var num = new BigInt(bytes);
        assertNotNull(num);
        assertArrayEquals(bytes, num.toByteArray());
    }

    @Test
    public void testAdd() {
        var a = new BigInt("100", 10);
        var b = new BigInt("200", 10);
        var sum = a.add(b);
        assertEquals("300", sum.toString());
    }

    @Test
    public void testSubtract() {
        var a = new BigInt("300", 10);
        var b = new BigInt("100", 10);
        var diff = a.subtract(b);
        assertEquals("200", diff.toString());
    }

    @Test
    public void testMultiply() {
        var a = new BigInt("10", 10);
        var b = new BigInt("20", 10);
        var product = a.multiply(b);
        assertEquals("200", product.toString());
    }

    @Test
    public void testDivide() {
        var a = new BigInt("100", 10);
        var b = new BigInt("5", 10);
        var quotient = a.divide(b);
        assertEquals("20", quotient.toString());
    }

    @Test
    public void testRemainder() {
        var a = new BigInt("100", 10);
        var b = new BigInt("7", 10);
        var remainder = a.remainder(b);
        assertEquals("2", remainder.toString());
    }

    @Test
    public void testPow() {
        var a = new BigInt("2", 10);
        var result = a.pow(10);
        assertEquals("1024", result.toString());
    }

    @Test
    public void testModPow() {
        var base = new BigInt("4", 10);
        var exponent = new BigInt("13", 10);
        var modulus = new BigInt("497", 10);
        var result = base.modPow(exponent, modulus);
        assertEquals("445", result.toString());
    }

    @Test
    public void testMod() {
        var a = new BigInt("100", 10);
        var m = new BigInt("9", 10);
        var result = a.mod(m);
        assertEquals("1", result.toString());
    }

    @Test
    public void testGcd() {
        var a = new BigInt("48", 10);
        var b = new BigInt("18", 10);
        var gcd = a.gcd(b);
        assertEquals("6", gcd.toString());
    }

    @Test
    public void testIsProbablePrime() {
        var prime = new BigInt("17", 10);
        assertTrue(prime.isProbablePrime(50));
        var composite = new BigInt("15", 10);
        assertFalse(composite.isProbablePrime(50));
    }

    @Test
    public void testCompareTo() {
        var a = new BigInt("100", 10);
        var b = new BigInt("200", 10);
        assertTrue(a.compareTo(b) < 0);
        assertTrue(b.compareTo(a) > 0);
        assertEquals(0, a.compareTo(a));
    }

    @Test
    public void testToByteArray() {
        var num = new BigInt("255", 10);
        var bytes = num.toByteArray();
        assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0xFF}, bytes);
    }

    @Test
    public void testEquals() {
        var a = new BigInt("123", 10);
        var b = new BigInt("123", 10);
        var c = new BigInt("456", 10);
        assertEquals(a, b);
        assertNotEquals(a, c);
    }

    @Test
    public void testHashCode() {
        var a = new BigInt("123", 10);
        var b = new BigInt("123", 10);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    public void testSignumFunction() {
        var pos = new BigInt("123", 10);
        assertEquals(1, pos.signum());

        var neg = new BigInt("-123", 10);
        assertEquals(-1, neg.signum());

        var zero = new BigInt("0", 10);
        assertEquals(0, zero.signum());
    }

    @Test
    public void testConstructorWithSignum() {
        byte[] magnitude = {1, 2, 3};
        var pos = new BigInt(1, magnitude);
        assertEquals("66051", pos.toString());

        var neg = new BigInt(-1, magnitude);
        assertEquals("-66051", neg.toString());

        var zero = new BigInt(0, magnitude);
        assertEquals("0", zero.toString());
    }

    @Test
    public void testDivisionByZero() {
        var a = new BigInt("100", 10);
        var zero = new BigInt("0", 10);
        assertThrows(ArithmeticException.class, () -> a.divide(zero));
    }

    @Test
    public void testNegativeNumbers() {
        var neg = new BigInt("-456", 10);
        var pos = new BigInt("456", 10);
        assertTrue(neg.signum() < 0);
        assertTrue(pos.signum() > 0);
    }

    @Test
    void shiftLeft_zero() {
        var a = BigInt.valueOf(12345);
        assertEquals(a, a.shiftLeft(0), "Shifting left by 0 should return the same value");
    }

    @Test
    void shiftRight_zero() {
        var a = BigInt.valueOf(-6789);
        assertEquals(a, a.shiftRight(0), "Shifting right by 0 should return the same value");
    }

    @Test
    void shiftLeft_positive() {
        assertEquals(BigInt.valueOf(16), BigInt.valueOf(1).shiftLeft(4), "1 << 4 = 16");
        assertEquals(BigInt.valueOf(1024), BigInt.valueOf(4).shiftLeft(8), "4 << 8 = 1024");
    }

    @Test
    void shiftRight_positive() {
        assertEquals(BigInt.valueOf(2), BigInt.valueOf(8).shiftRight(2), "8 >> 2 = 2");
        assertEquals(BigInt.valueOf(3), BigInt.valueOf(25).shiftRight(3), "25 >> 3 = floor(25/8) = 3");
    }

    @Test
    void shiftLeft_negativeParameter_shouldBehaveAsShiftRight() {
        var original = BigInt.valueOf(12);
        assertEquals(BigInt.valueOf(3), original.shiftLeft(-2), "12 << -2 should be 12 >> 2 = 3");
    }

    @Test
    void shiftRight_negativeParameter_shouldBehaveAsShiftLeft() {
        var original = BigInt.valueOf(6);
        assertEquals(BigInt.valueOf(24), original.shiftRight(-2), "6 >> -2 should be 6 << 2 = 24");
    }

    @Test
    void shiftRight_negativeValues_floorDivision() {
        assertEquals(BigInt.valueOf(-5), BigInt.valueOf(-9).shiftRight(1), "Arithmetic right shift of -9 by 1 bit");
        assertEquals(BigInt.valueOf(-5), BigInt.valueOf(-17).shiftRight(2), "Arithmetic right shift of -17 by 2 bits");
    }

    @Test
    void shiftLeft_large() {
        var one = BigInt.ONE;
        var large = one.shiftLeft(100);
        assertEquals(101, large.bitLength(), "1 << 100 should have bit length 101");
    }

    @Test
    void shiftRight_largeBeyondSize() {
        var small = BigInt.valueOf(5);
        assertEquals(BigInt.ZERO, small.shiftRight(10), "5 >> 10 should be 0");
        assertEquals(BigInt.ZERO, BigInt.ZERO.shiftRight(100), "0 >> 100 should still be 0");
    }

    @Test
    @DisplayName("Zero returns array of required length filled with zeros")
    void zeroProducesAllZeros() {
        var n = BigInt.ZERO;
        assertArrayEquals(new byte[]{0, 0, 0, 0}, n.toUnsignedByteArray(4));
    }

    @Test
    @DisplayName("128 (0x80) has no extra sign byte")
    void positiveNoExtraSignByte() {
        var n = BigInt.valueOf(128);
        assertArrayEquals(new byte[]{(byte) 0x80}, n.toUnsignedByteArray(1));
    }

    @Test
    @DisplayName("255 (0xFF) padded with leading zero")
    void paddedWithLeadingZero() {
        var n = BigInt.valueOf(255);
        assertArrayEquals(new byte[]{0x00, (byte) 0xFF}, n.toUnsignedByteArray(2));
    }

    @Test
    @DisplayName("65535 (0xFFFF) fits exactly in 2 bytes")
    void exactFit() {
        var n = BigInt.valueOf(65_535);
        assertArrayEquals(new byte[]{(byte) 0xFF, (byte) 0xFF}, n.toUnsignedByteArray(2));
    }

    @Test
    @DisplayName("Size ≤ 0 throws IllegalArgumentException")
    void nonPositiveSizeThrows() {
        var n = BigInt.ONE;
        assertThrows(IllegalArgumentException.class, () -> n.toUnsignedByteArray(0));
    }

    @Test
    @DisplayName("Negative value throws ArithmeticException")
    void negativeValueThrows() {
        var n = BigInt.valueOf(-1);
        assertThrows(ArithmeticException.class, () -> n.toUnsignedByteArray(1));
    }

    @Test
    @DisplayName("Number doesn't fit size throws IllegalArgumentException")
    void tooSmallSizeThrows() {
        var n = BigInt.valueOf(256);
        assertThrows(IllegalArgumentException.class, () -> n.toUnsignedByteArray(1));
    }

    @RepeatedTest(30)
    void modPowSec_equals_regular() {
        BigInt base = new BigInt(256, RND);
        BigInt exp  = new BigInt(128, RND);

        BigInt mod;
        do {
            mod = new BigInt(256, RND);
        } while (mod.signum() == 0 || !mod.testBit(0));

        BigInt regular = base.modPow(exp,  mod);
        BigInt secure  = base.modPowSec(exp, mod);

        assertEquals(regular, secure, "modPowSec should match regular modPow for odd modulus");
    }

    @RepeatedTest(30)
    void multiplySec_equals_regular() {
        var a = new BigInt(256, RND);
        var b = new BigInt(256, RND);

        var regular = a.multiply(b);
        var secure = a.multiplySec(b);

        assertEquals(regular, secure,
                "multiplySec should match regular multiply");
    }

    @RepeatedTest(20)
    void modInverseSec_equals_regular() {
        BigInt m;
        do {
            m = new BigInt(256, RND);
        } while (m.signum() == 0);

        BigInt a;
        do {
            a = new BigInt(256, RND).mod(m);
        } while (!a.gcd(m).equals(BigInt.ONE));

        var regular = a.modInverse(m);
        var secure = a.modInverseSec(m);

        assertEquals(regular, secure, "modInverseSec should match regular modInverse");
        assertEquals(BigInt.ONE, a.multiply(secure).mod(m));
    }
}