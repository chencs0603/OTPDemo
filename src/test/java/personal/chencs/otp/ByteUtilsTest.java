package personal.chencs.otp;

import java.security.SecureRandom;
import java.util.Arrays;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.pqc.math.linearalgebra.BigEndianConversions;
import org.bouncycastle.pqc.math.linearalgebra.LittleEndianConversions;
import org.junit.Test;

import personal.chencs.utils.MyByteUtils;

public class ByteUtilsTest {

	@Test
	public void testLongToBytes() {
		long num = 0;
		byte[] bytes1;
		byte[] bytes2;
		
		//测试大端模式
		for (int i = 0; i < 0x80; i++) {
			num = new SecureRandom().nextLong();
//			num = 0x0203040500000000L;
			bytes1 = MyByteUtils.longToBytes(num, true);
			bytes2 = BigEndianConversions.I2OSP(num);
			if (!Arrays.equals(bytes1, bytes2)) {
				System.out.println("BigEndian Test Error!");
			}
		}
		
		//测试小端模式
		for (int i = 0; i < 0x80; i++) {
			num = new SecureRandom().nextLong();
			bytes1 = MyByteUtils.longToBytes(num, false);
			bytes2 = LittleEndianConversions.I2OSP(num);
			if (!Arrays.equals(bytes1, bytes2)) {
				System.out.println("LittleEndian Test Error!");
			}
		}
	}
	
	@Test
	public void testBytesToLong() {
		byte[] bytes;
		long num1, num2;
		
		//测试大端模式
		for (int i = 0; i < 0x80; i++) {
			bytes = RandomStringUtils.randomAlphabetic(0x08).getBytes();
			bytes = new byte[]{(byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01};
			num1 = MyByteUtils.bytesToLong(bytes, true);
			num2 = BigEndianConversions.OS2LIP(bytes, 0x00);
			if (!(num1 == num2)) {
				System.out.println("BigEndian Test Error!");
			}
		}
		
		//测试大端模式
		for (int i = 0; i < 0x80; i++) {
			bytes = RandomStringUtils.randomAlphabetic(0x08).getBytes();
			num1 = MyByteUtils.bytesToLong(bytes, false);
			num2 = LittleEndianConversions.OS2LIP(bytes, 0x00);
			if (!(num1 == num2)) {
				System.out.println("LittleEndian Test Error!");
			}
		}
	}
}
