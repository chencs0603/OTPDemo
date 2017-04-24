package personal.chencs.otp;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import personal.chencs.otp.OTPApi.CryptoType;

public class OTPApiTest {
	private static Logger logger = LogManager.getLogger(OTPApiTest.class);

	@Test
	public void testTruncateHmac() throws DecoderException {
		byte[] hmac = Hex.decodeHex("1F8698690E02CA16618550EF7F19DA8E945B555A".toCharArray());
		int returnDigits = 0x06;
		logger.info("hmac:" + Hex.encodeHexString(hmac).toUpperCase() + ", returnDigits:" + returnDigits);
	
		String otp = OTPApi.truncateHmac(hmac, returnDigits);
		
		logger.info("otp:" + otp);
		Assert.assertTrue("872921".equals(otp));
	}
	
	@Test
	public void testGenerateTOTP() throws DecoderException {
		byte[] key = Hex.decodeHex("3132333435363738393031323334353637383930".toCharArray());
		byte[] key32 = Hex.decodeHex("3132333435363738393031323334353637383930313233343536373839303132".toCharArray());
		byte[] key64 = Hex.decodeHex("31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334".toCharArray());
		
		String[] hexTime = {"0000000000000001", "00000000023523EC", "00000000023523ED", "000000000273EF07", "0000000003F940AA", "0000000027BC86AA"};
		int returnDigits = 0x08;
		byte[] time;
		String otp;
		
		System.out.println("+------------------+-------------+----------+");
		System.out.println("|        time      |     TOTP    |    Mode  |");
		System.out.println("+------------------+-------------+----------+");
		for (int i = 0; i < hexTime.length; i++) {
			time = Hex.decodeHex(hexTime[i].toCharArray());
			otp = OTPApi.generateTOTP(key, time, returnDigits, CryptoType.HmacSHA1);
			System.out.println("| " + hexTime[i] + " |   " + otp +
					"  | " + CryptoType.HmacSHA1 + " |");
			otp = OTPApi.generateTOTP(key32, time, returnDigits, CryptoType.HmacSHA256);
			System.out.println("| " + hexTime[i] + " |   " + otp +
					"  |" + CryptoType.HmacSHA256 + "|");
			otp = OTPApi.generateTOTP(key64, time, returnDigits, CryptoType.HmacSHA512);
			System.out.println("| " + hexTime[i] + " |   " + otp +
					"  |" + CryptoType.HmacSHA512 + "|");
		}
	}
	
	@Test
	public void testGenerateOCRA() throws DecoderException {
		byte[] key = Hex.decodeHex("3132333435363738393031323334353637383930".toCharArray());
		
		String[] challengeCode = {"00000000", "11111111", "12345678", "87654321"};
		String ocraSuite = "OCRA-1:HOTP-SHA1-6:QN08";
		String otp;
		System.out.println("OCRASuite:" + ocraSuite);
		System.out.println("+-----------------+-----------+");
		System.out.println("|  challengeCode  |    OCRA   |");
		System.out.println("+-----------------+-----------+");
		for (int i = 0; i < challengeCode.length; i++) {
			otp = OTPApi.generateOCRA(ocraSuite, key, challengeCode[i], 0x00);
			System.out.println("|     " + challengeCode[i] + "    |  " + otp + "   |");
			System.out.println("+-----------------+-----------+");
		}
		
		ocraSuite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
		System.out.println("OCRASuite:" + ocraSuite);
		System.out.println("+-----------------+-----------+");
		System.out.println("|  challengeCode  |    OCRA   |");
		System.out.println("+-----------------+-----------+");
		for (int i = 0; i < challengeCode.length; i++) {
			otp = OTPApi.generateOCRA(ocraSuite, key, challengeCode[i], 0x00);
			System.out.println("|     " + challengeCode[i] + "    |  " + otp + " |");
			System.out.println("+-----------------+-----------+");
		}
	}
	
	@Test
	public void testAuthTOTP() throws DecoderException {
		byte[] key = Hex.decodeHex("3132333435363738393031323334353637383930".toCharArray());
		CryptoType cryptoType = CryptoType.HmacSHA1;
		int cycle = 60;
		int timeOffset = 0;
		int returnDigits = 0x06;
		int bigTimeWindow = 0x08;
		byte[] time = OTPApi.generateTime(cycle, timeOffset);
		String password = OTPApi.generateTOTP(key, time, returnDigits, cryptoType);
		
		logger.info("time:" + Hex.encodeHexString(time).toUpperCase() + ", password:" + password);
		Integer authResult = OTPApi.authTOTP(password, key, cycle, timeOffset, bigTimeWindow);
		
		logger.info("authResult:" + authResult);
		Assert.assertTrue(0x01 >= Math.abs(authResult));
	}

	@Test
	public void testAuthOCRA() throws DecoderException{
		byte[] key = Hex.decodeHex("3132333435363738393031323334353637383930".toCharArray());
		String ocraSuite = "OCRA-1:HOTP-SHA1-6:QN08-T1M";
		String challengeCode = RandomStringUtils.random(0x08, "1234567890");
		int timeOffset = 0;
		int bigTimeWindow = 0x08;
		String password = OTPApi.generateOCRA(ocraSuite, key, challengeCode, timeOffset);
		
		logger.info("challengeCode:" + challengeCode + ", password:" + password);
		Integer authResult = OTPApi.authOCRA(password, ocraSuite, key, challengeCode, timeOffset, bigTimeWindow);
		
		logger.info("authResult:" + authResult);
		Assert.assertTrue(0x01 >= Math.abs(authResult));
	}
}
