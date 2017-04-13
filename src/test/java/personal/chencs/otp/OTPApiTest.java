package personal.chencs.otp;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
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
		byte[] time = Hex.decodeHex("00000000023523EC".toCharArray());
		int returnDigits = 0x08;
		CryptoType cryptoType = CryptoType.HmacSHA1;
		logger.info("key:" + Hex.encodeHexString(key).toUpperCase() + ", time:" + Hex.encodeHexString(time).toUpperCase() + ", returnDigits:" + returnDigits + ", cryptoType:" + cryptoType);
		
		String otp = OTPApi.generateTOTP(key, time, returnDigits, cryptoType);
		
		logger.info("otp:" + otp);
		Assert.assertTrue("07081804".equals(otp));
	}
	
	@Test
	public void testAuthTOTP() throws DecoderException{
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

}
