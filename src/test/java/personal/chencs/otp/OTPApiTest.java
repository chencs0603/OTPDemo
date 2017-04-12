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
		byte[] key = Hex.decodeHex("03AECB998837F80FF158E57452B91ECE6EE3ABDB".toCharArray());
		byte[] time = Hex.decodeHex("0000000001771A28".toCharArray());
		int returnDigits = 0x06;
		CryptoType cryptoType = CryptoType.HmacSHA1;
		logger.info("key:" + Hex.encodeHexString(key).toUpperCase() + ", time:" + Hex.encodeHexString(time).toUpperCase() + ", returnDigits:" + returnDigits + ", cryptoType:" + cryptoType);
		
		String otp = OTPApi.generateTOTP(key, time, returnDigits, cryptoType);
		
		logger.info("otp:" + otp);
		Assert.assertTrue("027388".equals(otp));
	}

}
