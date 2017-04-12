package personal.chencs.otp;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;


public class OTPApiTest {

	@Test
	public void testTruncateHmac() throws DecoderException {
		byte[] hmac = Hex.decodeHex("1F8698690E02CA16618550EF7F19DA8E945B555A".toCharArray());
		int returnDigits = 0x06;
		
		String otp = OTPApi.truncateHmac(hmac, returnDigits);
		
		Assert.assertTrue("872921".equals(otp));
	}

}
