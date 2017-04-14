package personal.chencs.otp;

import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import personal.chencs.otp.OTPApi.CryptoType;

//(1)步骤一：测试类指定特殊的运行器org.junit.runners.Parameterized
@RunWith(Parameterized.class)
public class OTPApiTest {
	private static Logger logger = LogManager.getLogger(OTPApiTest.class);
	
	// (2)步骤二：为测试类声明几个变量，分别用于存放期望值和测试所用数据。
	private String hexTime;
	private String otp;
	// (3)步骤三：为测试类声明一个带有参数的公共构造函数，并在其中为第二个环节中声明的几个变量赋值。 
	public OTPApiTest(String hexTime, String otp)
    {
        // 构造方法
        // JUnit会使用准备的测试数据传给构造函数
        this.hexTime = hexTime;
        this.otp = otp;
    }
	// (4)步骤四：为测试类声明一个使用注解 org.junit.runners.Parameterized.Parameters修饰的，返回值为  
    // java.util.Collection 的公共静态方法，并在此方法中初始化所有需要测试的参数对。
	@SuppressWarnings("rawtypes")
	@Parameters
    public static Collection prepareData()
    {
        // 测试数据
        Object[][] objects = { {"0000000000000001", "94287082"}, {"00000000023523EC", "07081804"},
        		{"00000000023523ED", "14050471"}, {"000000000273EF07", "89005924"}, 
        		{"0000000003F940AA", "69279037"}, {"0000000027BC86AA", "65353130"}};
        return Arrays.asList(objects);// 将数组转换成集合返回

    }
	
	
	@Test
	public void testGenerateTOTPSHA1() throws DecoderException{
		byte[] key = Hex.decodeHex("3132333435363738393031323334353637383930".toCharArray());
		// (5)步骤五：编写测试方法，使用定义的变量作为参数进行测试。  
		Assert.assertEquals(this.otp, OTPApi.generateTOTP(key, Hex.decodeHex(this.hexTime.toCharArray()), 0x08, CryptoType.HmacSHA1));
	}
	
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
