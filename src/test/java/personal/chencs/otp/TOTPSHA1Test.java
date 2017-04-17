package personal.chencs.otp;

import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import personal.chencs.otp.OTPApi.CryptoType;

//(1)步骤一：测试类指定特殊的运行器org.junit.runners.Parameterized
@RunWith(Parameterized.class)
public class TOTPSHA1Test {
	
	// (2)步骤二：为测试类声明几个变量，分别用于存放期望值和测试所用数据。
	private String hexTime;
	private String otp;
	
	// (3)步骤三：为测试类声明一个带有参数的公共构造函数，并在其中为第二个环节中声明的几个变量赋值。 
	public TOTPSHA1Test(String hexTime, String otp)
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

}
