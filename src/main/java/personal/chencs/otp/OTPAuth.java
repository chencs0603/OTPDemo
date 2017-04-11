package personal.chencs.otp;

/**
 * OTP认证接口
 * @author chencs
 *
 */
public class OTPAuth {

	/**
	 * 时间型动态口令认证
	 * @param password 需要认证的动态口令
	 * @param key
	 * @param cycle
	 * @param timeOffset
	 * @param bigTimeWindow
	 * @return
	 */
	public static Integer authTOTP(String password, byte[] key, int cycle, int timeOffset, int bigTimeWindow){
		
		return null;
	}
	
	/**
	 * 挑战型动态口令认证
	 * @param password
	 * @param key
	 * @param cycle
	 * @param timeOffset
	 * @param challengeCode
	 * @param bigTimeWindow
	 * @return
	 */
	public static Integer authOCRA(String password, byte[] key, int cycle, int timeOffset, String challengeCode, int bigTimeWindow){
		
		return null;
	}
	
	/**
	 * 生成时间因子
	 * @param cycle 周期
	 * @param timeOffset 时间偏移
	 * @return 时间因子
	 */
	public static byte[] generateTime(int cycle, int timeOffset){
		
		return null;
	}
}
