package personal.chencs.otp;

/**
 * OTP相关接口
 * @author chencs
 *
 */
public class OTPApi {
	
	/**
	 * 算法类型（包括HmacSHA1、HmacSHA256、HmacSHA512）
	 * @author chencs
	 *
	 */
	enum CryptoType {
		HmacSHA1, HmacSHA256, HmacSHA512 
	}
	
	/**
	 * 生成时间型动态口令
	 * @param key 令牌种子密钥
	 * @param time 时间因子
	 * @param returnDigits 动态口令长度
	 * @param cryptoType 算法类型
	 * @return 动态口令
	 */
	public static String generateTOTP(byte[] key, byte[] time, int returnDigits, CryptoType cryptoType){
		
		return null;
	}
	
	/**
	 * 生成挑战型动态口令
	 * @param key 令牌种子密钥
	 * @param time 时间因子
	 * @param challengeCode 挑战码
	 * @param returnDigits 动态口令长度 
	 * @param cryptoType 算法类型
	 * @return  动态口令长度
	 */
	public static String generateOCRA(byte[] key, byte[] time, byte[] challengeCode, int returnDigits, CryptoType cryptoType){
		
		return null;
	}
	
	/**
	 * 截位算法（用于生成动态口令）
	 * @param hmac mac值
	 * @param returnDigits 动态口令长度 
	 * @return 动态口令
	 */
	public static String truncateHmac(byte[] hmac, int returnDigits){
		
		return null;
	}

}
