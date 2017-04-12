package personal.chencs.otp;

import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

/**
 * OTP相关接口
 * @author chencs
 *
 */
public class OTPApi {
	private static Logger logger = LogManager.getLogger(OTPApi.class);
	
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
		//检测输入参数的合法性
		if(ArrayUtils.isEmpty(key)){
			logger.warn("key is invalid");
			throw new IllegalArgumentException("key is invalid");
		}
		if(ArrayUtils.isEmpty(time)){
			logger.warn("time is invalid");
			throw new IllegalArgumentException("time is invalid");
		}
		if(0x04 >= returnDigits || 0x08 < returnDigits){
			logger.warn("returnDigits is invalid--returnDigits:" + returnDigits);
			throw new IllegalArgumentException("returnDigits is invalid--returnDigits:" + returnDigits);
		}
		if(null == cryptoType){
			logger.warn("cryptoType is invalid");
			throw new IllegalArgumentException("cryptoType is invalid");
		}
		logger.debug("keyLen:" + key.length + ", timeLen:" + time.length + ", returnDigits:" + returnDigits + ", cryptoType:" + cryptoType);
		
		byte[] hmac = null;
		switch (cryptoType) {
		case HmacSHA1:
			hmac = HmacUtils.hmacSha1(key, time);
			break;
		case HmacSHA256:
			hmac = HmacUtils.hmacSha256(key, time);
			break;
		case HmacSHA512:
			hmac = HmacUtils.hmacSha512(key, time);
				break;
		default:
			break;
		}
		
		String otp = truncateHmac(hmac, returnDigits);
		
		logger.debug("otp:" + otp);
		return otp;
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
		//检测输入参数的合法性
		if(ArrayUtils.isEmpty(hmac) || hmac.length < 0x04){
			logger.warn("hmac is invalid");
			throw new IllegalArgumentException("hmac is invalid");
		}
		if(0x04 >= returnDigits || 0x08 < returnDigits){
			logger.warn("returnDigits is invalid--returnDigits:" + returnDigits);
			throw new IllegalArgumentException("returnDigits is invalid--returnDigits:" + returnDigits);
		}
		logger.debug("hmacLen:" + hmac.length + ", returnDigits:" + returnDigits);
		
		//取hmac数组的最后一个元素的低四位作为索引
		int offset = hmac[hmac.length - 0x01]&0x0F;
		//从offset开始取四字节，并去掉开头的符号位
		int binary = ((hmac[offset] & 0x7f) << 24) |
				((hmac[offset + 1] & 0xff) << 16) |
				((hmac[offset + 2] & 0xff) << 8) |
				(hmac[offset + 3] & 0xff);
		
		                        // 0  1  2    3     4     5       6      7        8
		final int[] digitsPower = {1,10,100,1000,10000,100000,1000000,10000000,100000000};
		int otp = binary % digitsPower[returnDigits];
		String result = Integer.toString(otp);
		//位数不够在前面0
		while (result.length() < returnDigits) {
			result = "0" + result;
		}
		logger.debug("result:" + result);
		return result;
	}

}
