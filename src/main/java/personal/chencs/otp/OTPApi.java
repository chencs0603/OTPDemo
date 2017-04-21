package personal.chencs.otp;

import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import personal.chencs.utils.MyByteUtils;

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
	 * 时间型动态口令认证
	 * @param password 需要认证的动态口令
	 * @param key
	 * @param cycle
	 * @param timeOffset
	 * @param bigTimeWindow
	 * @return
	 */
	public static Integer authTOTP(String password, byte[] key, int cycle, int timeOffset, int bigTimeWindow){
		//检测输入参数的合法性
		if (StringUtils.isBlank(password)) {
			logger.warn("password is invalid");
			throw new IllegalArgumentException("password is invalid");
		}
		if(ArrayUtils.isEmpty(key)){
			logger.warn("key is invalid");
			throw new IllegalArgumentException("key is invalid");
		}
		if(30 != cycle && 60 != cycle){
			logger.warn("cycle is invalid");
			throw new IllegalArgumentException("cycle is invalid--cycle:" + cycle);
		}
		if(0 >= bigTimeWindow){
			logger.warn("bigTimeWindow is invalid");
			throw new IllegalArgumentException("bigTimeWindow is invalid--bigTimeWindow:" + bigTimeWindow);
		}
		logger.debug("password:" + password + ", keyLen:" + key.length + ", cycle:" + cycle + ", timeOffset:" + timeOffset + ", bigTimeWindow:" + bigTimeWindow);
		
		String otp;
		byte[] time;
		int returnDigits = password.length();
		CryptoType cryptoType = CryptoType.HmacSHA1;
		for (int i = 0; i < bigTimeWindow; i++) {
			if(0 == i){
				time = generateTime(cycle, timeOffset);
				otp = generateTOTP(key, time, returnDigits, cryptoType);
				logger.debug("i:" + i + ", otp:" + otp);
				if(password.equals(otp)){
					return i;
				}
			}else{
				time = generateTime(cycle, timeOffset + i);
				otp = generateTOTP(key, time, returnDigits, cryptoType);
				logger.debug("i:" + i + ", otp:" + otp);
				if(password.equals(otp)){
					return i;
				}
				time = generateTime(cycle, timeOffset - i);
				otp = generateTOTP(key, time, returnDigits, cryptoType);
				logger.debug("i:" + i + ", otp:" + otp);
				if(password.equals(otp)){
					return -i;
				}
			}
		}
		
		return null;
	}
	
	/**
	 * 生成挑战型动态口令（只支持挑战码和时间两个因子）
	 * @param ocraSuite 包含算法、动态口令长度、挑战码长度等信息
	 * @param key 密钥
	 * @param challengeCode 挑战码
	 * @param timeOffset 时间偏移（单位是周期）
	 * @return 动态口令
	 */
	public static String generateOCRA(String ocraSuite, byte[] key, String challengeCode, int timeOffset){
		//检测输入参数的合法性
		if (StringUtils.isBlank(ocraSuite)) {
			logger.warn("ocraSuite is invalid");
			throw new IllegalArgumentException("ocraSuite is invalid");
		}
		if(ArrayUtils.isEmpty(key)){
			logger.warn("key is invalid");
			throw new IllegalArgumentException("key is invalid");
		}
		if (StringUtils.isBlank(challengeCode)) {
			logger.warn("challengeCode is invalid");
			throw new IllegalArgumentException("challengeCode is invalid");
		}
		
		//OCRASuite=<Algorithm>:<CryptoFunction>:<DataInput>
		String cryptoFunction = ocraSuite.split(":")[1];
		String dataInput = ocraSuite.split(":")[2];
		
		//解析算法信息，默认算法为HMAC-SHA1
		CryptoType cryptoType = CryptoType.HmacSHA1;
		if(cryptoFunction.indexOf("SHA1") > 1)
			cryptoType = CryptoType.HmacSHA1;
		if(cryptoFunction.indexOf("SHA256") > 1)
			cryptoType = CryptoType.HmacSHA256;
		if(cryptoFunction.indexOf("SHA512") > 1)
			cryptoType = CryptoType.HmacSHA512;
		//解析动态口令长度，只支持4-8位的动态口令,默认长度为6
		int returnDigits = Integer.parseInt(cryptoFunction.substring(
				cryptoFunction.lastIndexOf("-")+1));
		if(0x04 > returnDigits || 0x08 < returnDigits){
			returnDigits = 0x06;
		}
		
		//暂支持Q、T两种因子，其中挑战码是必备因子
		if(!(dataInput.startsWith("Q") ||(dataInput.contains("-") && dataInput.split("-")[0].indexOf("Q") > 0))){
			logger.warn("the ocraSuite is invalid");
			throw new IllegalArgumentException("the ocraSuite is invalid");
		}
		//解析挑战码，只支持数字和字母
		byte[] question = new byte[0x80];
		int maxQuestionLen = Integer.parseInt(dataInput.split("-")[0].substring(0x02));
		byte[] challengeCodeBytes = challengeCode.getBytes();
		if(0x04 > maxQuestionLen || 0x40 < maxQuestionLen || challengeCodeBytes.length > maxQuestionLen){
			logger.warn("challengeCodeLen or ocraSuite is invalid");
			throw new IllegalArgumentException("challengeCodeLen or ocraSuite is invalid");
		}
		System.arraycopy(challengeCodeBytes, 0x00, question, 0x00, challengeCodeBytes.length);
		
		//解析时间周期(单位是秒)
		int cycle = 0;
		byte[] time = null;
		int timeLen = 0x00;
		if(dataInput.startsWith("T") ||
				(dataInput.indexOf("-T") >= 0)) {
			int num = Integer.decode(dataInput.split("-")[1].substring(0x01, 0x02));
			char timeUnit = dataInput.split("-")[1].charAt(0x02);
			switch (timeUnit) {
			case 'S':
				cycle = num;
				break;
			case 'M':
				cycle = 60 * num;
				break;
			case 'H':
				cycle = 3600 * num;
				break;
			default:
				cycle = 60;
				break;
			}
			time = generateTime(cycle, timeOffset);
			timeLen = time.length;
		} else{
			//没有时间因子
			timeLen = 0x00;
		}
		
		byte[] ocraSuiteBytes = ocraSuite.getBytes();
		int ocraSuiteBytesLen = ocraSuiteBytes.length;
		//拼接数据：ocraSuite || 0x00 || question || time
		byte[] msg = new byte[ocraSuiteBytesLen + 0x01 + question.length + timeLen];
		System.arraycopy(ocraSuiteBytes, 0x00, msg, 0x00, ocraSuiteBytesLen);
		msg[ocraSuiteBytesLen] = 0x00;
		System.arraycopy(question, 0x00, msg, ocraSuiteBytesLen + 0x01, question.length);
		if (0x00 != timeLen) {
			System.arraycopy(time, 0x00, msg, ocraSuiteBytesLen + 0x01 + question.length, timeLen);
		}
		byte[] hmac = null;
		switch (cryptoType) {
		case HmacSHA1:
			hmac = HmacUtils.hmacSha1(key, msg);
			break;
		case HmacSHA256:
			hmac = HmacUtils.hmacSha256(key, msg);
			break;
		case HmacSHA512:
			hmac = HmacUtils.hmacSha512(key, msg);
				break;
		default:
			break;
		}
		
		String otp = truncateHmac(hmac, returnDigits);
		
		logger.debug("otp:" + otp);
		return otp;
	}
	
	/**
	 * 截位算法（用于生成动态口令）
	 * @param hmac mac值
	 * @param returnDigits 动态口令长度 (只支持4-8位)
	 * @return 动态口令
	 */
	public static String truncateHmac(byte[] hmac, int returnDigits){
		//检测输入参数的合法性
		if(ArrayUtils.isEmpty(hmac) || hmac.length < 0x04){
			logger.warn("hmac is invalid");
			throw new IllegalArgumentException("hmac is invalid");
		}
		if(0x04 > returnDigits || 0x08 < returnDigits){
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
	
	/**
	 * 生成时间因子
	 * @param cycle 周期(单位是秒)
	 * @param timeOffset 时间偏移(单位是周期)
	 * @return 时间因子
	 */
	public static byte[] generateTime(int cycle, int timeOffset){
		//检测输入参数的合法性
		if(30 != cycle && 60 != cycle){
			logger.warn("cycle is invalid");
			throw new IllegalArgumentException("cycle is invalid--cycle:" + cycle);
		}
		
		long timestamp = System.currentTimeMillis();
		long time = timestamp/(cycle*1000) + timeOffset;
		
		return MyByteUtils.longToBytes(time, true);
	}

}
