package personal.chencs.utils;

/**
 * Byte数组相关的工具类
 * @author chencs
 *
 */
public class MyByteUtils {
	/**
	 * long整数转成8字节byte数组（支持大小端两种模式）
	 * @param num
	 * @param bigEndian true：大端模式，false：小端模式
	 * @return
	 */
	public static byte[] longToBytes(long num, boolean bigEndian) {
        byte[] bytes = new byte[0x08];
        if (bigEndian) {
        	//大端模式
			for (int i = 0; i < 0x08; i++) {
	            int offset = (bytes.length - 1 - i) * 8;
	            bytes[i] = (byte) (num >>> offset);
			}
		}else{
			//小端模式
			for (int i = 0; i < 0x08; i++) {
	            int offset = (1 + i) * 8;
	            bytes[i] = (byte) (num >>> offset);
			}
		}
        
        return bytes;
    }
}
