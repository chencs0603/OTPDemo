package personal.chencs.utils;

/**
 * Byte数组相关的工具类
 * @author chencs
 *
 */
public class ByteUtils {
	/**
	 * long转成8字节byte数组
	 * @param num
	 * @return
	 */
	public static byte[] longToBytes(long num) {
        byte[] targets = new byte[0x08];
        for (int i = 0; i < 8; i++) {
            int offset = (targets.length - 1 - i) * 8;
            targets[i] = (byte) ((num >>> offset) & 0xff);
        }
        return targets;
    }
}
