package guanyue.util;

import java.security.MessageDigest;

/**
 * @author Guan Yue
 * @time 2018年1月6日下午3:46:13
 *
 */
public class MD5Test {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String content = "Hello World !";
		System.out.println(md5(content));
	}

	private static String md5(String content) {
		// TODO Auto-generated method stub
		String md5str = "";
		try {
			// 1 创建一个提供信息摘要算法的对象，初始化为md5算法对象
			MessageDigest md = MessageDigest.getInstance("MD5");

			// 2 将消息变成byte数组
			byte[] passwdbytes = content.getBytes("utf-8");

			// 3 计算后获得字节数组,这就是那128位了
			byte[] buff = md.digest(passwdbytes);

			// 4 把数组每一字节（一个字节占八位）换成16进制连成md5字符串
			md5str = bytesToHex(buff);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return md5str;
	}

	private static String bytesToHex(byte[] buff) {
		// TODO Auto-generated method stub
		StringBuffer md5str = new StringBuffer();
		// 把数组每一字节换成16进制连成md5字符串
		int digital;
		for (int i = 0; i < buff.length; i++) {
			digital = buff[i];
			if (digital < 0) {
				digital = digital & 0xff;// 符号扩展，最高位是1表负数！ 转16进制，高位取反即可。
				// digital += 256;
			}
			if (digital < 16) {
				md5str.append("0");
			}
			md5str.append(Integer.toHexString(digital));
		}
		return md5str.toString();
	}

}
