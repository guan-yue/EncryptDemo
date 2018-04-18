package guanyue.util;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESDemo {
	private static SecretKey kk = null;

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		String content = "hello你好";
		String key = "aaaaaaaa";//
		String iv = "abcdefghijklmnop";// 16字节的初始向量

		System.out.println(content);
		System.out.println("加密前：" + byteToHexString(content.getBytes()));
		byte[] encrypted = AES_CBC_Encrypt(content.getBytes(), key.getBytes(), iv.getBytes());
		System.out.println("加密后：" + byteToHexString(encrypted)); // 加密后数据不可强制转化成字符串
		byte[] decrypted = AES_CBC_Decrypt(encrypted, key.getBytes(), iv.getBytes());
		System.out.println("解密后：" + byteToHexString(decrypted));
		System.out.println(new String(decrypted));
	}

	/**
	 * 
	 * @param content
	 * @param keyBytes
	 * @param iv
	 * @return
	 */
	public static byte[] AES_CBC_Encrypt(byte[] content, byte[] keyBytes, byte[] iv) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128, new SecureRandom(keyBytes));
			SecretKey key = keyGenerator.generateKey(); // key长可设为128，192，256位，这里只能设为128
			kk = key;
			System.out.println(byteToHexString(key.getEncoded()));

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			byte[] result = cipher.doFinal(content);
			return result;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("exception:" + e.toString());
		}
		return null;
	}

	/**
	 * 
	 * @param content
	 * @param keyBytes
	 * @param iv
	 * @return
	 */
	public static byte[] AES_CBC_Decrypt(byte[] content, byte[] keyBytes, byte[] iv) {
		try {
			SecretKey key = kk;
			System.out.println(byteToHexString(key.getEncoded()));

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			byte[] result = cipher.doFinal(content);
			return result;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("exception:" + e.toString());
		}
		return null;
	}

	public static String byteToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer(bytes.length);
		String sTemp;
		for (int i = 0; i < bytes.length; i++) {
			sTemp = Integer.toHexString(0xFF & bytes[i]);
			if (sTemp.length() < 2)
				sb.append(0);
			sb.append(sTemp.toUpperCase());
		}
		return sb.toString();
	}
}