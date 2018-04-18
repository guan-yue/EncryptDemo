package guanyue.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加密算法实现
 * 
 * @author Guan Yue
 * @time 2018年1月6日下午4:18:51
 *
 */
public class AESTest {
	private static SecretKey kk = null;

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			String content = "你好吗？";
			System.out.println("加密前：" + content);

			String key = "123456";
			System.out.println("加密密钥和解密密钥：" + key);

			byte[] encrypt = aesEncrypt(content, key);
			System.out.println("加密后：" + bytesToHex(encrypt));

			String decrypt = aesDecrypt(encrypt, key);
			System.out.println("解密后：" + decrypt);

		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			// TODO: handle finally clause
		}
	}

	/**
	 * 
	 * @param buff
	 *            待转化的字节数组
	 * @return
	 */
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

	/**
	 * 
	 * @param content
	 *            加密内容
	 * @param encryptKey
	 *            加密密钥
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	private static byte[] aesEncrypt(String content, String encryptKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		// TODO Auto-generated method stub
		return base64Encode(aesEncryptToBytes(content.getBytes("utf-8"), encryptKey));
	}

	/**
	 * 
	 * @param decryptBytes
	 *            解密内容
	 * @param decryptKey
	 *            解密密钥
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	private static String aesDecrypt(byte[] decryptBytes, String decryptKey)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		// TODO Auto-generated method stub
		return decryptBytes == null ? null : aesDecryptByBytes(base64Decode(decryptBytes), decryptKey);
	}

	/**
	 * 
	 * @param encryptBytes
	 *            加密内容
	 * @param encryptKey
	 *            加密密钥
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	private static byte[] aesEncryptToBytes(byte[] encryptBytes, String encryptKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		// TODO Auto-generated method stub
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128, new SecureRandom(encryptKey.getBytes("utf-8")));
		kk = new SecretKeySpec(kgen.generateKey().getEncoded(), "AES");

		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, kk);

		return cipher.doFinal(encryptBytes);
	}

	/**
	 * 
	 * @param decryptBytes
	 *            解密内容
	 * @param decryptKey
	 *            解密密钥
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	private static String aesDecryptByBytes(byte[] decryptBytes, String decryptKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		// TODO Auto-generated method stub
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, kk);
		byte[] res = cipher.doFinal(decryptBytes);

		return new String(res, "utf-8");
	}

	/**
	 * 
	 * @param bytes
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	private static byte[] base64Encode(byte[] bytes) throws UnsupportedEncodingException {
		// TODO Auto-generated method stub
		return Base64.getEncoder().encode(bytes);
	}

	/**
	 * 
	 * @param base64Code
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	private static byte[] base64Decode(byte[] base64Code) throws UnsupportedEncodingException {
		// TODO Auto-generated method stub
		return base64Code == null ? null : Base64.getDecoder().decode(base64Code);// new
	}

}
