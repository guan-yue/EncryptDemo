package guanyue.util;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*-
 * 1、 加密还是解密。
 * 
 * 只需要在Cypher.init初始化时设置Mode即可，即Cypher.ENCRYPT 或 Cypher.DECRYPT。
 * 
 * 2、 秘钥的产生。
 * 
 * 这个有点恶心， 我研究了一下 KeyGenerator，
 * KeyPairGenerator，KeyFactory，SecretKeyFactory这四个类，是有区别的。
 * 
 * 根据 Oracle 的 Standard Algorithm Name Documentation 提供的说明：
 * 
 * KeyGenerator和SecretKeyFactory，都是javax.crypto包的，
 * 生成的key主要是提供给AES，DES，3DES，MD5，SHA1等 对称 和 单向 加密算法。
 * 
 * KeyPairGenerator和KeyFactory，都是java.security包的， 生成的key主要是提供给DSA，RSA， EC等
 * 非对称加密算法。
 * 
 * 3、块加密的模式以及数据填充。
 * 
 * Cipher加密器初始化需要一个字符串，字符串里提供了三种设置。 一是，加解密算法；二是，加解密模式；三是，是否需要填充。
 * 
 * 常见的模式有四种： ECB（电码本模式），CBC（加密块链模式），OFB（输出反馈模式），CFB（加密反馈模式）
 * ECB模式简单，缺点是块加密的内容容易重复，会被统计分析攻击；
 * 
 * CBC, OFB, CFB三个模式，都是根据前面加密块的内容，对key进行新一轮处理后，
 * 再对下一数据块进行处理，如此类推下去，这样一来，加密的强度也有所增强，他们都需要用到初始化向量IV（8字节）！
 * 
 * @author Guan Yue
 * @time 2018年1月9日下午7:47:21
 *
 */
public class DESDemo {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		String content = "aaaaaaaabbbbbbbbaaaaaaaaa你好";
		String key = "01234567891011";// must be 8 bytes !

		System.out.println(content);
		System.out.println("加密前：" + byteToHexString(content.getBytes()));
		byte[] encrypted = DES_CBC_Encrypt(content.getBytes(), key.getBytes());
		System.out.println("加密后：" + byteToHexString(encrypted));
		byte[] decrypted = DES_CBC_Decrypt(encrypted, key.getBytes());
		System.out.println("解密后：" + byteToHexString(decrypted));
		System.out.println(new String(decrypted));

		generateKey(key.getBytes());
	}

	/**
	 * 三种生成秘密密钥的方式： 方式二比较好，方式三最差！
	 * 
	 * @param keyBytes
	 */
	private static void generateKey(byte[] keyBytes) {
		// TODO Auto-generated method stub
		try {
			// 第一种，Factory
			DESKeySpec keySpec = new DESKeySpec(keyBytes);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey key1 = keyFactory.generateSecret(keySpec);

			// 第二种, Generator
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
			keyGenerator.init(56, new SecureRandom(keyBytes));// key为8个字节，实际用了56位； 后面随机数用key作为种子seed生成
			SecretKey key2 = keyGenerator.generateKey();

			// 第三种， SecretKeySpec
			//// 输入必须为8字节，原始密码未作替换！！！
			SecretKey key3 = new SecretKeySpec(keyBytes, "DES");// SecretKeySpec类同时实现了Key和KeySpec接口

			// 打印
			System.out.println("key1：" + byteToHexString(key1.getEncoded()));
			System.out.println("key2：" + byteToHexString(key2.getEncoded()));
			System.out.println("key3：" + byteToHexString(key3.getEncoded()));

		} catch (Exception e) {
			System.out.println(e.toString());
		}
	}

	public static byte[] DES_CBC_Encrypt(byte[] content, byte[] keyBytes) {
		try {
			DESKeySpec keySpec = new DESKeySpec(keyBytes);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey key = keyFactory.generateSecret(keySpec);

			System.out.println("IV:   " + byteToHexString(keySpec.getKey()));
			Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(keySpec.getKey()));
			byte[] result = cipher.doFinal(content);
			return result;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("exception:" + e.toString());
		}
		return null;
	}

	public static byte[] DES_CBC_Decrypt(byte[] content, byte[] keyBytes) {
		try {
			DESKeySpec keySpec = new DESKeySpec(keyBytes);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey key = keyFactory.generateSecret(keySpec);

			System.out.println("IV:   " + byteToHexString(keySpec.getKey()));
			Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(keySpec.getKey()));
			byte[] result = cipher.doFinal(content);
			return result;
		} catch (Exception e) {
			// TODO Auto-generated catch block
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