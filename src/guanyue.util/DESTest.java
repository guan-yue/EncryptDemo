package guanyue.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class DESTest {
	public static void main(String[] args) {
		String content = "is张三丰";
		String key = "test中英文杂七烂八混搭@123654{";

		
		String res = encrypt(content, key);
		System.out.println(res);
		System.out.println(decrypt(res, key));
	}

	private static String encrypt(String content, String key) {
		// TODO Auto-generated method stub
		try {
			SecureRandom random = new SecureRandom();
			
			DESedeKeySpec keySpec = new DESedeKeySpec(key.getBytes());
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey secretKey = keyFactory.generateSecret(keySpec);

			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, random);

			return new String(Base64.getEncoder().encode(cipher.doFinal(content.getBytes())));
		} catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	private static String decrypt(String res, String key) {
		// TODO Auto-generated method stub
		try {
			SecureRandom random = new SecureRandom();
			DESedeKeySpec keySpec = new DESedeKeySpec(key.getBytes());
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey secretKey = keyFactory.generateSecret(keySpec);

			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, random);

			return new String(Base64.getEncoder().encode(cipher.doFinal(Base64.getDecoder().decode(res.getBytes()))));
		} catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
