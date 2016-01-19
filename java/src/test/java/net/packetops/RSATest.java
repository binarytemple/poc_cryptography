package net.packetops;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class RSATest {

	public static void main(String[] args) throws FileNotFoundException, InvalidKeySpecException, NoSuchAlgorithmException, IOException, ClassNotFoundException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchProviderException, SignatureException {
		RSATool tool = RSAToolFactory.getRSATool();
		tool.generateKeyPair(new File("public.pem"), new File("private.pem"));
//		byte[] input = "Hello World!".getBytes();
//
//		RSAKey publicKey = tool.loadPublicKey(new File("public.pem"));
//		RSAKey privateKey = tool.loadPrivateKey(new File("private.pem"));
//
//		byte[] encoded = tool.encryptWithKey(input, privateKey);
//		System.out.println("Encoded string: " + new String(encoded));
//
//		byte[] decoded = tool.decryptWithKey(encoded, publicKey);
//		System.out.println("Decoded string: " + new String(decoded));
		
		/*
		int php_encrypted_length = (int) (new File("php_encrypted.bin")).length();
		byte[] php_encrypted = new byte[php_encrypted_length];
		FileInputStream fis = new FileInputStream("php_encrypted.bin");
		fis.read(php_encrypted);
		fis.close();
		
		byte[] php_decoded = tool.decryptWithKey(php_encrypted, privateKey);
		System.out.println("Decoded string: " + new String(php_decoded));	
		
		int php_signature_length = (int) (new File("php_signature.bin")).length();
		byte[] php_signature = new byte[php_signature_length];
		fis = new FileInputStream("php_signature.bin");
		fis.read(php_signature);
		fis.close();
		
		System.out.println(tool.verifyWithKey("Hello World!".getBytes(), php_signature, publicKey));		
		*/
	}

}
