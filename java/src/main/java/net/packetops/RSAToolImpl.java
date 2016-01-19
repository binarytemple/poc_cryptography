package net.packetops;


import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.x509.Certificate;

public class RSAToolImpl implements RSATool {

    @Override
    public void generateKeyPair(File publicKeyFile, File privateKeyFile) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048, random);

        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();





//        X509Certificate s = new X509CertificateObject();




        JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(publicKeyFile));
        writer.writeObject(pubKey);
        writer.close();

        JcaPEMWriter privWriter = new JcaPEMWriter(new FileWriter(privateKeyFile));
        privWriter.writeObject(pair);
        privWriter.close();
    }

    @Override
    public RSAKey loadPublicKey(File file) throws FileNotFoundException, IOException, ClassNotFoundException, InvalidKeySpecException, NoSuchAlgorithmException {
        PEMParser reader = new PEMParser(new FileReader(file));
        Key pubKey = (Key) reader.readObject();
        reader.close();
        return new RSAKeyImpl(pubKey);
    }

    @Override
    public RSAKey loadPrivateKey(File file) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        PEMParser reader = new PEMParser(new FileReader(file));
        KeyPair pair = (KeyPair) reader.readObject();
        Key privKey = (Key) pair.getPrivate();
        reader.close();
        return new RSAKeyImpl(privKey);
    }

    @Override
    public byte[] encryptWithKey(byte[] input, RSAKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, ((RSAKeyImpl) key).getKey(),
                new SecureRandom());
        return cipher.doFinal(input);
    }

    @Override
    public byte[] decryptWithKey(byte[] input, RSAKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, ((RSAKeyImpl) key).getKey());
        return cipher.doFinal(input);
    }

    @Override
    public byte[] signWithKey(byte[] input, RSAKey key)
            throws NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign((PrivateKey) ((RSAKeyImpl) key).getKey(),
                new SecureRandom());
        signature.update(input);
        return signature.sign();
    }

    @Override
    public boolean verifyWithKey(byte[] input, byte[] sig, RSAKey key) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify((PublicKey) ((RSAKeyImpl) key).getKey());
        signature.update(input);
        return signature.verify(sig);
    }

}
