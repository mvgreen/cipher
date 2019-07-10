package com.mvgreen.cipher.service;

import com.mvgreen.cipher.entity.CipherData;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Service(AsymmetricAlgorithmService.NAME)
public class AsymmetricAlgorithmServiceBean implements AsymmetricAlgorithmService {

    private Cipher rsa;
    private KeyFactory keyFactory;

    @Override
    public byte[][] generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        return new byte[][] {
                pair.getPrivate().getEncoded(), pair.getPublic().getEncoded()
        };
    }

    @Override
    public byte[] encryptData(CipherData data) throws GeneralSecurityException {
        if (data == null)
            throw new IllegalArgumentException("data must not be null");
        if (data.getPublicKey() == null)
            throw new IllegalArgumentException("data.publicKey must not be null");
        if (data.getFirstname() == null || data.getFirstname().isEmpty())
            throw new IllegalArgumentException("data.firstName must be a non-null non-empty string");
        if (data.getLastname() == null || data.getLastname().isEmpty())
            throw new IllegalArgumentException("data.lastName must be a non-null non-empty string");
        if (data.getCompany() == null || data.getCompany().isEmpty())
            throw new IllegalArgumentException("data.company must be a non-null non-empty string");

        initRsa();

        rsa.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(new X509EncodedKeySpec(data.getPublicKey())));

        byte[] input = (data.getFirstname() + " " + data.getLastname() + " " + data.getCompany()).getBytes();

        return rsa.doFinal(input);
    }

    @Override
    public String decryptData(CipherData data) throws GeneralSecurityException{
        if (data == null)
            throw new IllegalArgumentException("data must not be null");
        if (data.getPrivateKey() == null)
            throw new IllegalArgumentException("data.privateKey must not be null");

        initRsa();

        rsa.init(Cipher.DECRYPT_MODE, keyFactory.generatePrivate(new PKCS8EncodedKeySpec(data.getPrivateKey())));

        byte[] output = rsa.doFinal(data.getEncrypted());
        return new String(output);
    }

    private void initRsa() throws NoSuchPaddingException, NoSuchAlgorithmException {
        if (rsa == null)
            rsa = Cipher.getInstance("RSA");
        if (keyFactory == null)
            keyFactory = KeyFactory.getInstance("RSA");
    }

}