package com.mvgreen.cipher.service;

import com.mvgreen.cipher.entity.CipherData;

import java.security.GeneralSecurityException;

public interface AsymmetricAlgorithmService {
    String NAME = "cipher_AsymmetricAlgorithmService";

    byte[][] generateKeyPair() throws GeneralSecurityException;

    byte[] encryptData(CipherData data) throws GeneralSecurityException;

    String decryptData(CipherData data) throws GeneralSecurityException;
}