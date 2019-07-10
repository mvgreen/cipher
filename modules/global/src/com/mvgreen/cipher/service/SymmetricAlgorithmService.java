package com.mvgreen.cipher.service;

import com.mvgreen.cipher.entity.CipherData;

public interface SymmetricAlgorithmService {
    String NAME = "cipher_SymmetricAlgorithmService";

    byte[] generatePrivateKey();

    byte[] encryptData(CipherData data);

    String decryptData(CipherData data);
}