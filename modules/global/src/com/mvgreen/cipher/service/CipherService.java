package com.mvgreen.cipher.service;

public interface CipherService {
    String NAME = "cipher_CipherService";

    SymmetricAlgorithmService useSymmetric();

    AsymmetricAlgorithmService useAsymmetric();
}