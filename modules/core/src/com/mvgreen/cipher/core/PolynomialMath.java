package com.mvgreen.cipher.core;

import org.springframework.stereotype.Component;

@Component(PolynomialMath.NAME)
public class PolynomialMath {
    public static final String NAME = "cipher_PolynomialMath";

    // Таблицы логарифмов по основанию (x ^ 1) для быстрого умножения через сложение
    protected final byte[] LOG_TABLE;
    protected final byte[] INV_LOG_TABLE;
    {
        LOG_TABLE = new byte[256];
        INV_LOG_TABLE = new byte[256];
        calculateLogTables();
    }

    // Вспомогательная функция для генерации таблиц логарифмов по основанию (x ^ 1)
    private void calculateLogTables() {
        INV_LOG_TABLE[0] = 1;
        LOG_TABLE[0] = 0;

        for (int i = 1; i < 256; i++) {
            INV_LOG_TABLE[i] = multiplyByOnePlusX(INV_LOG_TABLE[i - 1]);
            LOG_TABLE[Byte.toUnsignedInt(INV_LOG_TABLE[i])] = (byte) i;
        }

        LOG_TABLE[1] = 0;
    }

    // Произведение многочленов 7 степени (коэффициенты которых представлены соответствующими степени битами) по модулю (x.pow(8) ^ x.pow(4) ^ x.pow(3) ^ x ^ 1)
    public byte multiplyPolynomials(byte a, byte b) {
        if ((a != 0) && (b != 0))
            return INV_LOG_TABLE[((Byte.toUnsignedInt(LOG_TABLE[Byte.toUnsignedInt(a)]) + Byte.toUnsignedInt(LOG_TABLE[Byte.toUnsignedInt(b)])) % 255)];
        else
            return 0;
    }

    // Умножение b * (x ^ 1) по модулю (x.pow(8) ^ x.pow(4) ^ x.pow(3) ^ x ^ 1)
    private byte multiplyByOnePlusX(byte b) {
        return (byte) (multiplyByX(b) ^ b);
    }

    // Умножение b * x по модулю (x.pow(8) ^ x.pow(4) ^ x.pow(3) ^ x ^ 1)
    private byte multiplyByX(byte b) {
        byte top = (byte) ((b << 1) & 0xff);
        boolean highBitSet = (b & 0x80) == 0x80;
        byte bottom = (byte) (highBitSet ? 0x1b : 0);

        return (byte) (top ^ bottom);
    }
}