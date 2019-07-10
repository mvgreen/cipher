package com.mvgreen.cipher.service;

import com.mvgreen.cipher.core.PolynomialMath;
import com.mvgreen.cipher.entity.CipherData;
import org.springframework.stereotype.Service;

import javax.inject.Inject;
import java.util.Random;

@Service(SymmetricAlgorithmService.NAME)
public class SymmetricAlgorithmServiceBean implements SymmetricAlgorithmService {

    @Inject
    PolynomialMath polynomialMath;

    // Количество 32-битных слов в блоке
    private static final int WORD_COUNT = 4;
    // Количество циклов
    private static final int ROUND_COUNT = 10;
    // Количество 32-битных слов в ключе
    private static final int KEY_WORD_COUNT = 4;


    // Таблица нелинейной замены байтов
    private static final byte[][] S_BOX = new byte[][]{
            {0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5, 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, 0x76},
            {(byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, 0x72, (byte) 0xc0},
            {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte) 0xcc, 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15},
            {0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96, 0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2, 0x75},
            {0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0, 0x52, 0x3b, (byte) 0xd6, (byte) 0xb3, 0x29, (byte) 0xe3, 0x2f, (byte) 0x84},
            {0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc, (byte) 0xb1, 0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe, 0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf},
            {(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, 0x43, 0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f, 0x50, 0x3c, (byte) 0x9f, (byte) 0xa8},
            {0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2},
            {(byte) 0xcd, 0x0c, 0x13, (byte) 0xec, 0x5f, (byte) 0x97, 0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a, (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee, (byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb},
            {(byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79},
            {(byte) 0xe7, (byte) 0xc8, 0x37, 0x6d, (byte) 0x8d, (byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56, (byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08},
            {(byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, 0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
            {0x70, 0x3e, (byte) 0xb5, 0x66, 0x48, 0x03, (byte) 0xf6, 0x0e, 0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, 0x1d, (byte) 0x9e},
            {(byte) 0xe1, (byte) 0xf8, (byte) 0x98, 0x11, 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55, 0x28, (byte) 0xdf},
            {(byte) 0x8c, (byte) 0xa1, (byte) 0x89, 0x0d, (byte) 0xbf, (byte) 0xe6, 0x42, 0x68, 0x41, (byte) 0x99, 0x2d, 0x0f, (byte) 0xb0, 0x54, (byte) 0xbb, 0x16}
    };

    // Таблица обратной замены байтов
    private static final byte[][] INV_S_BOX = new byte[][]{
            {0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36, (byte) 0xa5, 0x38, (byte) 0xbf, 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
            {0x7c, (byte) 0xe3, 0x39, (byte) 0x82, (byte) 0x9b, 0x2f, (byte) 0xff, (byte) 0x87, 0x34, (byte) 0x8e, 0x43, 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
            {0x54, 0x7b, (byte) 0x94, 0x32, (byte) 0xa6, (byte) 0xc2, 0x23, 0x3d, (byte) 0xee, 0x4c, (byte) 0x95, 0x0b, 0x42, (byte) 0xfa, (byte) 0xc3, 0x4e},
            {0x08, 0x2e, (byte) 0xa1, 0x66, 0x28, (byte) 0xd9, 0x24, (byte) 0xb2, 0x76, 0x5b, (byte) 0xa2, 0x49, 0x6d, (byte) 0x8b, (byte) 0xd1, 0x25},
            {0x72, (byte) 0xf8, (byte) 0xf6, 0x64, (byte) 0x86, 0x68, (byte) 0x98, 0x16, (byte) 0xd4, (byte) 0xa4, 0x5c, (byte) 0xcc, 0x5d, 0x65, (byte) 0xb6, (byte) 0x92},
            {0x6c, 0x70, 0x48, 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, 0x5e, 0x15, 0x46, 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
            {(byte) 0x90, (byte) 0xd8, (byte) 0xab, 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, 0x0a, (byte) 0xf7, (byte) 0xe4, 0x58, 0x05, (byte) 0xb8, (byte) 0xb3, 0x45, 0x06},
            {(byte) 0xd0, 0x2c, 0x1e, (byte) 0x8f, (byte) 0xca, 0x3f, 0x0f, 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, 0x03, 0x01, 0x13, (byte) 0x8a, 0x6b},
            {0x3a, (byte) 0x91, 0x11, 0x41, 0x4f, 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, 0x73},
            {(byte) 0x96, (byte) 0xac, 0x74, 0x22, (byte) 0xe7, (byte) 0xad, 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, 0x37, (byte) 0xe8, 0x1c, 0x75, (byte) 0xdf, 0x6e},
            {0x47, (byte) 0xf1, 0x1a, 0x71, 0x1d, 0x29, (byte) 0xc5, (byte) 0x89, 0x6f, (byte) 0xb7, 0x62, 0x0e, (byte) 0xaa, 0x18, (byte) 0xbe, 0x1b},
            {(byte) 0xfc, 0x56, 0x3e, 0x4b, (byte) 0xc6, (byte) 0xd2, 0x79, 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, 0x78, (byte) 0xcd, 0x5a, (byte) 0xf4},
            {0x1f, (byte) 0xdd, (byte) 0xa8, 0x33, (byte) 0x88, 0x07, (byte) 0xc7, 0x31, (byte) 0xb1, 0x12, 0x10, 0x59, 0x27, (byte) 0x80, (byte) 0xec, 0x5f},
            {0x60, 0x51, 0x7f, (byte) 0xa9, 0x19, (byte) 0xb5, 0x4a, 0x0d, 0x2d, (byte) 0xe5, 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
            {(byte) 0xa0, (byte) 0xe0, 0x3b, 0x4d, (byte) 0xae, 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, 0x3c, (byte) 0x83, 0x53, (byte) 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, (byte) 0xba, 0x77, (byte) 0xd6, 0x26, (byte) 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

    // Константы для первых 10 раундов
    // R_CONST[0] никогда не применяется и нужен только для более читабельного кода
    private static final byte[][] R_CONST = new byte[][]{
            {0x00, 0x00, 0x00, 0x00},
            {0x01, 0x00, 0x00, 0x00},
            {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00},
            {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00},
            {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00},
            {(byte) 0x80, 0x00, 0x00, 0x00},
            {0x1b, 0x00, 0x00, 0x00},
            {0x36, 0x00, 0x00, 0x00}
    };

    // Константы для процедуры смешивания байтов в словах
    private static final byte[][] MIX_CONST = new byte[][]{
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
    };

    // Константы для процедуры возвращения байтов в словах в исходное состояние
    private static final byte[][] INV_MIX_CONST = new byte[][]{
            {0x0e, 0x0b, 0x0d, 0x09},
            {0x09, 0x0e, 0x0b, 0x0d},
            {0x0d, 0x09, 0x0e, 0x0b},
            {0x0b, 0x0d, 0x09, 0x0e},
    };

    @Override
    public byte[] generatePrivateKey() {
        byte[] key = new byte[16];
        Random random = new Random(System.currentTimeMillis());
        random.nextBytes(key);
        return key;
    }

    @Override
    public byte[] encryptData(CipherData data) {
        if (data == null)
            throw new IllegalArgumentException("data must not be null");
        if (data.getPrivateKey() == null || data.getPrivateKey().length != 16)
            throw new IllegalArgumentException("data.privateKey must be a 16-bite array");
        if (data.getFirstname() == null || data.getFirstname().isEmpty())
            throw new IllegalArgumentException("data.firstName must be a non-null non-empty string");
        if (data.getLastname() == null || data.getLastname().isEmpty())
            throw new IllegalArgumentException("data.lastName must be a non-null non-empty string");
        if (data.getCompany() == null || data.getCompany().isEmpty())
            throw new IllegalArgumentException("data.company must be a non-null non-empty string");

        byte[] input = (data.getFirstname() + " " + data.getLastname() + " " + data.getCompany()).getBytes();

        return encryptArray(input, data.getPrivateKey());
    }

    @Override
    public String decryptData(CipherData data) {
        if (data == null)
            throw new IllegalArgumentException("data must not be null");
        if (data.getPrivateKey() == null || data.getPrivateKey().length != 16)
            throw new IllegalArgumentException("data.privateKey must be a 16-bite array");
        if (data.getEncrypted() == null || data.getEncrypted().length == 0 || data.getEncrypted().length % (4 * WORD_COUNT) != 0)
            throw new IllegalArgumentException("data.encrypted must be a non-null non-empty array, its length must be a multiple of " + (4 * WORD_COUNT));

        // Обрезаем паддинг
        byte[] result = decryptArray(data.getEncrypted(), data.getPrivateKey());
        if (result[result.length - 1] == 1) {
            int i = result.length - 2;
            while (result[i] == 0)
                i--;
            byte[] buf = new byte[i + 1];
            System.arraycopy(result, 0, buf, 0, buf.length);
            result = buf;
        }

        return new String(result);
    }

    private byte[] encryptArray(byte[] input, byte[] key) {

        byte[][] slicedInput = sliceArray(input, WORD_COUNT); // Разбиваем ввод на блоки по 4*nb байт
        byte[][] slicedOutput = new byte[slicedInput.length][slicedInput[0].length]; // Буфер для вывода
        byte[][] keySchedule = keyExpansion(key); // Набор раундовых ключей, генерируемых из исходного

        for (int i = 0; i < slicedInput.length; i++) {
            slicedOutput[i] = encryptBlock(slicedInput[i], keySchedule);
        }

        return concatOutput(slicedOutput);
    }

    private byte[] decryptArray(byte[] dataEncrypted, byte[] key) {

        byte[][] slicedInput = sliceArray(dataEncrypted, WORD_COUNT);
        byte[][] slicedOutput = new byte[slicedInput.length][slicedInput[0].length];
        byte[][] keySchedule = keyExpansion(key);

        for (int i = 0; i < slicedInput.length; i++) {
            slicedOutput[i] = decryptBlock(slicedInput[i], keySchedule);
        }
        return concatOutput(slicedOutput);
    }



    // Приватные методы

    // Шифрование отдельного блока
    private byte[] encryptBlock(byte[] block, byte[][] keySchedule) {
        // Первая координата - номер столбца!
        byte[][] slicedBlock = sliceArray(block, 1);

        addRoundKey(slicedBlock, keySchedule[0], keySchedule[1], keySchedule[2], keySchedule[3]);
        for (int i = 1; i < ROUND_COUNT; i++) {
            subBytes(slicedBlock);
            shiftRows(slicedBlock);
            mixColumns(slicedBlock, MIX_CONST);
            // Требуется WORD_COUNT столбцов раундовых ключей
            addRoundKey(slicedBlock,
                    keySchedule[i * WORD_COUNT],
                    keySchedule[i * WORD_COUNT + 1],
                    keySchedule[i * WORD_COUNT + 2],
                    keySchedule[i * WORD_COUNT + 3]);
        }
        subBytes(slicedBlock);
        shiftRows(slicedBlock);
        addRoundKey(slicedBlock,
                keySchedule[ROUND_COUNT * 4],
                keySchedule[ROUND_COUNT * 4 + 1],
                keySchedule[ROUND_COUNT * 4 + 2],
                keySchedule[ROUND_COUNT * 4 + 3]);

        return concatOutput(slicedBlock);
    }

    // Дешифрование отдельного блока
    private byte[] decryptBlock(byte[] block, byte[][] keySchedule) {
        byte[][] slicedBlock = sliceArray(block, 1);

        addRoundKey(slicedBlock, keySchedule[WORD_COUNT * ROUND_COUNT],
                keySchedule[WORD_COUNT * ROUND_COUNT + 1],
                keySchedule[WORD_COUNT * ROUND_COUNT + 2],
                keySchedule[WORD_COUNT * ROUND_COUNT + 3]);

        for (int i = ROUND_COUNT - 1; i > 0; i--) {
            shiftRowsBack(slicedBlock);
            subBytesBack(slicedBlock);
            // Требуется WORD_COUNT столбцов раундовых ключей
            addRoundKey(slicedBlock, keySchedule[WORD_COUNT * i],
                    keySchedule[WORD_COUNT * i + 1],
                    keySchedule[WORD_COUNT * i + 2],
                    keySchedule[WORD_COUNT * i + 3]);
            mixColumns(slicedBlock, INV_MIX_CONST);
        }

        shiftRowsBack(slicedBlock);
        subBytesBack(slicedBlock);
        addRoundKey(slicedBlock, keySchedule[0], keySchedule[1], keySchedule[2], keySchedule[3]);

        return concatOutput(slicedBlock);
    }

    // Разбивает массив на блоки размером в указанное количество 32-битных слов
    // Если размер массива не кратен размеру блока, последний блок дополняется единицей в конце и нулями в остальных битах
    private byte[][] sliceArray(byte[] array, int wordCount) {
        int blockSize = 4 * wordCount;
        int lastBlockSize = array.length % blockSize;

        int blockCount = array.length / blockSize + (lastBlockSize == 0 ? 0 : 1); // Количество блоков

        byte[][] slicedArray = new byte[blockCount][blockSize]; // Разбиваем на блоки

        int i = 0;
        for (int r = 0; r < blockCount - 1; r++) { // Последний блок может быть неполным, его создаем отдельно
            for (int c = 0; c < blockSize; c++) {
                slicedArray[r][c] = array[i++];
            }
        }

        if (lastBlockSize == 0) {
            for (int c = 0; c < blockSize; c++)
                slicedArray[blockCount - 1][c] = array[i++];
        } else {
            // Последний бит - единица
            slicedArray[blockCount - 1][blockSize - 1] = 1;
            // Записываем значимую часть блока
            int c = 0;
            while (i < array.length)
                slicedArray[blockCount - 1][c++] = array[i++];
            // Все остальное - нули
            while (c < blockSize - 1)
                slicedArray[blockCount - 1][c++] = 0;
        }

        return slicedArray;
    }

    // Операция обратная sliceArray
    private byte[] concatOutput(byte[][] sliced) {
        byte[] result = new byte[sliced.length * sliced[0].length];
        int i = 0;
        for (byte[] bytes : sliced)
            for (byte b : bytes)
                result[i++] = b;
        return result;
    }



    // Процедуры преобразования блока

    // Процедура применяет раундовый ключ к блоку
    // Количество roundKeyColumns должно быть равно длине block
    private void addRoundKey(byte[][] block, byte[]... roundKeyColumns) {
        for (int i = 0; i < block.length; i++) {
            for (int j = 0; j < 4; j++) {
                block[i][j] = (byte) (block[i][j] ^ roundKeyColumns[i][j]);
            }
        }
    }

    // Процедура подменяет каждый байт на соответствующий из S_BOX
    private void subBytes(byte[][] block) {
        for (int i = 0; i < block.length; i++) {
            block[i] = subWord(block[i], S_BOX);
        }
    }

    // Процедура обратная subBytes
    private void subBytesBack(byte[][] block) {
        for (int i = 0; i < block.length; i++) {
            block[i] = subWord(block[i], INV_S_BOX);
        }
    }

    // Генерация раундовых ключей из исходного
    private byte[][] keyExpansion(byte[] sourceKey) {
        // Очередь состоит ROUND_COUNT + 1 блоков по WORD_COUNT столбцов, каждый столбец - 32-битное слово
        // Каждый блок - раундовый ключ.
        byte[][] keySchedule = new byte[(ROUND_COUNT + 1) * WORD_COUNT][4];
        // Нулевой блок совпадает с исходным ключом
        for (int i = 0; i < KEY_WORD_COUNT; i++) {
            for (int j = 0; j < 4; j++) {
                keySchedule[i][j] = sourceKey[4 * i + j];
            }
        }
        // Остальные блоки генерируются из предыдущих блоков
        for (int i = KEY_WORD_COUNT; i < keySchedule.length; i++) {
            byte[] temp = keySchedule[i - 1];
            if (i % KEY_WORD_COUNT == 0)
                temp = xor(subWord(rotWord(temp), S_BOX), R_CONST[i / KEY_WORD_COUNT]);
            keySchedule[i] = xor(keySchedule[i - KEY_WORD_COUNT], temp);
        }

        return keySchedule;
    }

    // Процедура производит циклические сдвиги в строках блока
    // i-ая строка сдвигается влево на i позиций
    private void shiftRows(byte[][] block) {
        // Проходимся по строкам - второй координате блока
        for (int row = 1; row < 4; row++) {
            byte[] buf = new byte[row];
            for (int i = 0; i < buf.length; i++) {
                buf[i] = block[i][row];
            }

            for (int i = 0; i < block.length - row; i++) {
                block[i][row] = block[i + row][row];
            }
            for (int i = block.length - row; i < block.length; i++) {
                block[i][row] = buf[i - (block.length - row)];
            }
        }
    }

    // Процедура обратная shiftRows
    private void shiftRowsBack(byte[][] block) {
        // Проходимся по строкам - второй координате блока
        for (int row = 1; row < 4; row++) {
            byte[] buf = new byte[row];
            for (int i = 0; i < buf.length; i++) {
                buf[i] = block[block.length - row + i][row];
            }

            for (int i = block.length - 1; i >= row; i--) {
                block[i][row] = block[i - row][row];
            }
            for (int i = 0; i < buf.length; i++) {
                block[i][row] = buf[i];
            }
        }
    }

    // Процедура переставляет биты в каждом столбце путем скалярного умножения на специальную матрицу
    private void mixColumns(byte[][] block, byte[][] box) {
        for (int i = 0; i < block.length; i++) {
            byte[] res = new byte[4];
            for (int j = 0; j < 4; j++) {
                res[j] = (byte)
                        (polynomialMath.multiplyPolynomials(box[j][0], block[i][0]) ^
                                polynomialMath.multiplyPolynomials(box[j][1], block[i][1]) ^
                                polynomialMath.multiplyPolynomials(box[j][2], block[i][2]) ^
                                polynomialMath.multiplyPolynomials(box[j][3], block[i][3]));
            }
            block[i] = res;
        }
    }



    // Вспомогательные операции со словами

    // Перемещает младший байт на место старшего
    private byte[] rotWord(byte[] word) {
        byte[] result = new byte[word.length];
        for (int i = 0; i < word.length - 1; i++) {
            result[i] = word[i + 1];
        }
        result[result.length - 1] = word[0];
        return result;
    }

    // Применяет S_BOX либо INV_S_BOX для подмены каждого байта другим
    private byte[] subWord(byte[] word, byte[][] box) {
        byte[] result = new byte[word.length];
        for (int i = 0; i < word.length; i++) {
            // Строка таблицы - старшие 4 бита
            int x = (word[i] >> 4) & 0xf;
            // Столбец таблицы - младшие 4 бита
            int y = word[i] & 0xf;
            result[i] = box[x][y];
        }
        return result;
    }

    // Выполняет xor над каждым байтом из a с соответствующим байтом из b
    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }


}