package edu.krypt.algorytmdesx;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class DESX {

    private byte[] initPermutation = {
            58,	50,	42,	34,	26,	18,	10,	2,
            60,	52,	44,	36,	28,	20,	12,	4,
            62,	54, 46, 38,	30, 22, 14, 6,
            64,	56,	48,	40,	32,	24,	16,	8,
            57,	49,	41,	33,	25,	17,	9,	1,
            59,	51,	43,	35,	27,	19,	11,	3,
            61,	53,	45,	37,	29,	21,	13,	5,
            63,	55,	47,	39,	31,	23,	15,	7
    };

    private byte[] endPermutation = {
            40,     8, 48,    16,    56,   24,    64,   32,
            39,     7,   47,    15,    55,   23,   63,   31,
            38,     6,   46,    14,    54,   22,    62,   30,
            37,     5,   45,    13,    53,   21,    61,   29,
            36,     4,   44,    12,    52,   20,    60,   28,
            35,     3,   43,    11,    51,   19,    59,   27,
            34,     2,   42,    10,    50,   18,    58,   26,
            33,     1,   41,     9,    49,   17,    57,   25
    };

    private byte[] PC1 = {57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 63, 55, 47, 39,
            31, 23, 15, 7, 62, 54, 46, 38,
            30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4};
    private byte[] PC2 = {14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32};
    private byte[] SHIFTS = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    private  byte[] extendedPermutation = {
            32,	1,	2,	3,	4,  5,	4,	5,	6, 	7, 	8, 	9,
            8,	9,	10,	11,	12,	13,	12,	13,	14,	15,	16,	17,
            16,	17,	18,	19,	20,	21, 20,	21,	22, 23,	24,	25,
            24,	25,	26,	27,	28, 29,	28,	29,	30,	31,	32,	1
    };

    private byte[] SBoxes = {
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, // S1
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, // S2
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, // S3
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, // S4
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, // S5
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, // S6
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, // S7
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, // S8
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11

    };

    public byte[] hexToBytes(String mess) throws NumberFormatException
    {
        if (mess == null) {
            return null;}
        else  {
            if (mess.length() % 2 != 0) {
                mess = '0' + mess; //dopisanie na poczatek, zeby nie bylo sytuacji zwiekszenia liczby
            }
            int len = mess.length() / 2;
            byte[] wynik = new byte[len];
            for (int i = 0; i < 2 * len; i += 2) {
                wynik[i] = (byte) Integer.parseInt(mess.substring(i, i + 2), 16);
            }
            return wynik;
        }
    }

    public String bytesToHex(byte[] bytes)
    {
        StringBuilder hexText = new StringBuilder();
        String hex;
        int len;

        for (int i = 0; i < bytes.length; i++)
        {
            int value = bytes[i] & 0xFF; //ograniczamy inta do byta i to nieujemnego
            hex = Integer.toHexString(value);
            len = hex.length();
            while (len < 2)
            {
                hexText.append("0");
                len++;
            }
            hexText.append(hex);
        }
        return hexText.toString();
    }

    DESX() {
        subKeys = new byte[16][6];
    }


    public byte[] generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            SecretKey secretKey = keyGen.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    public void setKeyInt(byte[] keyInt) {
        this.keyInt = keyInt;
    }

    public void setKeyExt(byte[] keyExt) {
        this.keyExt = keyExt;
    }

    public void setKeyDes(byte[] keyDes) {
        this.keyDes = keyDes;
        keys(keyDes);
    }

    private byte[] keyInt;

    private byte[] keyExt;

    private byte[] keyDes;

    public byte[] getKeyInt() {
        return keyInt;
    }

    public byte[] getKeyExt() {
        return keyExt;
    }

    public byte[] getKeyDes() {
        return keyDes;
    }

    byte[][] subKeys;

    public void keys(byte[] originalKey) {
        byte[] key_56 = new byte[7];
        byte[] key_28left = new byte[4];
        byte[] key_28right = new byte[4];
        byte[] key_48 = new byte[6];

        for (int i = 0; i < 56; i++) {
            key_56 = setBit(key_56, i, isBitSet(originalKey, PC1[i] - 1));
        }

        System.out.println();

        for (int i = 0; i < 28; i++) {
            boolean left = isBitSet(key_56, i);
            boolean right = isBitSet(key_56, i + 28);
            key_28left = setBit(key_28left, i, left);
            key_28right = setBit(key_28right, i, right);
        }


        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < SHIFTS[i]; j++) {
                key_28left = circularLeftShift(key_28left, 28);
                key_28right = circularLeftShift(key_28right, 28);
            }

            for (int bitCounter = 0; bitCounter < 28; bitCounter++) {
                key_56 = setBit(key_56, bitCounter, isBitSet(key_28left, bitCounter));
                key_56 = setBit(key_56, bitCounter + 28, isBitSet(key_28right, bitCounter));
            }



            for (int bitConuter = 0; bitConuter < 48; bitConuter++) {
                key_48 = setBit(key_48,bitConuter, isBitSet(key_56, PC2[bitConuter] - 1));
            }


            System.arraycopy(key_48, 0, subKeys[i], 0, 6);
        }
    }



    private byte[] pBlock = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                                2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

    public boolean isBitSet(byte[] mess, int pos) { //pozycje bitów są od lewej 0 .. najstarszy bit
        byte tempByte = mess[pos / 8];
        byte tempPos = (byte) (pos % 8);
        return ((tempByte & (1 << (7 - tempPos))) != 0);
    }

    public byte[] setBit(byte[] mess, int pos, boolean value) { //pozycje bitów są od lewej 0 .. najstarszy bit
        byte tempByte = mess[pos / 8];
        byte tempPos = (byte) (pos % 8);

        if (value) {
            mess[pos / 8] = (byte) (tempByte | (1 << (7 - tempPos)));
        } else {
            mess[pos / 8] = (byte) (tempByte & (~(1 << (7 - tempPos))));
        }
        return mess;
    }

    public byte setBit(byte mess, int pos, boolean value) { //standardowe pozycje: najstarszy .. 0
        if (value) {
            return (byte) (mess | (1 << pos));
        } else {
            return (byte) (mess & (~(1 << pos)));
        }
    }

    private void printNum(int len) {
        for (int i = 0; i < len; i++) {
            System.out.print(i+" ");
            if (i < 10) {
                System.out.print(" ");
            }
        }
        System.out.println();
    }

    public void printBits(byte[] data) { //przyjmuje dowolna dlugosc bytow, przygotowane bylo pod wyswietlanie 8 bytow
        int len = data.length;
        printNum(8 * len);
        for (int i = 0; i < 8 * len; i++) {
            if (isBitSet(data, i)) {
                System.out.print("1  ");
            } else {
                System.out.print("0  ");
            }
        }
        System.out.println();
    }

    private byte[] circularLeftShift(byte[] data, int dataLen) {
        byte[] res = new byte[data.length];
        byte step = (byte) (data.length * 8 - dataLen);

        System.arraycopy(data, 0, res, 0, data.length);

        for (int i = 0; i < data.length; i++) {
            res[i] = (byte) (res[i] << 1);
            if (i + 1 < data.length) {
                res = setBit(res, 8 * i + 7, isBitSet(data, 8 * i + 8));
            } else {
                res = setBit(res, 8 * i + 7 - step, isBitSet(data, 0));
            }
        }
        return res;
    }

    public byte[] FeistelFunction(byte[] _4Blocks, byte[] subKey) {
        byte[] extended = new byte[6];

        //rozszerzenie z 32 do 48

        for (int i = 0; i < 48; i++) {
            extended = setBit(extended, i, isBitSet(_4Blocks, extendedPermutation[i] - 1));
        }

        //xor z podkluczem 48 XOR 48 [0 ... 47] XOR [0 ... 47] --> [0 - 7] w byte

        for (int i = 0; i < 6; i++) {
            extended[i] = (byte) (extended[i] ^ subKey[i]);
        }

        byte[] num = new byte[8];

        //Sboxy wynik 32 bitowy

        for (int i = 0; i < 8; i++) {
            byte leftNum = 0;
            byte upNum = 0;
            leftNum = setBit(leftNum, 1, isBitSet(extended, 6 * i));
            leftNum = setBit(leftNum, 0, isBitSet(extended, 6 * i + 5));
            for (int j = 4; j >= 1; j--) {
                upNum = setBit(upNum, j - 1, isBitSet(extended, 6 * i + (5 - j)));
            }
            num[i] = SBoxes[i * 64 + upNum + leftNum * 16];
        }


        int bitCounter = 4;
        byte[] res = new byte[4];
        for (int i = 0; i < 32; i++) {
            if (bitCounter % 8 == 0) {
                bitCounter += 4;
            }
            res = setBit(res, i, isBitSet(num, bitCounter));
            bitCounter++;
        }

        //Pboxy - permutacja wynik 32 bitowy - Funkcja to zwraca

        byte[] temp2 = new byte[4];

        for (int i = 0; i < 32; i++) {

            temp2 = setBit(temp2, i, isBitSet(res, pBlock[i] - 1));

        }

        return temp2;
    }

    public byte[] encrypting(byte[] partialMessage) {

        byte[] temp = inititalPermutation(partialMessage);
        byte[] left = new byte[4];
        byte[] right = new byte[4];

        System.arraycopy(temp, 0, left, 0, 4);
        System.arraycopy(temp, 4, right, 0, 4);

        for (int roundNum = 0; roundNum < 16; roundNum++) {
            byte[] pom = FeistelFunction(right, subKeys[roundNum]);
            for (int k = 0; k < 4; k++) {
                pom[k] = (byte) (pom[k] ^ left[k]);
            }
            if (roundNum != 15) {
                System.arraycopy(right, 0, left, 0, 4); //tu zmieniane było
                System.arraycopy(pom, 0, right, 0, 4);
            } else {
                System.arraycopy(pom, 0, left, 0, 4);
            }
        }

        byte[] fin = new byte[8];

        for (int i = 0; i < 4; i++) {
            fin[i] = left[i];
            fin[i+4] = right[i];
        }

        return endingPermutation(fin);
    }

    public byte[] decrypting(byte[] partialMessage) {

        byte[] temp = inititalPermutation(partialMessage);
        byte[] left = new byte[4];
        byte[] right = new byte[4];

        System.arraycopy(temp, 0, left, 0, 4);
        System.arraycopy(temp, 4, right, 0, 4);

        for (int roundNum = 15; roundNum >= 0; roundNum--) {
            byte[] pom = FeistelFunction(right, subKeys[roundNum]);
            for (int k = 0; k < 4; k++) {
                pom[k] = (byte) (pom[k] ^ left[k]);
            }
            if (roundNum != 0) {
                System.arraycopy(right, 0, left, 0, 4); //tu zmieniane było
                System.arraycopy(pom, 0, right, 0, 4);
            } else {
                System.arraycopy(pom, 0, left, 0, 4);
            }
        }

        byte[] fin = new byte[8];

        for (int i = 0; i < 4; i++) {
            fin[i] = left[i];
            fin[i+4] = right[i];
        }

        return endingPermutation(fin);
    }


    public byte[] inititalPermutation(byte[] _8Bytes) {
        byte[] local = new byte[8];
        for (int i = 0; i < 64; i++) {
            local = setBit(local, i, isBitSet(_8Bytes, initPermutation[i] - 1));
        }
        return local;
    }

    public byte[] endingPermutation(byte[] _8Bytes) {
        byte[] local = new byte[8];
        for (int i = 0; i < 64; i++) {
            local = setBit(local, i, isBitSet(_8Bytes, endPermutation[i] - 1));
        }
        return local;
    }


    public byte[] finalEncryption(byte[] fullMessage) {
        int length = fullMessage.length;
        int supplement = 0;

        if (length % 8 != 0) {
            supplement = 8 - (length % 8);
        }

        int newLen = length + supplement;

        byte[] suppliedMessage = new byte[newLen];
        System.arraycopy(fullMessage, 0, suppliedMessage, 0, length); // Kopiujemy fullMessage tyle ile zawiera bytow reszta dopelniona pozniej

        for (int i = length; i < newLen; i++) {
            suppliedMessage[i] = 0; //douzupełniamy zerami
        }

        byte[] fullCipher = new byte[newLen];
        byte[] temp = new byte[8];

        for (int i = 0; i < newLen / 8; i++) {
            int startIndex = i * 8;
            System.arraycopy(suppliedMessage, startIndex, temp, 0, 8);

            for (int j = 0; j < 8; j++) {
                temp[j] = (byte) (temp[j] ^ keyInt[j]);
            }

            byte[] partialCipher = encrypting(temp);

            for (int j = 0; j < 8; j++) {
                partialCipher[j] = (byte) (partialCipher[j] ^ keyExt[j]);
            }

            System.arraycopy(partialCipher, 0, fullCipher, startIndex, 8);
        }

        return fullCipher;
    }


    public byte[] finalDecryption(byte[] fullMessage) { //fullMessage jest odpowiedniego rozmiaru
        int length = fullMessage.length;

        byte[] fullCipher = new byte[length];
        byte[] temp = new byte[8];

        for (int i = 0; i < length / 8; i++) {
            int startIndex = i * 8;
            System.arraycopy(fullMessage, startIndex, temp, 0, 8);

            for (int j = 0; j < 8; j++) {
                temp[j] = (byte) (temp[j] ^ keyExt[j]);
            }

            byte[] partialCipher = decrypting(temp);

            for (int j = 0; j < 8; j++) {
                partialCipher[j] = (byte) (partialCipher[j] ^ keyInt[j]);
            }

            System.arraycopy(partialCipher, 0, fullCipher, startIndex, 8);
        }
        return fullCipher;
    }


}
