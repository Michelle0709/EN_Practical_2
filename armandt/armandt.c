//
// Created by fouri on 2020/03/27.
//

#include <stdio.h>
#include <string.h>
#include "armandt.h"
#include "michelle.h"


void encryptCBC(struct CBC *c, int round){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;
    if ((((round + 1) * blockSize - pSize) >= blockSize) || (round * blockSize - pSize == 0)){
        return;
    } else {
        unsigned char temp[blockSize];

        int i = round * blockSize;    //i is the index from where we will begin to copy chars
        int j = 0;          //j is the number of items that have been copied over so far

        while((i < pSize) && (j < blockSize)){
            temp[j] = (*c).plaintext[i];
            j++;
            i++;
        }   //first, copy chars from p to temp without going beyond the scope of p
        while(j < blockSize){
            temp[j] = 0;
            j++;
        }   //pad with zeros if necessary

        printf("Plaintext block: \t");
        for (int a = 0; a < blockSize; a++){
            printf("%x ", temp[a]);
        }
        printf("\n");

        //now we have temp, the block of input data we want to work with
        printf("XOR Output block: \t");
        if (round == 0){
            for (int a = 0; a < blockSize; a++){
                temp[a] = temp[a] ^ (*c).iv[a];
                printf("%x ", temp[a]);
            }   //xor the plaintext with the key
        } else {
            for (int a = 0; a < blockSize; a++){
                temp[a] = temp[a] ^ (*c).ciphertext[a + (round - 1) * blockSize]; //replace this with the previous block's ciphertext values
                printf("%x ", temp[a]);
            }   //xor the plaintext with the key
        }

        printf("\n");

        //call AES function on the temp array
        set_key_length(blockSize * 8);  //pass in the size of the key in bits

        printf("AES Output block: \t");
        for (int a = 0; a < blockSize; a++){
            temp[a] = temp[a] + 1;
            printf("%x ", temp[a]);
        }   //this is a mock aes function
        printf("\n");

        printf("New init vector: \t");
        for (int a = 0; a < blockSize; a++){
//            (*c).iv[a] = temp[a];
            (*c).ciphertext[a + blockSize * round] = temp[a];
            printf("%x ", temp[a]);
        }
        printf("\n\n");

        encryptCBC(c, ++round);
    }
}

void decryptCBC(struct CBC *c, int round){
    int blockSize = (*c).blockSize;
    int cSize = (*c).cSize;

    if ((round * blockSize) - cSize == 0){
        return;
    } else {
        unsigned char temp[blockSize];
        //call aes decryption
        printf("Decrypted block: \t");
        for (int a = 0 + round * blockSize; a < blockSize + round * blockSize; a++){
            temp[a - round * blockSize] = (*c).ciphertext[a] - 1;
            printf("%x ", temp[a - round * blockSize]);
        }   //dummy decryption function
        printf("\n");

        printf("XOR output block: \t");
        if (round == 0){
            for (int a = 0; a < blockSize; a++){
                temp[a] = temp[a] ^ (*c).iv[a];
                printf("%c ", temp[a]);
                (*c).plaintext[a + blockSize * round] = temp[a];
            }
        } else {
            for (int a = 0; a < blockSize; a++){
                temp[a] = temp[a] ^ (*c).ciphertext[a + (round - 1) * blockSize];
                printf("%c ", temp[a]);
                (*c).plaintext[a + blockSize * round] = temp[a];
            }
        }
        printf("\n\n");

        decryptCBC(c, ++round);
    }
}

void shiftBytesIn(unsigned char* shiftReg, int regSize, unsigned char* newData, int newDataSize){
    for (int a = 0; a < regSize - newDataSize; a++){
        shiftReg[a] = shiftReg[a + newDataSize];
    }

    int b = 0;
    for (int a = regSize - newDataSize; a < regSize; a++){
        shiftReg[a] = newData[b++];
    }
}

void encryptCFB(struct CFB *c, int round){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;
    int shiftRegSize = (*c).shiftRegSize;
    if ((round + 1) * blockSize > pSize){
        return;
    } else {
        printf("Plaintext block: \t");
        for (int a = 0 + round * blockSize; a < round * blockSize + blockSize; a++){
            printf("%x ", (*c).plaintext[a]);
        }
        printf("\n");

        //step 1: encrypt the IV/Shift Register using the provided Key, K
        unsigned char temp[shiftRegSize];
        for (int a = 0; a < shiftRegSize; a++){
            temp[a] = (*c).shiftRegister[a];
        }   //copy the shift register into a temp array

        dummyEncryptionFunction(temp, shiftRegSize);
        printf("Encrypted SR: \t\t");
        printArr(temp, shiftRegSize, 'x');

        //Step 2: XOR the LSB of the temp array with the plaintext
        printf("XOR Output Block: \t");
        int b = 0;
        for (int a = 0 + round * blockSize; a < round * blockSize + blockSize; a++){
            (*c).ciphertext[a] = temp[b] = temp[b] ^ (*c).plaintext[a];
            b++;
        }   //the first [blockSize] bytes of temp now contains the new block of ciphertext. And ciphertext has the new
            //data in it as well
        printArr(temp, blockSize, 'x');
//        printf("Ciphertext: \t\t");
//        printArr((*c).ciphertext, pSize, 'x');

        //Step 3: Shift the ciphertext into the shift register before starting the next round.
        shiftBytesIn((*c).shiftRegister, shiftRegSize, temp, blockSize);
        printf("New shiftreg: \t\t");
        printArr((*c).shiftRegister, shiftRegSize, 'x');
        printf("\n");
        encryptCFB(c, ++round);

    }
}

void decryptCFB(struct CFB *c, int round){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;
    int shiftRegSize = (*c).shiftRegSize;

    if ((round + 1) * blockSize > pSize){
        return;
    } else {
        if (round == 0){
            printf("Init Vector: \t\t");
            printArr((*c).iv, shiftRegSize, 'x');
            for (int a = 0; a < shiftRegSize; a++){
                (*c).shiftRegister[a] = (*c).iv[a];
            }   //the shift register should begin the same as the IV
        } else {
            printf("Shift Register: \t");
            printArr((*c).shiftRegister, shiftRegSize, 'x');
        }

        //step 1: encrypt the IV/Shift Register using the provided Key, K
        unsigned char temp[shiftRegSize];
        if (round == 0){
            for (int a = 0; a < shiftRegSize; a++){
                temp[a] = (*c).iv[a];
            }   //copy the IV into a temp array
        } else {
            for (int a = 0; a < shiftRegSize; a++){
                temp[a] = (*c).shiftRegister[a];
            }   //copy the shift register into a temp array
        }

        dummyEncryptionFunction(temp, shiftRegSize);
        printf("Encrypted SR: \t\t");
        printArr(temp, shiftRegSize, 'x');

        //step 2: XOR the first s bits of the encrypted output with the first s bits of ciphertext to get the plaintext
        printf("Decrypted block: \t");
        int b = blockSize * round;
        for (int a = 0; a < blockSize; a++){
            (*c).plaintext[a + b] = temp[a] ^ (*c).ciphertext[b + a];
            printf("%x ", (*c).plaintext[a+b]);
        }
        printf("\n");

        //step 3: shift ciphertext block into shiftreg before running next step
        for (int a = 0; a < blockSize; a++){
            temp[a] = (*c).ciphertext[a + b];
        }   //copy ciphertext block into temp array (just so I can use the shiftBytesIn function more easily)

        shiftBytesIn((*c).shiftRegister, shiftRegSize, temp, blockSize);
        printf("\n");
        decryptCFB(c, ++round);

    }
}

void dummyEncryptionFunction(unsigned char* data, int size){
    for (int a = 0; a < size; a++){
        data[a] = data[a] + 1;
    }
}

void dummyDecryptionFunction(unsigned char* data, int size){
    for (int a = 0; a < size; a++){
        data[a] = data[a] - 1;
    }
}

void printArr(unsigned char *arr, int size, char format){
    if (format == 'c'){
        for (int a = 0; a < size; a++){
            printf("%c ", arr[a]);
        }
    } else if (format == 'x'){
        for (int a = 0; a < size; a++){
            printf("%x ", arr[a]);
        }
    }

    printf("\n");
}
