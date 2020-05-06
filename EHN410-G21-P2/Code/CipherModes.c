//
// Created by fouri on 2020/03/27.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "CipherModes.h"
#include "AES.h"


void iterativeEncryptCBC(struct CBC *c){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;

    int round = 0; 

    while
        (!((((round + 1) * blockSize - pSize) >= blockSize) || (round * blockSize - pSize == 0))){
            unsigned char temp[blockSize];

            int i = round * blockSize; //i is the index from where we will begin to copy chars
            int j = 0;                 //j is the number of items that have been copied over so far

            while ((i < pSize) && (j < blockSize))
            {
                temp[j] = (*c).plaintext[i];
                j++;
                i++;
            } //first, copy chars from p to temp without going beyond the scope of p
            while (j < blockSize)
            {
                temp[j] = 0;
                j++;
            } //pad with zeros if necessary

            //now we have temp, the block of input data we want to work with
            //        printf("XOR Output block: \t");
            if (round == 0)
            {
                for (int a = 0; a < blockSize; a++)
                {
                    temp[a] = temp[a] ^ (*c).iv[a];
                    //                printf("%x ", temp[a]);
                } //xor the plaintext with the IV
            }
            else
            {
                for (int a = 0; a < blockSize; a++)
                {
                    temp[a] = temp[a] ^ (*c).ciphertext[a + (round - 1) * blockSize]; //replace this with the previous block's ciphertext values
                } //xor the plaintext with the previous block of ciphertext
            }


            //call AES function on the temp array
            set_key_length((*c).keySize); //pass in the size of the key in bits
            unsigned char encrypted[blockSize + 1];
            pad_and_encrypt(temp, encrypted, blockSize, (*c).keySize, (*c).key);


            for (int a = 0; a < blockSize; a++)
            {
                (*c).ciphertext[a + blockSize * round] = encrypted[a];
            }
            round++;
        }
}


void iterativeDecryptCBC(struct CBC *c){
    int blockSize = (*c).blockSize;
    int cSize = (*c).cSize;

    int round = 0;

    while ((round * blockSize) - cSize != 0) {
        unsigned char temp[blockSize + 1];
        unsigned char *decrypted;

        //call aes decryption
        for (int a = 0 + round * blockSize; a < blockSize + round * blockSize; a++)
        {
            temp[a - round * blockSize] = (*c).ciphertext[a];
        }                       //copy ciphertext into temp
        temp[blockSize] = '\0'; //append an endline char

        general_decrypt(temp, blockSize, (*c).keySize, (*c).key);   //decrypt the block 

        if (round == 0)
        {
            for (int a = 0; a < blockSize; a++)
            {
                temp[a] = temp[a] ^ (*c).iv[a];
                (*c).plaintext[a + blockSize * round] = temp[a];
            } //perform the XOR step using the IV and store the output in the plaintext array
        }
        else
        {
            for (int a = 0; a < blockSize; a++)
            {
                temp[a] = temp[a] ^ (*c).ciphertext[a + (round - 1) * blockSize];
                (*c).plaintext[a + blockSize * round] = temp[a];
            }//perform the xor step using the ciphertext block and store the output in the plaintext array
        }
        round++;
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


void iterativeEncryptCFB(struct CFB *c){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;
    int shiftRegSize = (*c).shiftRegSize;

    int round = 0;

    while (round * blockSize <= pSize){
        //step 1: encrypt the IV/Shift Register using the provided Key, K
        unsigned char temp[shiftRegSize];
        for (int a = 0; a < shiftRegSize; a++)
        {
            temp[a] = (*c).shiftRegister[a];
        } //copy the shift register into a temp array

        unsigned char storage[shiftRegSize + 1];
        unsigned char keyCopy[c->keySize / 8];
        for (int a = 0; a < c->keySize / 8; a++)
        {
            keyCopy[a] = (*c).key[a];
        }
        pad_and_encrypt(temp, storage, shiftRegSize, (*c).keySize, keyCopy);

        //Step 2: XOR the LSB of the temp array with the plaintext
        int b = 0;
        for (int a = 0 + round * blockSize; a < round * blockSize + blockSize; a++)
        {
            //            (*c).ciphertext[a] = temp[b] = temp[b] ^ (*c).plaintext[a];
            (*c).ciphertext[a] = storage[b] = storage[b] ^ (*c).plaintext[a];
            b++;
        } //the first [blockSize] bytes of temp now contains the new block of ciphertext. And ciphertext has the new
        //data in it as well

        //Step 3: Shift the ciphertext into the shift register before starting the next round.
        shiftBytesIn((*c).shiftRegister, shiftRegSize, storage, blockSize);
        round++;
    }
}


void iterativeDecryptCFB(struct CFB *c){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;
    int shiftRegSize = (*c).shiftRegSize;

    int round = 0;

    while ((round)*blockSize <= pSize){
        if (round == 0)
        {
            for (int a = 0; a < shiftRegSize; a++)
            {
                (*c).shiftRegister[a] = (*c).iv[a];
            } //the shift register should begin the same as the IV
        }
        else
        {
            //            printf("Shift Register: \t");
            //            printArr((*c).shiftRegister, shiftRegSize, 'x');
        }

        //step 1: encrypt the IV/Shift Register using the provided Key, K
        unsigned char temp[shiftRegSize];
        if (round == 0)
        {
            for (int a = 0; a < shiftRegSize; a++)
            {
                temp[a] = (*c).iv[a];
            } //copy the IV into a temp array
        }
        else
        {
            for (int a = 0; a < shiftRegSize; a++)
            {
                temp[a] = (*c).shiftRegister[a];
            } //copy the shift register into a temp array
        }

        unsigned char storage[shiftRegSize + 1];
        pad_and_encrypt(temp, storage, shiftRegSize, (*c).keySize, (*c).key);

        //step 2: XOR the first s bits of the encrypted output with the first s bits of ciphertext to get the plaintext
        int b = blockSize * round;
        for (int a = 0; a < blockSize; a++)
        {
            //            (*c).plaintext[a + b] = temp[a] ^ (*c).ciphertext[b + a];
            (*c).plaintext[a + b] = storage[a] ^ (*c).ciphertext[b + a];
        }

        //step 3: shift ciphertext block into shiftreg before running next step
        for (int a = 0; a < blockSize; a++)
        {
            temp[a] = (*c).ciphertext[a + b];
        } //copy ciphertext block into temp array (just so I can use the shiftBytesIn function more easily)

        shiftBytesIn((*c).shiftRegister, shiftRegSize, temp, blockSize);
        round++;
    }
}


void printArr(unsigned char *arr, int size, char format){
    if (format == 'c'){
        for (int a = 0; a < size; a++){
            printf("%c", arr[a]);
        }
    } else if (format == 'x'){
        for (int a = 0; a < size; a++){
            printf("%x ", arr[a]);
        }
    } else if (format == 'd'){
        for (int a = 0; a < size; a++){
            printf("%d ", arr[a]);
        }
    }

    printf("\n");
}

void readFile(unsigned char * filename, unsigned char * fileBuffer){
    FILE *f;
    f = fopen(filename, "rb");  //open binary file
    long int fileSize = 0;

    if (f == NULL){
        printf("Error, file not found.\n");
        exit(0);
    } else {
        fileSize = getFileSize(filename);

        printf("Reading %Ld bytes from file.\n", fileSize);
        fread(fileBuffer, fileSize + 1, 1, f);
    }

    fclose(f);
}

void saveFile(unsigned char * filename, unsigned char * fileBuffer, int fileSize){
    FILE * f;
    f = fopen(filename, "wb");

    int numZeros = 0;   //the number of zeros added to a file when using CBC
    int a = fileSize - 1;
    while(fileBuffer[a] == 0){
        a--;
        numZeros++;
    }

    fileSize -= numZeros;   //this stops zeroes that were added for padding from being saved upon decryption

    if (f == NULL) {
        printf("Error. File could not be opened.\n");
    } else {
        fwrite(fileBuffer, fileSize, 1, f);
    }
    fclose(f);
}

long int getFileSize(unsigned char * filename){
    FILE *f;
    f = fopen(filename, "rb");  //open binary file
    long int fileSize = 0;

    if (f == NULL){
        printf("Error, file not found.\n");
    } else {
        fseek(f, 0L, SEEK_END);
        fileSize = ftell(f);
    }

    fclose(f);
    return fileSize;
}