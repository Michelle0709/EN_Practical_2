//
// Created by fouri on 2020/03/27.
//

#include <stdio.h>
#include <stdlib.h>
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

//        printf("Plaintext block: \t");
//        for (int a = 0; a < blockSize; a++){
//            printf("%x ", temp[a]);
//        }
//        printf("\n");

        //now we have temp, the block of input data we want to work with
//        printf("XOR Output block: \t");
        if (round == 0){
            for (int a = 0; a < blockSize; a++){
                temp[a] = temp[a] ^ (*c).iv[a];
//                printf("%x ", temp[a]);
            }   //xor the plaintext with the IV
        } else {
            for (int a = 0; a < blockSize; a++){
                temp[a] = temp[a] ^ (*c).ciphertext[a + (round - 1) * blockSize]; //replace this with the previous block's ciphertext values
//                printf("%x ", temp[a]);
            }   //xor the plaintext with the previous block of ciphertext
        }

//        printf("\n");

        //call AES function on the temp array
        set_key_length((*c).keySize);  //pass in the size of the key in bits
        unsigned char encrypted[blockSize + 1];
//        unsigned char hello[17];
//        for (int a = 0; a < 16; a++){
//            hello[a] = a + 1;
//        }
//        hello[16] = '\0';
//        printf("Hello: \t");
//        printArr(hello, 16, 'x');
        pad_and_encrypt(temp, encrypted, blockSize, (*c).keySize, (*c).key);

//        printf("AES Output block: \t");
        for (int a = 0; a < blockSize; a++){
//            temp[a] = temp[a] + 1;
//            printf("%x ", encrypted[a]);
        }   //this is a mock aes function
//        printf("\n");

//        printf("New init vector: \t");
        for (int a = 0; a < blockSize; a++){
//            (*c).iv[a] = temp[a];
            (*c).ciphertext[a + blockSize * round] = encrypted[a];
//            printf("%x ", encrypted[a]);
        }
//        printf("\n\n");

        encryptCBC(c, ++round);
    }
}

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

            //        printf("Plaintext block: \t");
            //        for (int a = 0; a < blockSize; a++){
            //            printf("%x ", temp[a]);
            //        }
            //        printf("\n");

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
                                                                                      //                printf("%x ", temp[a]);
                }                                                                     //xor the plaintext with the previous block of ciphertext
            }

            //        printf("\n");

            //call AES function on the temp array
            set_key_length((*c).keySize); //pass in the size of the key in bits
            unsigned char encrypted[blockSize + 1];
            //        unsigned char hello[17];
            //        for (int a = 0; a < 16; a++){
            //            hello[a] = a + 1;
            //        }
            //        hello[16] = '\0';
            //        printf("Hello: \t");
            //        printArr(hello, 16, 'x');
            pad_and_encrypt(temp, encrypted, blockSize, (*c).keySize, (*c).key);

            //        printf("AES Output block: \t");
            for (int a = 0; a < blockSize; a++)
            {
                //            temp[a] = temp[a] + 1;
                //            printf("%x ", encrypted[a]);
            } //this is a mock aes function
              //        printf("\n");

            //        printf("New init vector: \t");
            for (int a = 0; a < blockSize; a++)
            {
                //            (*c).iv[a] = temp[a];
                (*c).ciphertext[a + blockSize * round] = encrypted[a];
                //            printf("%x ", encrypted[a]);
            }
            //        printf("\n\n");
            round++;
        }
}

void decryptCBC(struct CBC *c, int round){
    int blockSize = (*c).blockSize;
    int cSize = (*c).cSize;

    if ((round * blockSize) - cSize == 0){
        return;
    } else {
        unsigned char temp[blockSize + 1];
        unsigned char * decrypted;

//        printf("\nCiphertext: \t");
        for (int a = 0; a < 16; a++){
//            printf("%x ", (*c).ciphertext[a]);
        }
//        printf("\n");

        //call aes decryption
        for (int a = 0 + round * blockSize; a < blockSize + round * blockSize; a++){
            temp[a - round * blockSize] = (*c).ciphertext[a];
        }   //copy ciphertext into temp
        temp[blockSize] = '\0'; //append an endline char

//        printf("\nKey: \t");
//        printArr((*c).key, 16, 'x');

//        printf("Decrypted block: \t");
        general_decrypt(temp, blockSize, (*c).keySize, (*c).key);
//        printArr(temp, strlen(temp), 'x');
//        printf("\n");

//        for (int a = 0; a < blockSize; a++){
//            temp[a] = decrypted[a];
//        }

//        printf("XOR output block: \t");
        if (round == 0){
            for (int a = 0; a < blockSize; a++){
                temp[a] = temp[a] ^ (*c).iv[a];
//                printf("%x ", temp[a]);
                (*c).plaintext[a + blockSize * round] = temp[a];
            }
        } else {
            for (int a = 0; a < blockSize; a++){
                temp[a] = temp[a] ^ (*c).ciphertext[a + (round - 1) * blockSize];
//                printf("%x ", temp[a]);
                (*c).plaintext[a + blockSize * round] = temp[a];
            }
        }
//        printf("\n\n");

        decryptCBC(c, ++round);
    }
}

void iterativeDecryptCBC(struct CBC *c){
    int blockSize = (*c).blockSize;
    int cSize = (*c).cSize;

    int round = 0;

    while ((round * blockSize) - cSize != 0) {
        unsigned char temp[blockSize + 1];
        unsigned char *decrypted;

        //        printf("\nCiphertext: \t");
        for (int a = 0; a < 16; a++)
        {
            //            printf("%x ", (*c).ciphertext[a]);
        }
        //        printf("\n");

        //call aes decryption
        for (int a = 0 + round * blockSize; a < blockSize + round * blockSize; a++)
        {
            temp[a - round * blockSize] = (*c).ciphertext[a];
        }                       //copy ciphertext into temp
        temp[blockSize] = '\0'; //append an endline char

        //        printf("\nKey: \t");
        //        printArr((*c).key, 16, 'x');

        //        printf("Decrypted block: \t");
        general_decrypt(temp, blockSize, (*c).keySize, (*c).key);
        //        printArr(temp, strlen(temp), 'x');
        //        printf("\n");

        //        for (int a = 0; a < blockSize; a++){
        //            temp[a] = decrypted[a];
        //        }

        //        printf("XOR output block: \t");
        if (round == 0)
        {
            for (int a = 0; a < blockSize; a++)
            {
                temp[a] = temp[a] ^ (*c).iv[a];
                //                printf("%x ", temp[a]);
                (*c).plaintext[a + blockSize * round] = temp[a];
            }
        }
        else
        {
            for (int a = 0; a < blockSize; a++)
            {
                temp[a] = temp[a] ^ (*c).ciphertext[a + (round - 1) * blockSize];
                //                printf("%x ", temp[a]);
                (*c).plaintext[a + blockSize * round] = temp[a];
            }
        }
        //        printf("\n\n");
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

void encryptCFB(struct CFB *c, int round){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;
    int shiftRegSize = (*c).shiftRegSize;
    if (round * blockSize > pSize){
        return;
    } else {
//        printf("Plaintext block: \t");
        for (int a = 0 + round * blockSize; a < round * blockSize + blockSize; a++){
//            printf("%x ", (*c).plaintext[a]);
        }
//        printf("\n");

        //step 1: encrypt the IV/Shift Register using the provided Key, K
        unsigned char temp[shiftRegSize];
        for (int a = 0; a < shiftRegSize; a++){
            temp[a] = (*c).shiftRegister[a];
        }   //copy the shift register into a temp array

        unsigned char storage[shiftRegSize + 1];
        unsigned char keyCopy[c->keySize / 8];
        for (int a = 0; a < c->keySize / 8; a++){
            keyCopy[a] = (*c).key[a];
        }
        pad_and_encrypt(temp, storage, shiftRegSize, (*c).keySize, keyCopy);
//        general_decrypt(storage, shiftRegSize, 128, (*c).key);

//        dummyEncryptionFunction(temp, shiftRegSize);
//        printf("Encrypted SR: \t\t");
//        printArr(temp, shiftRegSize, 'x');
//        printArr(storage, shiftRegSize, 'x');

        //Step 2: XOR the LSB of the temp array with the plaintext
//        printf("XOR Output Block: \t");
        int b = 0;
        for (int a = 0 + round * blockSize; a < round * blockSize + blockSize; a++){
//            (*c).ciphertext[a] = temp[b] = temp[b] ^ (*c).plaintext[a];
            (*c).ciphertext[a] = storage[b] = storage[b] ^ (*c).plaintext[a];
            b++;
        }   //the first [blockSize] bytes of temp now contains the new block of ciphertext. And ciphertext has the new
            //data in it as well
//        printArr(temp, blockSize, 'x');
//        printArr(storage, blockSize, 'x');
//        printf("Ciphertext: \t\t");
//        printArr((*c).ciphertext, pSize, 'x');

        //Step 3: Shift the ciphertext into the shift register before starting the next round.
//        shiftBytesIn((*c).shiftRegister, shiftRegSize, temp, blockSize);
        shiftBytesIn((*c).shiftRegister, shiftRegSize, storage, blockSize);
//        printf("New shiftreg: \t\t");
//        printArr((*c).shiftRegister, shiftRegSize, 'x');
//        printf("\n");
        encryptCFB(c, ++round);

    }
}

void iterativeEncryptCFB(struct CFB *c){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;
    int shiftRegSize = (*c).shiftRegSize;

    int round = 0;

    while (round * blockSize <= pSize){
        for (int a = 0 + round * blockSize; a < round * blockSize + blockSize; a++)
        {
            //            printf("%x ", (*c).plaintext[a]);
        }
        //        printf("\n");

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
        //        general_decrypt(storage, shiftRegSize, 128, (*c).key);

        //        dummyEncryptionFunction(temp, shiftRegSize);
        //        printf("Encrypted SR: \t\t");
        //        printArr(temp, shiftRegSize, 'x');
        //        printArr(storage, shiftRegSize, 'x');

        //Step 2: XOR the LSB of the temp array with the plaintext
        //        printf("XOR Output Block: \t");
        int b = 0;
        for (int a = 0 + round * blockSize; a < round * blockSize + blockSize; a++)
        {
            //            (*c).ciphertext[a] = temp[b] = temp[b] ^ (*c).plaintext[a];
            (*c).ciphertext[a] = storage[b] = storage[b] ^ (*c).plaintext[a];
            b++;
        } //the first [blockSize] bytes of temp now contains the new block of ciphertext. And ciphertext has the new
        //data in it as well
        //        printArr(temp, blockSize, 'x');
        //        printArr(storage, blockSize, 'x');
        //        printf("Ciphertext: \t\t");
        //        printArr((*c).ciphertext, pSize, 'x');

        //Step 3: Shift the ciphertext into the shift register before starting the next round.
        //        shiftBytesIn((*c).shiftRegister, shiftRegSize, temp, blockSize);
        shiftBytesIn((*c).shiftRegister, shiftRegSize, storage, blockSize);
        //        printf("New shiftreg: \t\t");
        //        printArr((*c).shiftRegister, shiftRegSize, 'x');
        //        printf("\n");
        // encryptCFB(c, ++round);
        round++;
    }
}

void decryptCFB(struct CFB *c, int round){
    int blockSize = (*c).blockSize;
    int pSize = (*c).pSize;
    int shiftRegSize = (*c).shiftRegSize;

    if ((round) * blockSize > pSize){
        return;
    } else {
        if (round == 0){
//            printf("Init Vector: \t\t");
//            printArr((*c).iv, shiftRegSize, 'x');
            for (int a = 0; a < shiftRegSize; a++){
                (*c).shiftRegister[a] = (*c).iv[a];
            }   //the shift register should begin the same as the IV
        } else {
//            printf("Shift Register: \t");
//            printArr((*c).shiftRegister, shiftRegSize, 'x');
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

        unsigned char storage[shiftRegSize + 1];
        pad_and_encrypt(temp, storage, shiftRegSize, (*c).keySize, (*c).key);
//        dummyEncryptionFunction(temp, shiftRegSize);
//        printf("Encrypted SR: \t\t");
//        printArr(temp, shiftRegSize, 'x');
//        printArr(storage, shiftRegSize, 'x');

        //step 2: XOR the first s bits of the encrypted output with the first s bits of ciphertext to get the plaintext
//        printf("Decrypted block: \t");
        int b = blockSize * round;
        for (int a = 0; a < blockSize; a++){
//            (*c).plaintext[a + b] = temp[a] ^ (*c).ciphertext[b + a];
            (*c).plaintext[a + b] = storage[a] ^ (*c).ciphertext[b + a];
//            printf("%x ", (*c).plaintext[a+b]);
        }
//        printf("\n");

        //step 3: shift ciphertext block into shiftreg before running next step
        for (int a = 0; a < blockSize; a++){
            temp[a] = (*c).ciphertext[a + b];
        }   //copy ciphertext block into temp array (just so I can use the shiftBytesIn function more easily)

        shiftBytesIn((*c).shiftRegister, shiftRegSize, temp, blockSize);
//        printf("\n");
        decryptCFB(c, ++round);

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
            //            printf("Init Vector: \t\t");
            //            printArr((*c).iv, shiftRegSize, 'x');
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
        //        dummyEncryptionFunction(temp, shiftRegSize);
        //        printf("Encrypted SR: \t\t");
        //        printArr(temp, shiftRegSize, 'x');
        //        printArr(storage, shiftRegSize, 'x');

        //step 2: XOR the first s bits of the encrypted output with the first s bits of ciphertext to get the plaintext
        //        printf("Decrypted block: \t");
        int b = blockSize * round;
        for (int a = 0; a < blockSize; a++)
        {
            //            (*c).plaintext[a + b] = temp[a] ^ (*c).ciphertext[b + a];
            (*c).plaintext[a + b] = storage[a] ^ (*c).ciphertext[b + a];
            //            printf("%x ", (*c).plaintext[a+b]);
        }
        //        printf("\n");

        //step 3: shift ciphertext block into shiftreg before running next step
        for (int a = 0; a < blockSize; a++)
        {
            temp[a] = (*c).ciphertext[a + b];
        } //copy ciphertext block into temp array (just so I can use the shiftBytesIn function more easily)

        shiftBytesIn((*c).shiftRegister, shiftRegSize, temp, blockSize);
        //        printf("\n");
        round++;
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
//    fgets(fileBuffer, 32, f);
    long int fileSize = 0;

    if (f == NULL){
        printf("Error, file not found.\n");
//        exit(0);
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