//
// Created by fouri on 2020/03/30.
//

#ifndef ARMANDT_ARMANDT_H
#define ARMANDT_ARMANDT_H

/**
 * A structure to hold relevant info for doing cipher block chaining
 */
struct CBC{
    int pSize;         //size of plaintext in BYTES = no. of array indexes
    int cSize;         //size of the ciphertext created in BYTES
    int blockSize;     //size of each block in BYTES
    unsigned char* plaintext;   //array of chars
    unsigned char* key;
    unsigned char* ciphertext;
    unsigned char* iv;          //this holds the initialization vector
};

/**
 * The structure for the CFB methods. The shiftregister and IV should be initialized as having the same contents,
 * but not being the same object.
 */
struct CFB{
    int pSize;          //size of the plaintext message/ciphertext
    int shiftRegSize;   //bytes in the IV/Shift Register
    int blockSize;      //number of bytes processed per round
    unsigned char* plaintext;
    unsigned char* ciphertext;
    unsigned char* iv;  //init vector. THis does not get changed.
    unsigned char* shiftRegister;
    unsigned char* key;
};

/**
 * @brief Takes a CBC struct and encrypts the data it contains, storing the ciphertext in the struct itself.
 */
void encryptCBC(struct CBC *c, int round);

/**
 * @brief Takes a CBC struct and and decrypts the data it contains using recursion.
 * @param c The CBC structure used.
 * @param round The round of decryption that is to be performed.
 */
void decryptCBC(struct CBC *c, int round);

/**
 * @brief Acts as a shift register, shifting new data into an existing array.
 * @param shiftReg The register that is accepting new data
 * @param regSize The size of the accepting register
 * @param newData The array containing the new data
 * @param newDataSize The size of the new data array.
 */
void shiftBytesIn(unsigned char* shiftReg, int regSize, unsigned char* newData, int newDataSize);

void encryptCFB(struct CFB *c, int round);

void decryptCFB(struct CFB *c, int round);

void dummyEncryptionFunction(unsigned char* data, int size);

void dummyDecryptionFunction(unsigned char* data, int size);

/**
 * @brief Prints the contents of an array separated by spaces, with a newline at the end
 * @param arr The array containing the chars
 * @param size The size of the array
 * @param format The char that indicates to the printf function how it should display the data in the array
 */
void printArr(unsigned char *arr, int size, char format);


#endif //ARMANDT_ARMANDT_H
