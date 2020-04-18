//
// Created by fouri on 2020/03/30.
//

#ifndef ARMANDT_ARMANDT_H
#define ARMANDT_ARMANDT_H
#include <stdio.h>

/**
 * A structure to hold relevant info for doing cipher block chaining
 */
struct CBC{
    int pSize;         //size of plaintext in BYTES = no. of array indexes
    int cSize;         //size of the ciphertext created in BYTES
    int blockSize;     //size of each block in BYTES
    int keySize;       //size of the key in bits
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
    int keySize;        //size of the key in bits
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

/**
 * @brief Uses the cipher feedback mode to encrypt a message. Internally, this function uses the AES
 * encryption algorithm to encrypt the IV/Shift Register
 * @param c The CFB struct containing the plaintext and other relevant information
 * @param round A counter for the round of encryption being executed.
 */
void encryptCFB(struct CFB *c, int round);

/**
 * @brief Takes a CFB struct and decrypts the message stored in its ciphertext, using the
 * AES decryption function.
 * @param c A pointer to the CFB structure being used.
 * @param round The round (block) of decryption being executed.
 */
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


/**
 * @brief Accepts a filename and opens the file. The function assumes that the file is located in
 * the root directory of the program. (Same folder as main.c)
 * @param filename The name of the file that must be encrypted.
 */
void readFile(unsigned char * filename, unsigned char * fileBuffer);

#endif //ARMANDT_ARMANDT_H
