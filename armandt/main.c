#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "string.h"
#include "armandt.h"
#include "michelle.h"

int main(int argc, char *argv[])
{

    bool encrypt = false;
    bool decrypt = false;
    bool cbc = false;
    bool cfb = false;
    bool textIn = false;
    bool fileIn = false;
    unsigned char c_is_garbage[1000];
    unsigned char key[33];
    unsigned char iv[101];
    unsigned char *inFileName = NULL;
    unsigned char outFileName[100];
    unsigned char tempOutFileName[200];
    unsigned char newFileBuffer[1000000]; //approx 1mb file
    int keyLength = 0;  //the length of the key given by the user
    int streamLen = 0;
    int argLength = 0;  //the length of arguments like text, keys, etc.
    int plaintextLength = 0;

    struct CBC cbcStruct;
    struct CFB cfbStruct;

    for (int a = 1; a < argc; a++)
    {
        if (strcmp(argv[a], "-e") == 0)
        {
            encrypt = true;
        }
        else if (strcmp(argv[a], "-d") == 0)
        {
            decrypt = true;
        }
        else if (strcmp(argv[a], "-cbc") == 0)
        {
            cbc = true;
            keyLength = atoi(argv[a + 1]);
            if (!((keyLength == 128) || (keyLength == 192) || (keyLength == 256)))
            {
                printf("Incorrect key size entered. Closing.\n");
                return 0;
            }
            cbcStruct.keySize = keyLength;
        }
        else if (strcmp(argv[a], "-cfb") == 0)
        {
            cfb = true;
            keyLength = atoi(argv[a + 1]);
            if (!((keyLength == 128) || (keyLength == 192) || (keyLength == 256)))
            {
                printf("Incorrect key size entered. Closing.\n");
                return 0;
            }
            cfbStruct.keySize = keyLength;
        }
        else if (strcmp(argv[a], "-t") == 0)
        {
            textIn = true;
            argLength = strlen(argv[a + 1]);
            unsigned char t[argLength + 1];
            for (int b = 0; b < argLength; b++){
                c_is_garbage[b] = argv[a+1][b];
            }
            c_is_garbage[argLength] = '\0';
//            plaintext = c_is_garbage;
            plaintextLength = argLength;
            if (cbc){
                if (encrypt){
                    cbcStruct.plaintext = c_is_garbage;
                    cbcStruct.pSize = plaintextLength;
                    cbcStruct.cSize = (cbcStruct.pSize / 16 + 1) * 16;
                } else {
                    cbcStruct.ciphertext = c_is_garbage;
                    cbcStruct.cSize = plaintextLength;
                    cbcStruct.pSize = cbcStruct.cSize;
                }
            } else if (cfb){
                if (encrypt){
                    cfbStruct.pSize = plaintextLength;
                    cfbStruct.plaintext = c_is_garbage;
                } else {
                    cfbStruct.pSize = plaintextLength;
                    cfbStruct.ciphertext = c_is_garbage;
                }
            }
            a++;
        }
        else if (strcmp(argv[a], "-key") == 0)
        {
            argLength = strlen(argv[a + 1]);
            for (int b = 0; b < argLength; b++){
                key[b] = argv[a+1][b];
            }
            key[argLength] = '\0';
//            key = key;

            if (cbc){
                cbcStruct.key = key;
            } else if (cfb) {
                cfbStruct.key = key;
                cfbStruct.shiftRegSize = 32;
            }
            a++;
        }
        else if (strcmp(argv[a], "-iv") == 0)
        {
            argLength = strlen(argv[a + 1]);
//            unsigned char iv[argLength + 1];
            for (int b = 0; b < argLength; b++){
                iv[b] = argv[a+1][b];
            }
            iv[argLength] = '\0';

            if (cbc) {
                cbcStruct.iv = iv;
                cbcStruct.blockSize = 16;
            } else if (cfb) {
                cfbStruct.iv = iv;
                cfbStruct.shiftRegSize = argLength;
            }
            a++;
        }
        else if (strcmp(argv[a], "-fi") == 0)
        {
            fileIn = true;
            argLength = strlen(argv[a + 1]);
            unsigned char temp[argLength + 1];
            for (int b = 0; b < argLength; b++){
                temp[b] = argv[a+1][b];
                tempOutFileName[b] = temp[b];
            }
            temp[argLength] = '\0';
            inFileName = temp;
            plaintextLength = getFileSize(inFileName);
            readFile(inFileName, newFileBuffer);

            if (cbc) {
                if (encrypt){
                    cbcStruct.plaintext = newFileBuffer;
                    cbcStruct.pSize = plaintextLength;
                    cbcStruct.cSize = (cbcStruct.pSize / 16 + 1) * 16;
                } else {
                    cbcStruct.ciphertext = newFileBuffer;
                    cbcStruct.cSize = plaintextLength;
                    cbcStruct.pSize = plaintextLength;
                }
            } else if (cfb) {
                if (encrypt){
                    cfbStruct.plaintext = newFileBuffer;
                    cfbStruct.pSize = plaintextLength;
                } else {
                    cfbStruct.ciphertext = newFileBuffer;
                    cfbStruct.pSize = plaintextLength;
                }
            }
            a++;
        }
        else if (strcmp(argv[a], "-fo") == 0)
        {
            argLength = strlen(argv[a + 1]);
            if (argLength > 100){
                printf("The output file name entered is too long. Please use fewer than 100 characters.\n");
                return 0;
            }

            for (int b = 0; b < argLength - 2; b++){
                outFileName[b] = argv[a+1][b + 2];
            }
            outFileName[argLength] = '\0';

            for (int b = 199; b > 0; b--){
                if (tempOutFileName[b] == '/'){
                    if (cbc){
                        tempOutFileName[b + 1] = 'C';
                        tempOutFileName[b + 2] = 'B';
                        tempOutFileName[b + 3] = 'C';
                    } else {
                        tempOutFileName[b + 1] = 'C';
                        tempOutFileName[b + 2] = 'F';
                        tempOutFileName[b + 3] = 'B';
                    }
                    tempOutFileName[b + 4] = ' ';
                    tempOutFileName[b + 5] = 'O';
                    tempOutFileName[b + 6] = 'u';
                    tempOutFileName[b + 7] = 't';
                    tempOutFileName[b + 8] = 'p';
                    tempOutFileName[b + 9] = 'u';
                    tempOutFileName[b + 10] = 't';
                    tempOutFileName[b + 11] = '/';

                    for (int c = 0; c < argLength - 2; c++){
                        tempOutFileName[b + c + 11] = outFileName[c];
                    }// add the part of the path for the folders and the name for the output file
                    break;
                }
            }
            a++;
        }
        else if (strcmp(argv[a], "-streamlen") == 0)
        {
            streamLen = atoi(argv[a + 1]);

            if (!((streamLen == 8) || (streamLen == 64) || (streamLen == 128))){
                printf("Please try again and enter a valid streamlength.\n");
                return 0;
            }

            if (cfb) {
                cfbStruct.blockSize = atoi(argv[a + 1]);
            } else if (cbc){
                cbcStruct.blockSize = atoi(argv[a + 1]);
            }
            a++;
        }
        else if (strcmp(argv[a], "-h") == 0)
        {
            printf("\n============================================================\n");
            printf("The following commands are available: \n");
            printf("-e: \t\t\t\t Encryption\n");
            printf("-d: \t\t\t\t Decryption\n");
            printf("-cbc <len>:\t\t\t CBC Encryption/Decryption\n");
            printf("-cfb <len>:\t\t\t CFB Encryption/Decryption\n");
            printf("<len>: \t\t\t\t Key length: either 128, 192 or 256\n");
            printf("-t <text>:\t\t\t Enter the text to encrypt after this tag, surrounded by quotation marks.\n");
            printf("-key <password>: \t Enter the password after this tag.\n");
            printf("-iv <init vect>: \t Enter the initialisation vector after this tag.\n");
            printf("-fi <input file>:\t Enter the name of the input file.\n");
            printf("-fo <output file>:\t Enter the name of the output file.\n");
            printf("-streamlen <len>: \t Enter the streamlength after this tag.\n");
            printf("-h: \t\t\t\t Enter this tag to display this message.\n");
            printf("============================================================\n");
        }
    }

    int s = 0;
    if (cbc){
        if (encrypt){
            s = cbcStruct.cSize;  //make an array to hold the ciphertext
        } else {
            s = cbcStruct.pSize;  //plaintext array will be same size as ciphertext
        }
    } else if (cfb){
        s = cfbStruct.pSize;    //both arrays are the same size for cfb
    } else {
        s = (plaintextLength / 16 + 1) * 16;
    }

    unsigned char newArray[s + 1];  //this will store cipher or plaintext

    if (cbc) {
        if (encrypt){
            cbcStruct.ciphertext = newArray;
            printf("Encryption has started.\n");
            iterativeEncryptCBC(&cbcStruct);
            printf("Done encrypting.\n");

            if (fileIn){
                saveFile(tempOutFileName, cbcStruct.ciphertext, cbcStruct.cSize);
                printf("File saved in the CBC folder.\n");
            }

//            iterativeDecryptCBC(&cbcStruct);
//            printArr(cbcStruct.plaintext, cbcStruct.pSize, 'c');

        } else {
            cbcStruct.plaintext = newArray;
            printf("Decryption has started.\n");
            iterativeDecryptCBC(&cbcStruct);
            printf("Done decrypting. \n");

            if (fileIn){
                saveFile(tempOutFileName, cbcStruct.plaintext, cbcStruct.pSize);
                printf("File saved in the CBC folder.\n");
            }

//            printArr(cbcStruct.plaintext, cbcStruct.pSize, 'c');
        }
    } else if (cfb) {
        unsigned char newShiftReg[cfbStruct.shiftRegSize];
        cfbStruct.shiftRegister = newShiftReg;
        for (int a = 0; a < cfbStruct.shiftRegSize; a++){
            newShiftReg[a] = iv[a];
        }

        if (encrypt){
            cfbStruct.ciphertext = newArray;
            printf("Encryption has started.\n");
            iterativeEncryptCFB(&cfbStruct);
            printf("Done encrypting.\n");
            printArr(cfbStruct.ciphertext, cfbStruct.pSize, 'x');

            if (fileIn){
                saveFile(tempOutFileName, cfbStruct.ciphertext, cfbStruct.pSize);
                printf("File saved in the CFB folder.\n");
            }

//            iterativeDecryptCFB(&cfbStruct);
//            printArr(cfbStruct.plaintext, cfbStruct.pSize, 'c');
        } else {
            cfbStruct.plaintext = newArray;
            printf("Decryption has started.\n");
            iterativeDecryptCFB(&cfbStruct);
            printf("Done decrypting.\n");

            if (fileIn){
                saveFile(tempOutFileName, cfbStruct.plaintext, cfbStruct.pSize);
                printf("File saved in the CFB folder.\n");
            }
        }
    } else {
        if (encrypt){
            set_key_length(keyLength);
            test_functionality(c_is_garbage);
//            pad_and_encrypt(c_is_garbage, newArray, plaintextLength, keyLength, key);
        } else {
            general_decrypt(c_is_garbage, plaintextLength, keyLength, key);
        }

    }   //neither cbc nor cfb

    return 0;
}