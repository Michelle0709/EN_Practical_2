#include <stdio.h>
#include "string.h"
#include "armandt.h"
#include "michelle.h"

int main() {
    int number_of_rounds = -1;
    int expanded_key_size = -1;
    int key_length = -1;
//    unsigned char a = 0x45;
//    printf("%c\n", a);

    int cbc_section = 0;
    int cfb_section = 0;
    int armandt_aes = 0;
    int michelle_aes = 0;
    int files_test = 1;

    if (cbc_section == 1){
        printf("\n\n=================CBC SECTION=================\n\n");
        struct CBC c;

        c.pSize = 30;
        c.blockSize = 16;
        c.cSize = (c.pSize / 16 + 1) * 16;
        c.keySize = 128;
        unsigned char text1[c.pSize + 1];
        unsigned char k[c.blockSize + 1];
        unsigned char iv[c.blockSize + 1];
        unsigned char text[c.cSize + 1];

        for (int a = 0; a < c.pSize; a++){
            text[a] = a;    //fill the plaintext with just numbers.
            text1[a] = 0;   //set the cipher text to zeros

            if (a < c.blockSize){
                k[a] = 'a';
                iv[a] = 'b';
            }   //fill the key and IV
        }


        text1[c.cSize] = text[c.pSize] = '\0';      //append terminator

        c.plaintext = text;
        c.ciphertext = text1;
        c.iv = iv;
        c.key = k;

        encryptCBC(&c, 0);

        printf("CBC encryption: \n");
        for (int a = 0; a < c.cSize; a++){
            printf("%x ", c.ciphertext[a]);
            if (c.ciphertext[a] < 17){
                printf(" ");
            }
            if ((a +1) % 8 == 0){
                printf("\n");
            }
        }
        printf("\n\n");

        decryptCBC(&c, 0);

        printf("CBC decryption: \n");
        for (int a = 0; a < c.cSize; a++){
            printf("%x ", c.plaintext[a]);
            if (c.plaintext[a] < 16){
                printf(" ");
            }
            if ((a +1) % 8 == 0){
                printf("\n");
            }
        }
        printf("\n\n");
    }

    if (cfb_section == 1){
        printf("\n\n===============CFB SECTION===============\n\n");

//    unsigned char cfbPlainText[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
//    unsigned char cfbInitVector[8] = {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};
//    unsigned char cfbCipherText[16];
//    unsigned char cfbShiftReg[8];
//
//    for (int a = 0; a < 8; a++){
//        cfbShiftReg[a] = cfbInitVector[a];
//    }
//
//    struct CFB cfb;
//    cfb.plaintext = cfbPlainText;
//    cfb.ciphertext = cfbCipherText;
//    cfb.iv = cfbInitVector;
//    cfb.shiftRegister = cfbShiftReg;
//    cfb.pSize = 16;
//    cfb.shiftRegSize = 8;
//    cfb.blockSize = 4;
//
//    encryptCFB(&cfb, 0);
//
//    printf("CFB encryption: \t");
//    printArr(cfb.ciphertext, 16, 'x');
//    printf("\n");
//
//    decryptCFB(&cfb, 0);
//    printf("CFB decryption: \t");
//    printArr(cfb.plaintext, 16, 'c');

        struct CFB cfb;
        cfb.pSize = 23;
        cfb.shiftRegSize = 16;
        cfb.blockSize = 8;
        cfb.keySize = 128;

        unsigned char cfbPlainText[cfb.pSize + 1];
        unsigned char cfbInitVector[cfb.shiftRegSize];
        unsigned char cfbCipherText[cfb.pSize + 1];
        unsigned char cfbShiftReg[cfb.shiftRegSize];
        unsigned char cfbKey[16];

        for (int a = 0; a < cfb.shiftRegSize; a++){
            cfbShiftReg[a] = cfbInitVector[a] = 0;
        }

        for (int a = 0; a < cfb.pSize; a++){
            cfbPlainText[a] = a * 2;
            cfbShiftReg[a] = 0;
            cfbCipherText[a] = 0;
        }

        for (int a = 0; a < cfb.keySize / 8; a++){
            cfbKey[a] = a;
        }



        cfbPlainText[cfb.pSize] = '\0';
        cfbShiftReg[cfb.pSize] = '\0';

        cfb.plaintext = cfbPlainText;
        cfb.ciphertext = cfbCipherText;
        cfb.iv = cfbInitVector;
        cfb.shiftRegister = cfbShiftReg;
        cfb.key = cfbKey;

        encryptCFB(&cfb, 0);

        printf("CFB encryption: \t");
        printArr(cfb.ciphertext, cfb.pSize, 'x');
        printf("\n");

        for (int a = 0; a < cfb.pSize; a++){
            cfbPlainText[a] = 1;
        }

        decryptCFB(&cfb, 0);
        printf("CFB decryption: \t");
        printArr(cfb.plaintext, cfb.pSize, 'x');
    }

    if (armandt_aes == 1){
        printf("\n\n=================Armandt AES Section=================\n\n");
//    unsigned char myMessage[] = "My name is Armandt and I'm trying to encrypt this message.";   //59 chars
        unsigned char myMessage[] = "abcdefghijklmno";   //59 chars
        unsigned char myKey[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        int keyLength = 128;
        int rounds = 9;
        int expandedSize = 176;
        set_key_length(128);

        int myMessageLength = strlen(myMessage);
        int paddedLength = myMessageLength;

        if (paddedLength % 16 != 0){
            paddedLength = (paddedLength / 16 + 1) * 16;
        }

        unsigned char paddedMessage[paddedLength + 1];
        paddedMessage[paddedLength] = '\0';
        for (int a = 0; a < paddedLength; a++){
            if (a >= myMessageLength){
                paddedMessage[a] = 0;
            } else {
                paddedMessage[a] = myMessage[a];
            }
        }

        unsigned char encryptedMessage[paddedLength];

        unsigned char blockToEncrypt[17];
        for (int a = 0; a < 17; a++){
            blockToEncrypt[a] = paddedMessage[a];
        }

        AES_encrypt(blockToEncrypt, myKey);

        for (int a = 0; a< 16; a++){
            encryptedMessage[a] = blockToEncrypt[a];
        }

        printArr(myMessage, 16, 'c');
        printArr(encryptedMessage, 16, 'x');

        unsigned char decryptedMessage[17];
        decryptedMessage[16] = '\0';

        for (int a = 0; a < 16; a++){
            decryptedMessage[a] = encryptedMessage[a];
        }

        AES_decrypt(decryptedMessage, myKey);
        printArr(decryptedMessage, 16, 'c');

        printf("\n\n======Pad And Encrypt and General Decrypt Section======\n\n");
        unsigned char * newArray1 = NULL;
        unsigned char * newArray2 = NULL;
        unsigned char * newArray3 = NULL;
        unsigned char testMessage1[] = "this is a test m";
        unsigned char testMessage2[] = "essage help me!!";
        unsigned char testMessage3[] = "this is a test message help me!?";
        unsigned char storage[33];
        printArr(testMessage1, 16, 'c');
        newArray1 = pad_and_encrypt(testMessage1, storage, 16,128, myKey);
        printArr(newArray1, 16, 'x');
        unsigned char * decrypter;
        general_decrypt(storage, 16, 128, myKey);
        printArr(storage, strlen(storage), 'c');
//
        newArray2 = pad_and_encrypt(testMessage2, storage, 16, 128, myKey);
        printArr(storage, 16, 'x');
        decrypter = general_decrypt(storage, 16, 128, myKey);
        printArr(storage, strlen(storage), 'c');
//
        newArray3 = pad_and_encrypt(testMessage3, storage, 32, 128, myKey);
        printArr(storage, 32, 'x');
        decrypter = general_decrypt(storage, 32, 128, myKey);
        printArr(storage, 32, 'c');
//    AES_decrypt(newArray, myKey);
//    printArr(newArray1, strlen(decrypter), 'c');
    }

    if (michelle_aes == 1){
        printf("\n\n==================MICHELLE AES Section==================\n\n");

        unsigned char message[]= "This is the message is a secret";
        unsigned char key[] =  {1, 2, 3, 4, 6, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 6, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        // unsigned char key[] =  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        //unsigned char key[] =  {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5,  6,  7, 8 };
        // unsigned char key[] =  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        // 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
        //unsigned char key[] =  {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
        // 0x05, 0x06, 0x07, 0x08 , 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        printf("Enter key length: ");

        scanf("%d", &key_length); ///get the response from the user
        printf("%d", key_length);
        if(key_length == 128)    {
            number_of_rounds = 9;
            expanded_key_size = 176;

        }
        else if (key_length == 192) {
            number_of_rounds = 11;
            expanded_key_size = 208;
        }
        else if (key_length == 256) {
            number_of_rounds = 13;
            expanded_key_size = 240;
        }

        set_key_length(key_length);

        //Zero padding
        int original_length = strlen(message);
        int length_of_padded_message = original_length;

        if(length_of_padded_message % 16 != 0)
            length_of_padded_message = (length_of_padded_message / 16 + 1) * 16; // rounding the length to a multiple of 16

        unsigned char padded_message[length_of_padded_message+1];

        for(int i = 0; i < length_of_padded_message; i++)
        {
            if(i >= original_length)
                padded_message[i] = '0';
            else
                padded_message[i] = message[i];
        }
        padded_message[length_of_padded_message]='\0';// apparently very important :|

        unsigned char encrypted_message[length_of_padded_message];
        // unsigned char expanded_key[expanded_key_size];
        //key_expansion(key, expanded_key);



        //Encrypt padded message
        for(int i = 0; i < length_of_padded_message; i += 16)
        {
            unsigned char block_to_encrypt[17];

            for(int j = 0; j < 17; j++)
                block_to_encrypt[j] = padded_message[i+j];

            block_to_encrypt[16] = '\0';
            AES_encrypt(block_to_encrypt, key);

            for(int j = 0; j < 16; j++)
                encrypted_message[j+i] = block_to_encrypt[j];

            //printf("%s",block_to_encrypt);
//        printf("\nblock_to_encrypt");
//        printf("*********************\n");
//        print_hex(block_to_encrypt, 16);
//        AES_encrypt(block_to_encrypt, key);
//        printf("\nEncrypted block_to_encrypt");
//        printf("*********************\n");
//        print_hex(block_to_encrypt, 16);
//        for(int j = 0; j < 16; j++)
//            encrypted_message[j+i] = block_to_encrypt[j];

        }


        printf("\nEncrypted Message: \n");

        print_hex(encrypted_message, 32);
        printf("\n");


        printf("\nMessage Hex: \n");
        print_hex(message, 32);




        //Decrypt padded message
        unsigned char decrypted_message[length_of_padded_message];
        for(int i = 0; i < length_of_padded_message; i += 16)
        {
            unsigned char block_to_decrypt[17];

            for(int j = 0; j < 17; j++)
                block_to_decrypt[j] = encrypted_message[i+j];

            block_to_decrypt[16] = '\0';
            AES_decrypt(block_to_decrypt, key);

            for(int j = 0; j < 16; j++)
                decrypted_message[j+i] = block_to_decrypt[j];

        }
        printf("\nDecrypted message\n");
        print_hex(decrypted_message, 32);
        for(int i = 0; i < 32; i ++)
            printf("%c", decrypted_message[i]);

        unsigned char test[] = {0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x2e};
//    test_functionality(test);
    }

    if (files_test == 1){
        unsigned char fileName[] = "/home/armandt/Documents/EHN/EHN/prac2/armandt/main.c";
        long int s = getFileSize(fileName);
        unsigned char fileBuffer[s];

        readFile(fileName, fileBuffer);

//        printArr(fileBuffer, s, 'c');

        struct CBC c;
        c.pSize = s;
        c.blockSize = 16;
        c.cSize = (c.pSize / 16 + 1) * 16;
        c.keySize = 128;
        unsigned char text1[c.pSize + 1];
        unsigned char k[c.blockSize + 1];
        unsigned char iv[c.blockSize + 1];
        unsigned char text[c.cSize + 1];

        for (int a = 0; a < s; a++){
            text1[a] = fileBuffer[a];
        }
        for (int a = 0; a < c.cSize; a++){
            text[a] = 0;
        }
        for (int a = 0; a < 128 / 8; a++){
            k[a] = a;
            iv[a] = 0;
        }

        c.plaintext = text1;
        c.ciphertext = text;
        c.iv = iv;
        c.key = k;

        printf("Encrypting using CBC.\n");
        iterativeEncryptCBC(&c);
        printf("Done.\n");
//        printArr(c.ciphertext, c.cSize, 'x');
        unsigned char newName[] = "/home/armandt/Documents/EHN/EHN/prac2/armandt/mainCBC.c";
        saveFile(newName, c.ciphertext, c.cSize);

        for (int a = 0; a < s; a++){
            c.plaintext[a] = 0;
        }//clear the plaintext to be sure

        for (int a = 0; a < c.cSize; a++){
            c.ciphertext[a] = 0;
        }//clear the ciphertext
//        decryptCBC(&c, 0);

//        printArr(c.plaintext, c.pSize, 'c');



        readFile(newName, c.ciphertext);
        printf("Decrypting.\n");
        iterativeDecryptCBC(&c);
        printf("Done.\n");
//        printArr(c.plaintext, c.pSize, 'c');

        unsigned char newName2[] = "/home/armandt/Documents/EHN/EHN/prac2/armandt/mainCBCDec.c";
        saveFile(newName2, c.plaintext, c.pSize);

        long int s1 = getFileSize(fileName);
        struct CFB cfb;
        cfb.pSize = s1;
        cfb.shiftRegSize = 32;
        cfb.blockSize = 16;
        cfb.keySize = 128;

        unsigned char cfbPlainText[cfb.pSize + 1];
        unsigned char cfbInitVector[cfb.shiftRegSize];
        unsigned char cfbCipherText[cfb.pSize + 1];
        unsigned char cfbShiftReg[cfb.shiftRegSize];
        unsigned char cfbKey[16];

        for (int a = 0; a < cfb.shiftRegSize; a++){
            cfbShiftReg[a] = cfbInitVector[a] = 0;
        }

        for (int a = 0; a < cfb.pSize; a++){
            cfbPlainText[a] = 0;
            cfbShiftReg[a] = 0;
            cfbCipherText[a] = 0;
        }

        for (int a = 0; a < cfb.keySize / 8; a++){
            cfbKey[a] = a;
        }

        readFile(fileName, cfbPlainText);

        cfbPlainText[cfb.pSize] = '\0';
        cfbShiftReg[cfb.pSize] = '\0';

        cfb.plaintext = cfbPlainText;
        cfb.ciphertext = cfbCipherText;
        cfb.iv = cfbInitVector;
        cfb.shiftRegister = cfbShiftReg;
        cfb.key = cfbKey;

        printf("Encrypting with CFB.\n");
        iterativeEncryptCFB(&cfb);
        printf("Done.\n");
        unsigned char newName3[] = "/home/armandt/Documents/EHN/EHN/prac2/armandt/mainCFB.c";
        saveFile(newName3, cfb.ciphertext, cfb.pSize);

        for (int a = 0; a < cfb.pSize; a++){
            cfb.plaintext[a] = 0;
            cfb.ciphertext[a] = 0;
        }

        readFile(newName3, cfb.ciphertext);
        printf("Decrypting.\n");
        iterativeDecryptCFB(&cfb);
        printf("Done.\n");
        unsigned char newName4[] = "/home/armandt/Documents/EHN/EHN/prac2/armandt/mainCFBDec.c";
        saveFile(newName4, cfb.plaintext, cfb.pSize);
    }
    return 0;
}
