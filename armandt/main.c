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

    struct CBC c;

    c.pSize = 30;
    c.blockSize = 16;
    c.cSize = 32;
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

    printf("CBC encryption: \t");
    for (int a = 0; a < c.cSize; a++){
        printf("%x ", c.ciphertext[a]);
    }
    printf("\n\n");

    decryptCBC(&c, 0);

    printf("CBC decryption: \t");
    for (int a = 0; a < c.cSize; a++){
        printf("%x ", c.plaintext[a]);
    }
    printf("\n\n");

    return 0;

//    unsigned char shiftRegister[5] = {'a', 'b', 'c', 'd', 'e'};
//    unsigned char newBytes[2] = {'f', 'g'};
//    shiftBytesIn(shiftRegister, 5, newBytes, 2);
//
//    printArr(shiftRegister, 5);
//
//    dummyEncryptionFunction(shiftRegister, 5);
//    printArr(shiftRegister, 5);
//    dummyDecryptionFunction(shiftRegister, 5);
//    printArr(shiftRegister, 5);

    printf("\n===============CFB SECTION===============\n");

    unsigned char cfbPlainText[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
    unsigned char cfbInitVector[8] = {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};
    unsigned char cfbCipherText[16];
    unsigned char cfbShiftReg[8];

    for (int a = 0; a < 8; a++){
        cfbShiftReg[a] = cfbInitVector[a];
    }

    struct CFB cfb;
    cfb.plaintext = cfbPlainText;
    cfb.ciphertext = cfbCipherText;
    cfb.iv = cfbInitVector;
    cfb.shiftRegister = cfbShiftReg;
    cfb.pSize = 16;
    cfb.shiftRegSize = 8;
    cfb.blockSize = 4;

    encryptCFB(&cfb, 0);

    printf("CFB encryption: \t");
    printArr(cfb.ciphertext, 16, 'x');
    printf("\n");

    decryptCFB(&cfb, 0);
    printf("CFB decryption: \t");
    printArr(cfb.plaintext, 16, 'c');



    printf("\n\n==================AES Section==================\n\n");

    printf("Enter the key length:\n");
    printf("> ");
    scanf("%d", &key_length); ///get the response from the user
//    printf("%d\n", key_length);

    unsigned char message[]= "This is the message is a secret";
//    printf("Enter the message to encrypt:\n");
//    printf("> ");
//    scanf("%s", &message);
    unsigned char key[] =  {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    // unsigned char key[] =  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //unsigned char key[] =  {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5,  6,  7, 8 };

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

    //Armandt added this when he moves the AES functions to their own file
    set_key_length(key_length);
    set_expanded_key_size(expanded_key_size);
    set_number_of_rounds(number_of_rounds);

//    Zero padding
    int original_length = strlen(message);
//    int original_length = 31;
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
    //unsigned char expanded_key[expanded_key_size];
    //key_expansion(key, expanded_key);

    //Encrypt padded message
    for(int i = 0; i < length_of_padded_message; i += 16)
    {
        unsigned char block_to_encrypt[17];

        for(int j = 0; j < 17; j++)
            block_to_encrypt[j] = padded_message[i+j];

        block_to_encrypt[16] = '\0';
        // AES_encrypt(block_to_encrypt, key);

//        for(int j = 0; j < 16; j++)
//            encrypted_message[j+i] = block_to_encrypt[j];

        //printf("%s",block_to_encrypt);
        printf("\nblock_to_encrypt");
        printf("*********************\n");
        print_hex(block_to_encrypt, 16);
        AES_encrypt(block_to_encrypt, key);
        printf("\nEncrypted block_to_encrypt");
        printf("*********************\n");
        print_hex(block_to_encrypt, 16);
        for(int j = 0; j < 16; j++)
            encrypted_message[j+i] = block_to_encrypt[j];

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

//        printf("\nblock_to_decrypt\n");
//        print_hex(block_to_decrypt, 16);
//        AES_decrypt(block_to_decrypt, key);
//
//        printf("*********************\n");
//        print_hex(block_to_decrypt, 32);


    }
    printf("\nDecrypted message\n");
    print_hex(decrypted_message, 32);
    printf("%s\n", decrypted_message+10);



    return 0;
}
