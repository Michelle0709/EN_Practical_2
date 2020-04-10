//
// Created by armandt on 2020/04/07.
//

#ifndef ARMANDT_MICHELLE_H
#define ARMANDT_MICHELLE_H

void key_expansion_core(unsigned char* in, unsigned char i);
void key_expansion(unsigned char* input_key, unsigned char* expanded_key);
void sub_bytes(unsigned char* state);
void inverse_sub_bytes(unsigned char* state);
void shift_rows(unsigned char* state);
void inverse_shift_rows(unsigned char* state);
void mix_columns(unsigned char* state );
void inverse_mix_columns(unsigned char* state );
void add_round_key(unsigned char* state, unsigned char* round_key);

/**
 * @brief Uses AES method to encrypt a message using the provided key. The encrypted
 * message is stored in the message array that it passed in.
 * @param message The plaintext that will be encrypted.
 * @param key The key used by the algorithm
 */
void AES_encrypt(unsigned char* message, unsigned char* key);

void AES_decrypt(unsigned char* message, unsigned char* key);
void print_hex(const unsigned char *string, int count);
void print_hex_block(const char *string);
void test_functionality(unsigned char *input_string);

    //Functions wat Armandt by gesit het
    /**
 * @brief Sets the key length, number of rounds and expanded key size.
 * @param l Length of the key in bits
 */
    void set_key_length(int l);

/**
 * @brief Set the number_of_rounds variable
 * @param r Number of rounds
 */
void set_number_of_rounds(int r);

/**
 * @brief Set the expanded_key_size variable
 * @param s Expanded key size
 */
void set_expanded_key_size(int s);

/**
 * @brief A function that combines zero padding and encryption of an
 * arbitrarily-sized char array using AES_encrypt. This function will also
 * call the set_key_length function to initialise those variables.
 * @param message The char array that must be encrypted
 * @param key_length The length of the key in bits
 * @param key The key used for encryption
 * @return Returns an array containing the encrypted message
 */
unsigned char* pad_and_encrypt(unsigned char * message, int key_length, unsigned char * key);

/**
 * @brief Takes a longer encrypted message and decrypts it, returning an array containing the decrypted message
 * @param message The encrypted message
 * @param key_length Length of the key in bits
 * @param key The key used for encryption
 * @return An array containing the message that has been decrypted (possibly padded with zeros)
 */
unsigned char* general_decrypt(unsigned char * message, int key_length, unsigned char * key);


#endif //ARMANDT_MICHELLE_H
