//
// Created by armandt on 2020/04/07.
//

#ifndef ARMANDT_MICHELLE_H
#define ARMANDT_MICHELLE_H

/**
 * @brief The key expansion core is used in the key expansion method and contains 3 steps. 1) Rotate left. 2) S-box on all four bytes. 3) XOR with RCons
 * @param in A temporary 4 bytes used to generates the expanded key.
 * @param i The RCon iteration index
 */
void key_expansion_core(unsigned char* in, unsigned char i);
/**
 * @brief This method expands the original key to the appropriate expanded key, to provide enough round keys for the AES function.
 * @param input_key The original key.
 * @param expanded_key The final expanded to to be used by the AES algorithm.
 */
void key_expansion(unsigned char* input_key, unsigned char* expanded_key);
/**
 * @brief Uses the S-box table to perform a byte-by-byte substitution of the current state.
 * @param state The 128-bit block is copied to a state which is modified at each stage of the encryption.
 */
void sub_bytes(unsigned char* state);
/**
 * @brief Uses the inverse S-box table to perform a byte-by-byte substitution of the current state.
 * @param state The 128-bit block is copied to a state which is modified at each stage of the decryption.
 */
void inverse_sub_bytes(unsigned char* state);
/**
 * @brief A simple permutation which is performed row by row
 * @param state The 128-bit block is copied to a state which is modified at each stage of the encryption.
 */
void shift_rows(unsigned char* state);
/**
 * @brief A simple permutation which is performed row by row
 * @param state The 128-bit block is copied to a state which is modified at each stage of the decryption.
 */
void inverse_shift_rows(unsigned char* state);
/**
 * @brief A substitution that alters each byte in a column as a function of all of the bytes in the column.
 * @param state The 128-bit block is copied to a state which is modified at each stage of the decryption.
 */
void mix_columns(unsigned char* state );
/**
 * @brief A substitution that alters each byte in a column as a function of all of the bytes in the column.
 * @param state The 128-bit block is copied to a state which is modified at each stage of the decryption.
 */
void inverse_mix_columns(unsigned char* state );
/**
 * @brief A simple bitwise XOR of the current block with a portion of the expanded key.
 * @param state The 128-bit block is copied to a state which is modified at each stage of the decryption.
 * @param round_key The portion of the expanded key used in a particular round.
 */
void add_round_key(unsigned char* state, unsigned char* round_key);

/**
 * @brief Uses AES method to encrypt a message using the provided key. The encrypted
 * message is stored in the message array that it passed in.
 * @param message the plaintext that will be encrypted.
 * @param key The key used by the algorithm
 */
void AES_encrypt(unsigned char* message, unsigned char* key);
/**
 * @brief Uses AES method to decrypt a message using the provided key. The decrypted
 * message is stored in the message array that it passed in.
 * @param message The encrypted message that will be decrypted.
 * @param key The key used by the algorithm
 */
void AES_decrypt(unsigned char* message, unsigned char* key);
/**
 * @brief Simply prints the input string in a hex format.
 * @param string The message to be printed in hex format.
 * @param count The number of characters that will be printed
 */
void print_hex(const unsigned char *string, int count);
/**
 * @brief Prints the input string in a hex, in a 4x4 block format.
 * @param string The message to be printed in hex format.
 */
void print_hex_block(const char *string);
/**
 * @brief Displays each individual functions results independently.
 * @param string The message to be passed into each individual function.
 * @param key_length The length of the input key.
 * @param key The input key.
 */
void test_functionality(unsigned char *input_string, int key_length, unsigned char* key);

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
 * @param message_len Length of the message to be encrypted in bytes.
 * @param encrypted The array where the encrypted message is stored
 * @param key_length The length of the key in bits
 * @param key The key used for encryption
 * @return Returns an array containing the encrypted message
 */
unsigned char* pad_and_encrypt(unsigned char * message, unsigned char * encrypted, int message_len, int key_length, unsigned char * key);

/**
 * @brief Takes a longer encrypted message and decrypts it, returning an array containing the decrypted message
 * @param message The encrypted message
 * @param massage_len The length of the message in bytes
 * @param key_length Length of the key in bits
 * @param key The key used for encryption
 * @return An array containing the message that has been decrypted (possibly padded with zeros)
 */
unsigned char* general_decrypt(unsigned char * message, int message_len, int key_length, unsigned char * key);


#endif //ARMANDT_MICHELLE_H
