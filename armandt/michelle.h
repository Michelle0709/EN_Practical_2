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

//Functions wat ek by gesit het
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

#endif //ARMANDT_MICHELLE_H
