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
void AES_encrypt(unsigned char* message, unsigned char* key);
void AES_decrypt(unsigned char* message, unsigned char* key);
void print_hex(const unsigned char *string, int count);
void set_key_length(int l);
void set_number_of_rounds(int r);
void set_expanded_key_size(int s);

#endif //ARMANDT_MICHELLE_H
