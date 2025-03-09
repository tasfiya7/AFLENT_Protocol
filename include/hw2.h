#ifndef __HW2_H
#define __HW2_H

#define INFO(...) do {fprintf(stderr, "[          ] [ INFO ] "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr);} while(0)
#define ERROR(...) do {fprintf(stderr, "[          ] [ ERR  ] "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr);} while(0) 

#define EXPANDED_KEYS_LENGTH 32

#include <stdint.h>



void print_packet(unsigned char packet[]);

unsigned char* build_packets(int data[], int data_length, int max_fragment_size, int endianness, int array_number);

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths);



// PART IV

typedef uint64_t sbu_key_t;
typedef uint32_t block_t;
typedef block_t (*permute_func_t)(block_t);

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys);

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys);

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys);


block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys);
block_t sbu_encrypt_block_debug(block_t plain_text, block_t *expanded_keys);
block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys);
block_t sbu_decrypt_block_debug(block_t cipher_text, block_t *expanded_keys);


uint8_t rotl(uint8_t x, uint8_t shamt);
uint8_t rotr(uint8_t x, uint8_t shamt);

block_t reverse(block_t x);
block_t shuffle4(block_t x);
block_t unshuffle4(block_t x);
block_t shuffle1(block_t x);
block_t unshuffle1(block_t x);

uint8_t nth_byte(block_t x, uint8_t n);


void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys);


uint8_t scramble_op(block_t B, uint8_t i, block_t keyA, block_t keyB);

uint8_t mash_op(block_t B, uint8_t i, block_t *keys);

block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op);

block_t mash(block_t x, block_t *keys);


block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys);

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys);


uint8_t r_scramble_op(block_t B, uint8_t i, block_t keyA, block_t keyB);

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op);

block_t r_mash(block_t x, block_t *keys);




#endif // HW2_H
