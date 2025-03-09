#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#include <sys/mman.h>
#include <math.h>
#include <sys/stat.h>
#include <errno.h>



typedef struct {
    int frag_num;          
    int frag_length;       
    int endianness;        // 0 = big-endian, 1 = little-endian
    int last;              
    unsigned char *payload; 
} frag_info;

//Packet Code:

void print_packet(unsigned char packet[]){
	int array_number = (packet[0] & 0xFC) >> 2;
	int fragment_number = ((packet[0] & 0x03) << 3) | ((packet[1] & 0xE0) >> 5);
	int length = ((packet[1] & 0x1F) << 5) | ((packet[2] & 0xF8) >> 3);
	int encrypted = (packet[2] & 0x04) >> 2;
	int endianness = (packet[2] & 0x02) >> 1;
	int last = (packet[2] & 0x01);

	printf("Array Number: %d\n", array_number);
    printf("Fragment Number: %d\n", fragment_number);
    printf("Length: %d\n", length);
    printf("Encrypted: %d\n", encrypted);
    printf("Endianness: %d\n", endianness);
    printf("Last: %d\n", last);

	//Data:
	unsigned char *payload = &packet[3];
	printf("Data: ");
	for (int i = 0; i<length; i++){
		int value;
		if (endianness==1){
			value = (payload[i * 4]) | (payload[i * 4 + 1] << 8) | (payload[i * 4 + 2] << 16) | (payload[i * 4 + 3] << 24);
		} else{
			value = (payload[i * 4] << 24) | (payload[i * 4 + 1] << 16) | (payload[i * 4 + 2] << 8) | (payload[i * 4 + 3]);
		}
		printf("%x", value);
		if (i<length-1){
			printf(" ");
		}
	}
	printf("\n");
}

unsigned char* build_packets(int data[], int data_length, int max_fragment_size, int endianness, int array_number){

	int max_ints_per_fragment = max_fragment_size / 4; 
	int num_fragments = (data_length + max_ints_per_fragment - 1) / max_ints_per_fragment;

	int total_bytes = num_fragments * (3 + (max_ints_per_fragment * 4)); // Total memory
    unsigned char *packets = (unsigned char*)malloc(total_bytes);
    
    if (!packets) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    int data_index = 0;
    unsigned char *current_packet = packets;

	for (int frag_num = 0; frag_num < num_fragments; frag_num++) {
        int remaining_data = data_length - data_index;
        int fragment_length = (remaining_data < max_ints_per_fragment) ? remaining_data : max_ints_per_fragment;

		//header
		current_packet[0] = (array_number << 2) | ((frag_num >> 3) & 0x03);
        current_packet[1] = ((frag_num & 0x07) << 5) | ((fragment_length >> 5) & 0x1F);
        current_packet[2] = ((fragment_length & 0x1F) << 3) | (endianness << 1) | ((frag_num == num_fragments - 1) ? 1 : 0);

		//payload
		unsigned char *payload = &current_packet[3];
        for (int i = 0; i < fragment_length; i++) {
            int value = data[data_index++];
		
			if (endianness == 1) { // liitle e
                payload[i * 4] = value & 0xFF;
                payload[i * 4 + 1] = (value >> 8) & 0xFF;
                payload[i * 4 + 2] = (value >> 16) & 0xFF;
                payload[i * 4 + 3] = (value >> 24) & 0xFF;
            } else { // Big e
                payload[i * 4] = (value >> 24) & 0xFF;
                payload[i * 4 + 1] = (value >> 16) & 0xFF;
                payload[i * 4 + 2] = (value >> 8) & 0xFF;
                payload[i * 4 + 3] = value & 0xFF;
            }
        }
		current_packet += (3 + fragment_length * 4);
    }

    return packets;
}


static int compute_total_bytes(unsigned char packets[], int array_count) {
    int index = 0;
    int complete_count = 0;
    int *frag_count = calloc(array_count, sizeof(int));
    int *expected = calloc(array_count, sizeof(int));
    bool *complete = calloc(array_count, sizeof(bool));
    if (!frag_count || !expected || !complete) {
        fprintf(stderr, "Memory allocation error in compute_total_bytes.\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < array_count; i++) {
        expected[i] = -1;
        complete[i] = false;
    }
    
    while (complete_count < array_count) {
        unsigned char h0 = packets[index];
        unsigned char h1 = packets[index + 1];
        unsigned char h2 = packets[index + 2];
        
        int arr_num = (h0 & 0xFC) >> 2;
        int frag_num = ((h0 & 0x03) << 3) | ((h1 & 0xE0) >> 5);
        int frag_length = ((h1 & 0x1F) << 5) | ((h2 & 0xF8) >> 3);
        int last_flag = h2 & 0x01;
        int packet_size = 3 + frag_length * 4;
        
        if (arr_num < array_count) {
            frag_count[arr_num]++;
            if (last_flag) {
                expected[arr_num] = frag_num + 1;
            }
            if (expected[arr_num] != -1 && frag_count[arr_num] == expected[arr_num] && !complete[arr_num]) {
                complete[arr_num] = true;
                complete_count++;
            }
        }
        index += packet_size;
    }
    
    free(frag_count);
    free(expected);
    free(complete);
    return index;
}



int** create_arrays(unsigned char packets[], int array_count, int *array_lengths){	

	int i, j;
    
    int total_bytes = compute_total_bytes(packets, array_count);
    
    // First pass
    for (i = 0; i < array_count; i++) {
        array_lengths[i] = 0;
    }
    int index = 0;
    while (index < total_bytes) {
        unsigned char h0 = packets[index];
        unsigned char h1 = packets[index + 1];
        unsigned char h2 = packets[index + 2];
        
        int arr_num = (h0 & 0xFC) >> 2;
        int frag_length = ((h1 & 0x1F) << 5) | ((h2 & 0xF8) >> 3);
        int packet_size = 3 + frag_length * 4;
        
        if (arr_num < array_count) {
            array_lengths[arr_num] += frag_length;
        }
        index += packet_size;
    }
    
    int **result = malloc(array_count * sizeof(int *));
    if (!result) {
        fprintf(stderr, "Memory allocation error for result arrays.\n");
        exit(EXIT_FAILURE);
    }
    
    int max_frags = 32;
    frag_info **frag_lists = malloc(array_count * sizeof(frag_info *));
    int *frag_counts = calloc(array_count, sizeof(int));
    if (!frag_lists || !frag_counts) {
        fprintf(stderr, "Memory allocation error for fragment info arrays.\n");
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < array_count; i++) {
        frag_lists[i] = malloc(max_frags * sizeof(frag_info));
        if (!frag_lists[i]) {
            fprintf(stderr, "Memory allocation error for fragment list of array %d.\n", i);
            exit(EXIT_FAILURE);
        }
    }
    
    // Second pass
    index = 0;
    while (index < total_bytes) {
        unsigned char h0 = packets[index];
        unsigned char h1 = packets[index + 1];
        unsigned char h2 = packets[index + 2];
        
        int arr_num = (h0 & 0xFC) >> 2;
        int frag_num = ((h0 & 0x03) << 3) | ((h1 & 0xE0) >> 5);
        int frag_length = ((h1 & 0x1F) << 5) | ((h2 & 0xF8) >> 3);
        int endianness = (h2 & 0x02) >> 1;
        int last_flag = h2 & 0x01;
        int packet_size = 3 + frag_length * 4;
        
        if (arr_num < array_count) {
            int pos = frag_counts[arr_num];
            frag_lists[arr_num][pos].frag_num = frag_num;
            frag_lists[arr_num][pos].frag_length = frag_length;
            frag_lists[arr_num][pos].endianness = endianness;
            frag_lists[arr_num][pos].last = last_flag;
            frag_lists[arr_num][pos].payload = &packets[index + 3];
            frag_counts[arr_num]++;
        }
        index += packet_size;
    }
    
    for (i = 0; i < array_count; i++) {
        for (j = 0; j < frag_counts[i] - 1; j++) {
            for (int k = j + 1; k < frag_counts[i]; k++) {
                if (frag_lists[i][j].frag_num > frag_lists[i][k].frag_num) {
                    frag_info temp = frag_lists[i][j];
                    frag_lists[i][j] = frag_lists[i][k];
                    frag_lists[i][k] = temp;
                }
            }
        }
    }
    
    for (i = 0; i < array_count; i++) {
        result[i] = malloc(array_lengths[i] * sizeof(int));
        if (!result[i]) {
            fprintf(stderr, "Memory allocation error for array %d.\n", i);
            exit(EXIT_FAILURE);
        }
        int offset = 0;
        for (j = 0; j < frag_counts[i]; j++) {
            int frag_length = frag_lists[i][j].frag_length;
            unsigned char *payload = frag_lists[i][j].payload;
            int endian = frag_lists[i][j].endianness;
            for (int k = 0; k < frag_length; k++) {
                int value;
                if (endian == 1) { 
                    value = payload[k * 4] |
                           (payload[k * 4 + 1] << 8) |
                           (payload[k * 4 + 2] << 16) |
                           (payload[k * 4 + 3] << 24);
                } else { 
                    value = (payload[k * 4] << 24) |
                           (payload[k * 4 + 1] << 16) |
                           (payload[k * 4 + 2] << 8) |
                           payload[k * 4 + 3];
                }
                result[i][offset++] = value;
            }
        }
    }
    
    for (i = 0; i < array_count; i++) {
        free(frag_lists[i]);
    }
    free(frag_lists);
    free(frag_counts);
    
    return result;
	
}


//Encryption Code:

#define EXPANDED_KEYS_LENGTH 32

typedef uint64_t sbu_key_t;
typedef uint32_t block_t;
typedef block_t(*permute_func_t)(block_t);

block_t table[] = { 
    0x6a09e667, 0xbb67ae84, 0x3c6ef372, 0xa54ff539, 0x510e527f, 0x9b05688b, 0x1f83d9ab, 0x5be0cd18, 
    0xcbbb9d5c, 0x629a2929, 0x91590159, 0x152fecd8, 0x67332667, 0x8eb44a86, 0xdb0c2e0c, 0x47b5481d, 
    0xae5f9156, 0xcf6c85d2, 0x2f73477d, 0x6d1826ca, 0x8b43d456, 0xe360b595, 0x1c456002, 0x6f196330, 
    0xd94ebeb0, 0x0cc4a611, 0x261dc1f2, 0x5815a7bd, 0x70b7ed67, 0xa1513c68, 0x44f93635, 0x720dcdfd, 
    0xb467369d, 0xca320b75, 0x34e0d42e, 0x49c7d9bd, 0x87abb9f1, 0xc463a2fb, 0xec3fc3f2, 0x27277f6c, 
    0x610bebf2, 0x7420b49e, 0xd1fd8a32, 0xe4773593, 0x092197f5, 0x1b530c95, 0x869d6342, 0xeee52e4e, 
    0x11076689, 0x21fba37b, 0x43ab9fb5, 0x75a9f91c, 0x86305019, 0xd7cd8173, 0x07fe00ff, 0x379f513f, 
    0x66b651a8, 0x764ab842, 0xa4b06be0, 0xc3578c14, 0xd2962a52, 0x1e039f40, 0x857b7bed, 0xa29bf2de
};




// ----------------- Bitwise Functions ----------------- //

uint8_t rotl(uint8_t x, uint8_t shamt)
{
    shamt = shamt % 8;
    return (x << shamt) | (x >> (8 - shamt));
}

uint8_t rotr(uint8_t x, uint8_t shamt)
{
    shamt = shamt % 8;
    return (x >> shamt) | (x << (8 - shamt));
}

block_t reverse(block_t x)
{
    block_t result = 0;
    for (int i = 0; i < 32; i++) {
        if ((x & (1u << i)) != 0) {
            result |= (1u << (31 - i));
        }
    }
    return result;
}

block_t shuffle4(block_t x)
{
    block_t upper = x >> 16;  
    block_t lower = x & 0xFFFF; 
    block_t result = 0;
    
    for (int i = 0; i < 4; i++) {
        result |= ((upper >> (12 - 4*i)) & 0xF) << (28 - 8*i);
        result |= ((lower >> (12 - 4*i)) & 0xF) << (24 - 8*i);
    }
    
    return result;
}

block_t unshuffle4(block_t x)
{
    block_t upper = 0;
    block_t lower = 0;
    
    for (int i = 0; i < 4; i++) {
        upper |= ((x >> (28 - 8*i)) & 0xF) << (12 - 4*i);
        lower |= ((x >> (24 - 8*i)) & 0xF) << (12 - 4*i);
    }
    
    return (upper << 16) | lower;
}

block_t shuffle1(block_t x)
{
    block_t upper = x >> 16;  
    block_t lower = x & 0xFFFF;  
    block_t result = 0;
    
    for (int i = 0; i < 16; i++) {
        result |= ((upper >> i) & 1) << (2*i + 1);
        result |= ((lower >> i) & 1) << (2*i);
    }
    
    return result;
}

block_t unshuffle1(block_t x)
{
    block_t upper = 0;
    block_t lower = 0;
    
    for (int i = 0; i < 16; i++) {
        upper |= ((x >> (2*i + 1)) & 1) << i;
        lower |= ((x >> (2*i)) & 1) << i;
    }
    
    return (upper << 16) | lower;
}

uint8_t nth_byte(block_t x, uint8_t n)
{
    n = n % 4; 
    return (x >> (8 * n)) & 0xFF;
}



// ----------------- Encryption Functions ----------------- //

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys){

    expanded_keys[0] = (block_t)(key & 0xFFFFFFFFULL);
    expanded_keys[1] = (block_t)(key >> 32);
    for (int i = 2; i < EXPANDED_KEYS_LENGTH; i++) {
        uint32_t temp = expanded_keys[i - 1] ^ expanded_keys[i - 2];
        int idx = temp % 64;
        expanded_keys[i] = table[idx] ^ expanded_keys[i - 1];
    }
    for (int i = EXPANDED_KEYS_LENGTH - 3; i >= 0; i--) {
        uint32_t temp = expanded_keys[i + 1] ^ expanded_keys[i + 2];
        int idx = temp % 64;
        expanded_keys[i] = table[idx] ^ expanded_keys[i];
    }

}

static inline block_t set_byte(block_t x, int i, uint8_t byte_val) {
    x &= ~(0xFFUL << (8 * i));
    x |= ((block_t)byte_val << (8 * i));
    return x;
}

block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
    static const uint8_t rot_table[] = {2, 3, 5, 7};
    block_t keyA = keys[round];
    block_t keyB = keys[31 - round];
    x = op(x);
    for (int i = 0; i < 4; i++) {
        uint8_t b_i = nth_byte(x, i);
        uint8_t i_1 = nth_byte(x, i-1);
        uint8_t i_2 = nth_byte(x, i-2);
        uint8_t i_3 = nth_byte(x, i-3);
        uint8_t key_a_i = nth_byte(keyA, i);
        uint8_t key_b_i = nth_byte(keyB, i);
        uint8_t b1 = b_i ^ (i_1 & i_2) ^ ((~i_1) & i_3) ^ key_a_i ^ key_b_i;
        uint8_t rotate = rotl(b1, rot_table[i % 4]);
        x = set_byte(x, i, rotate);

    }
    
    return x;
}

block_t mash(block_t x, block_t *keys)
{
    for (int i = 0; i < 4; i++) {
        uint8_t b_i = nth_byte(x, i);
        uint8_t i_1 = nth_byte(x, i-1);
        block_t key = keys[i_1 % 32];
        uint8_t key_i = nth_byte(key, i);
        uint8_t mashed = b_i ^ key_i;
        x = set_byte(x, i, mashed);
    }
    
    return x;
}

block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys)
{
    block_t result = plain_text;
    result = scramble(result, expanded_keys, 0, reverse);
    result = scramble(result, expanded_keys, 1, shuffle1);
    result = scramble(result, expanded_keys, 2, shuffle4);
    result = scramble(result, expanded_keys, 3, reverse);
    result = mash(result, expanded_keys);
    result = scramble(result, expanded_keys, 4, reverse);
    result = scramble(result, expanded_keys, 5, shuffle1);
    result = scramble(result, expanded_keys, 6, shuffle4);
    result = scramble(result, expanded_keys, 7, reverse);
    result = mash(result, expanded_keys);
    result = scramble(result, expanded_keys, 8, reverse);
    result = scramble(result, expanded_keys, 9, shuffle1);
    result = scramble(result, expanded_keys, 10, shuffle4);
    result = scramble(result, expanded_keys, 11, reverse);
    result = mash(result, expanded_keys);
    result = scramble(result, expanded_keys, 12, reverse);
    result = scramble(result, expanded_keys, 13, shuffle1);
    result = scramble(result, expanded_keys, 14, shuffle4);
    result = scramble(result, expanded_keys, 15, reverse);
    
    return result;
}

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
    static const uint8_t r_rot_table[] = {2, 3, 5, 7};
    block_t keyA = keys[round];
    block_t keyB = keys[31 - round];
    for (int i = 3; i >= 0; i--) {
        uint8_t b_i = nth_byte(x, i);
        uint8_t rotate = rotr(b_i, r_rot_table[i % 4]);
        block_t X = x;
        X &= ~(0xFF << (8 * i));
        X |= ((block_t)rotate << (8 * i));
        uint8_t b_im1 = nth_byte(X, i-1);
        uint8_t b_im2 = nth_byte(X, i-2);
        uint8_t b_im3 = nth_byte(X, i-3);
        uint8_t key_a_i = nth_byte(keyA, i);
        uint8_t key_b_i = nth_byte(keyB, i);
        uint8_t unscramble = rotate ^ (b_im1 & b_im2) ^ ((~b_im1) & b_im3) ^ key_a_i ^ key_b_i;
        x = set_byte(x, i, unscramble);

    }
    
     return op(x);
}

block_t r_mash(block_t x, block_t *keys)
{
    for (int i = 3; i >= 0; i--) {
        uint8_t b_i = nth_byte(x, i);
        uint8_t i_1 = nth_byte(x, i-1);
        block_t key = keys[i_1 % 32];
        uint8_t key_i = nth_byte(key, i);
        uint8_t unmash = b_i ^ key_i;
        x = set_byte(x, i, unmash);
    }
    
    return x;
}

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys)
{
    block_t result = cipher_text;
    result = r_scramble(result, expanded_keys, 15, reverse);
    result = r_scramble(result, expanded_keys, 14, unshuffle4);
    result = r_scramble(result, expanded_keys, 13, unshuffle1);
    result = r_scramble(result, expanded_keys, 12, reverse);
    result = r_mash(result, expanded_keys);
    result = r_scramble(result, expanded_keys, 11, reverse);
    result = r_scramble(result, expanded_keys, 10, unshuffle4);
    result = r_scramble(result, expanded_keys, 9, unshuffle1);
    result = r_scramble(result, expanded_keys, 8, reverse);
    result = r_mash(result, expanded_keys);
    result = r_scramble(result, expanded_keys, 7, reverse);
    result = r_scramble(result, expanded_keys, 6, unshuffle4);
    result = r_scramble(result, expanded_keys, 5, unshuffle1);
    result = r_scramble(result, expanded_keys, 4, reverse);
    result = r_mash(result, expanded_keys);
    result = r_scramble(result, expanded_keys, 3, reverse);
    result = r_scramble(result, expanded_keys, 2, unshuffle4);
    result = r_scramble(result, expanded_keys, 1, unshuffle1);
    result = r_scramble(result, expanded_keys, 0, reverse);
    
    return result;
}

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys)
{
    size_t num_blocks = (pt_len + 3) / 4; 
    for (size_t i = 0; i < num_blocks; i++) {
        block_t b = 0;
        size_t remaining = (i == num_blocks - 1) ? pt_len - i * 4 : 4;
        
        for (size_t j = 0; j < 4; j++) {
            if (j < remaining) {
                b |= ((block_t)plaintext_input[i * 4 + j] << (j * 8));
            }
        }
        
        encrypted_output[i] = sbu_encrypt_block(b, expanded_keys);
    }
}

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys)
{
    size_t num_blocks = (pt_len + 3) / 4; 
    
    for (size_t i = 0; i < num_blocks; i++) {
        block_t decrypt = sbu_decrypt_block(encrypted_input[i], expanded_keys);
        
        for (size_t j = 0; j < 4; j++) {
             if (i * 4 + j < pt_len) {
                plaintext_output[i * 4 + j] = (decrypt >> (j * 8)) & 0xFF;
            }
        }
    }
}
