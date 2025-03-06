#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/mman.h>
#include <math.h>
#include <sys/stat.h>
#include <errno.h>

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
		
			if (endianness == 1) { // Convert to little-endian if needed
                payload[i * 4] = value & 0xFF;
                payload[i * 4 + 1] = (value >> 8) & 0xFF;
                payload[i * 4 + 2] = (value >> 16) & 0xFF;
                payload[i * 4 + 3] = (value >> 24) & 0xFF;
            } else { // Big-endian (default)
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

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths){	

	int **arrays = (int**)calloc(array_count, sizeof(int*));
    if (!arrays) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

	int **fragment_sizes = (int**)calloc(array_count, sizeof(int*));
    int ***fragment_data = (int***)calloc(array_count, sizeof(int**));

    if (!fragment_sizes || !fragment_data) {
        fprintf(stderr, "Memory allocation failed.\n");
        free(arrays);
        return NULL;
    }

    int max_fragments = 32;

	for (int i = 0; i < array_count; i++) {
        fragment_sizes[i] = (int*)calloc(max_fragments, sizeof(int));
        fragment_data[i] = (int**)calloc(max_fragments, sizeof(int*));

        if (!fragment_sizes[i] || !fragment_data[i]) {
            fprintf(stderr, "Memory allocation failed.\n");
            return NULL;
        }
    }

    int index = 0;
	while (packets[index]){
		int array_number = (packets[index] & 0xFC) >> 2;
        int fragment_number = ((packets[index] & 0x03) << 3) | ((packets[index + 1] & 0xE0) >> 5);
        int length = ((packets[index + 1] & 0x1F) << 5) | ((packets[index + 2] & 0xF8) >> 3);
        //int encrypted = (packets[index + 2] & 0x04) >> 2;
        int endianness = (packets[index + 2] & 0x02) >> 1;
        //int last = (packets[index + 2] & 0x01);

		fragment_sizes[array_number][fragment_number] = length;
        fragment_data[array_number][fragment_number] = (int*)malloc(length * sizeof(int));
        
		if (!fragment_data[array_number][fragment_number]) {
            fprintf(stderr, "Memory allocation failed.\n");
            return NULL;
        }
		//payload
		unsigned char *payload = &packets[index + 3];
        for (int i = 0; i < length; i++) {
            int value;
            if (endianness == 1) { //litle
                value = (payload[i * 4]) | (payload[i * 4 + 1] << 8) | (payload[i * 4 + 2] << 16) | (payload[i * 4 + 3] << 24);
            } else { // big
                value = (payload[i * 4] << 24) | (payload[i * 4 + 1] << 16) | (payload[i * 4 + 2] << 8) | (payload[i * 4 + 3]);
            }
            fragment_data[array_number][fragment_number][i] = value;
        }
		index += (3 + length * 4);

	}

	for (int i = 0; i < array_count; i++) {
        int total_length = 0;

		for (int j = 0; j < max_fragments; j++) {
            total_length += fragment_sizes[i][j];
        }
		arrays[i] = (int*)malloc(total_length * sizeof(int));
        if (!arrays[i]) {
            fprintf(stderr, "Memory allocation failed.\n");
            return NULL;
        }

        array_lengths[i] = total_length;
        int position = 0;

		for (int j = 0; j < max_fragments; j++) {
            if (fragment_data[i][j] != NULL) {
                memcpy(&arrays[i][position], fragment_data[i][j], fragment_sizes[i][j] * sizeof(int));
                position += fragment_sizes[i][j];
                free(fragment_data[i][j]); 
            }
        }
    }

	for (int i = 0; i < array_count; i++) {
        free(fragment_sizes[i]);
        free(fragment_data[i]);
    }
    free(fragment_sizes);
    free(fragment_data);
    
	return arrays;
	
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
	(void) x;
	(void) shamt;
    return 0;
}

uint8_t rotr(uint8_t x, uint8_t shamt)
{
	(void) x;
	(void) shamt;
    return 0;
}

block_t reverse(block_t x)
{
	(void) x;
    return 0;
}

block_t shuffle4(block_t x)
{
	(void) x;
    return 0;
}

block_t unshuffle4(block_t x)
{
	(void) x;
    return 0;
}

block_t shuffle1(block_t x)
{
	(void) x;
    return 0;
}

block_t unshuffle1(block_t x)
{
	(void) x;
    return 0;
}

uint8_t nth_byte(block_t x, uint8_t n)
{
	(void) x;
	(void) n;
    return 0;
}

// ----------------- Encryption Functions ----------------- //

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys)
{
	(void) key;
	(void) expanded_keys;
}

block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	(void) x;
	(void) keys;
	(void) round;
	(void) op;
    return 0;
}

block_t mash(block_t x, block_t *keys)
{
	(void) x;
	(void) keys;
    return 0;
}

block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys)
{
	(void) plain_text;
	(void) expanded_keys;

    return 0;
}

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	(void) x;
	(void) keys;
	(void) round;
	(void) op;

    return 0;
}

block_t r_mash(block_t x, block_t *keys)
{
	(void) x;
	(void) keys;
	return 0;
}

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys)
{
	(void) cipher_text;
	(void) expanded_keys;
	return 0;
}

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys)
{
	(void) plaintext_input;
	(void) encrypted_output;
	(void) pt_len;
	(void) expanded_keys;
}

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys)
{
	(void) encrypted_input;
	(void) plaintext_output;
	(void) pt_len;
	(void) expanded_keys;
}

// ----------------- Utility Functions ----------------- //