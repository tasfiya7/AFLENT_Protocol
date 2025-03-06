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


static int compute_total_bytes(unsigned char packets[], int array_count) {
    int index = 0;
    int count_last_found = 0;
    // Allocate a boolean array to track which arrays have received their final packet.
    bool *last_found = calloc(array_count, sizeof(bool));
    if (!last_found) {
        fprintf(stderr, "Memory allocation error in compute_total_bytes.\n");
        exit(EXIT_FAILURE);
    }
    while (true) {
        // Decode header.
        unsigned char h0 = packets[index];
        unsigned char h1 = packets[index + 1];
        unsigned char h2 = packets[index + 2];
        int arr_num = (h0 & 0xFC) >> 2;
        int frag_length = ((h1 & 0x1F) << 5) | ((h2 & 0xF8) >> 3);
        int last_flag = h2 & 0x01;
        int packet_size = 3 + frag_length * 4;
        index += packet_size;
        if (last_flag && arr_num < array_count && !last_found[arr_num]) {
            last_found[arr_num] = true;
            count_last_found++;
        }
        if (count_last_found == array_count)
            break;
    }
    free(last_found);
    return index;
}




int** create_arrays(unsigned char packets[], int array_count, int *array_lengths){	

	int i, j;
    
    // First, compute the total number of bytes in the packets array.
    int total_bytes = compute_total_bytes(packets, array_count);
    
    // First pass: determine the total number of 32-bit ints for each array.
    // Initialize array_lengths to zero.
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
    
    // Allocate an array of int pointers for the reassembled arrays.
    int **result = malloc(array_count * sizeof(int *));
    if (!result) {
        fprintf(stderr, "Memory allocation error for result arrays.\n");
        exit(EXIT_FAILURE);
    }
    
    // Temporary storage: for each array, store its fragments (protocol allows up to 32 fragments per array).
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
    
    // Second pass: record each packet's fragment info.
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
    
    // Sort fragments for each array by fragment number.
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
    
    // Allocate memory for each complete array and reassemble the payloads.
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
            // Convert each group of 4 bytes to a 32-bit int.
            for (int k = 0; k < frag_length; k++) {
                int value;
                if (endian == 1) { // little-endian
                    value = payload[k * 4] |
                           (payload[k * 4 + 1] << 8) |
                           (payload[k * 4 + 2] << 16) |
                           (payload[k * 4 + 3] << 24);
                } else { // big-endian
                    value = (payload[k * 4] << 24) |
                           (payload[k * 4 + 1] << 16) |
                           (payload[k * 4 + 2] << 8) |
                           payload[k * 4 + 3];
                }
                result[i][offset++] = value;
            }
        }
    }
    
    // Free temporary fragment info.
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