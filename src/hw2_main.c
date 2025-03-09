#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include "hw2.h"
#include <string.h>

extern block_t sbu_encrypt_block_debug(block_t plain_text, block_t *expanded_keys);

int main(void) {
    printf("=== Debugging Encryption/Decryption Module ===\n\n");

    // --- Use the example from the pdf ---
    // Key from pdf: 0xab6176446f0c280a
    sbu_key_t key = 0xab6176446f0c280aULL;
    block_t key_sched[EXPANDED_KEYS_LENGTH] = {0};
    sbu_expand_keys(key, key_sched);

    printf("Expanded key schedule (first 8 values):\n");
    for (int i = 0; i < 8; i++) {
        printf("S[%d] = 0x%08X\n", i, key_sched[i]);
    }
    printf("\n");

    // --- Debug Single Block Encryption (only once) ---
    // Use plaintext block 0x739192B5 from the pdf.
    block_t plaintext_block = 0x739192B5;
    printf("Debug single block encryption (plaintext = 0x%08X):\n", plaintext_block);
    block_t cipher_block = sbu_encrypt_block_debug(plaintext_block, key_sched);
    printf("Final ciphertext block: 0x%08X\n\n", cipher_block);

    // --- Stream Encryption/Decryption Test (without debug prints) ---
    char message[] = "We the People of the United States, in Order to form a more perfect Union...";
    size_t msg_len = strlen(message) + 1; // include null terminator
    size_t num_blocks = (msg_len + 3) / 4;
    block_t *encrypted = malloc(num_blocks * sizeof(block_t));
    uint8_t *decrypted = malloc(msg_len);
    if (!encrypted || !decrypted) {
        fprintf(stderr, "Memory allocation error.\n");
        return 1;
    }

    printf("Encrypting message:\n%s\n\n", message);
    sbu_encrypt((uint8_t *)message, encrypted, msg_len, key_sched);

    printf("Encrypted blocks:\n");
    for (size_t i = 0; i < num_blocks; i++) {
        printf("Block %zu: 0x%08X\n", i, encrypted[i]);
    }
    printf("\n");

    sbu_decrypt(encrypted, decrypted, msg_len, key_sched);
    printf("Decrypted message:\n%s\n", decrypted);

    free(encrypted);
    free(decrypted);
    return 0;
}