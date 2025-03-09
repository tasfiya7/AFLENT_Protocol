#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include "hw2.h"
#include <string.h>

typedef uint32_t block_t;
typedef uint64_t sbu_key_t;

extern uint8_t rotl(uint8_t x, uint8_t shamt);
extern uint8_t rotr(uint8_t x, uint8_t shamt);
extern block_t reverse(block_t x);
extern block_t shuffle4(block_t x);
extern block_t unshuffle4(block_t x);
extern block_t shuffle1(block_t x);
extern block_t unshuffle1(block_t x);
extern uint8_t nth_byte(block_t x, uint8_t n);

void test_reverse() {
    block_t x = 0x12345678;
    block_t rev = reverse(x);
    block_t rev2 = reverse(rev);
    printf("reverse: x = 0x%08X, reverse(x) = 0x%08X, reverse(reverse(x)) = 0x%08X\n", x, rev, rev2);
    assert(rev2 == x);
}

void test_shuffle4() {
    block_t x = 0x76543210;
    block_t shuf = shuffle4(x);
    block_t unshuf = unshuffle4(shuf);
    printf("shuffle4: x = 0x%08X, shuffle4(x) = 0x%08X, unshuffle4(shuffle4(x)) = 0x%08X\n", x, shuf, unshuf);
    assert(unshuf == x);
}

void test_shuffle1() {
    block_t x = 0x12345678;
    block_t shuf = shuffle1(x);
    block_t unshuf = unshuffle1(shuf);
    printf("shuffle1: x = 0x%08X, shuffle1(x) = 0x%08X, unshuffle1(shuffle1(x)) = 0x%08X\n", x, shuf, unshuf);
    assert(unshuf == x);
}

void test_nth_byte() {
    // For a block in little-endian order, nth_byte(x, 0) should return the least-significant byte.
    block_t x = 0xDDCCBBAA; // Expected bytes: AA, BB, CC, DD
    uint8_t b0 = nth_byte(x, 0);
    uint8_t b1 = nth_byte(x, 1);
    uint8_t b2 = nth_byte(x, 2);
    uint8_t b3 = nth_byte(x, 3);
    printf("nth_byte: x = 0x%08X, bytes = 0x%02X 0x%02X 0x%02X 0x%02X\n", x, b0, b1, b2, b3);
    // Expect: b0 = 0xAA, b1 = 0xBB, b2 = 0xCC, b3 = 0xDD
    assert(b0 == 0xAA);
    assert(b1 == 0xBB);
    assert(b2 == 0xCC);
    assert(b3 == 0xDD);
}

int main(void) {
    printf("Testing low-level operations...\n");
    test_reverse();
    test_shuffle4();
    test_shuffle1();
    test_nth_byte();
    printf("All low-level tests passed.\n");
    return 0;
}