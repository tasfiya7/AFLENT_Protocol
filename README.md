AFLENT Protocol Packet Processor

This C project simulates the processing of a fictional network protocol known as AFLENT, designed for transmitting 32-bit integer arrays over unreliable or unordered packet channels. The implementation includes:

Packet Parsing

Packet Construction

Reassembly of Arrays

Encryption & Decryption

Features:

1. Packet Parsing:

Extract and print all header fields and payload from AFLENT packets:
Array number
Fragment number
Payload length
Encryption and Endianness flags
Payload (as 32-bit signed integers)

2. Packet Construction:

Split a given array into one or more AFLENT-compliant packets based on:
Maximum payload size
Chosen endianness (big-endian or little-endian)
Fragmenting across packets if needed

3. Array Reassembly:

Given multiple packets (potentially out of order), reconstruct full arrays:
Account for all fragments and their indices
Handle different endianness
Return assembled integer arrays and their lengths

4. Encryption and Decryption:

Implements custom bitwise-based encryption including:
Key expansion to 1024 bits
Scrambling, mashing, shuffling, and bit-rotation
Full decryption logic to reverse transformations


Build & Run:
1. Configure project (run once):
cmake -S . -B build
2. Build:
cmake --build build
3. Run executable:
./build/hw2_main
4. Run tests:
./build/part1
./build/part2
./build/part3
./build/part_4_tests
