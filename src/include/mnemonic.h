#ifndef MNEMONIC_H
#define MNEMONIC_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    unsigned char* data;
    size_t size;
} bytes;

typedef struct {
    char** words;
    int size;
    int capacity;
} WordVector;

typedef struct {
    char** keys;
    int* values;
    int size;
    int capacity;
} WordMap;

void initialize_mnemonic();
char* mnemonic_from_seed(bytes seed);
bytes seed_from_mnemonic(const char* mnemonic);

#endif // MNEMONIC_H