#ifndef MNEMONIC_H
#define MNEMONIC_H

#include <stddef.h>
#include <stdint.h>

#include "vertices_types.h"

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
ret_code_t mnemonic_from_seed(bytes seed, char** mnemonic);
ret_code_t seed_from_mnemonic(const char* mnemonic, bytes *seed);

#endif // MNEMONIC_H