//
// Created by Bruno on 6/15/2024.
//
#include "base2048.h"
#include <stdint.h>
#include <malloc.h>

void init_uint16_vector(Uint16Vector* vec) {
    vec->data = (uint16_t*)malloc(10 * sizeof(uint16_t));
    vec->size = 0;
    vec->capacity = 10;
}

void push_back_uint16_vector(Uint16Vector* vec, uint16_t value) {
    if (vec->size >= vec->capacity) {
        vec->capacity *= 2;
        vec->data = (uint16_t*)realloc(vec->data, vec->capacity * sizeof(uint16_t));
    }
    vec->data[vec->size++] = value;
}

void init_bytes(Bytes* vec) {
    vec->data = (unsigned char*)malloc(10 * sizeof(unsigned char));
    vec->size = 0;
    vec->capacity = 10;
}

void push_back_bytes(Bytes* vec, unsigned char value) {
    if (vec->size >= vec->capacity) {
        vec->capacity *= 2;
        vec->data = (unsigned char*)realloc(vec->data, vec->capacity * sizeof(unsigned char));
    }
    vec->data[vec->size++] = value;
}

void free_bytes(Bytes* vec) {
    free(vec->data);
    vec->data = NULL;
    vec->size = 0;
    vec->capacity = 0;
}

Uint16Vector b2048_encode(const Bytes* in) {
    Uint16Vector out;
    init_uint16_vector(&out);

    unsigned val = 0;
    int bits = 0;
    for (size_t i = 0; i < in->size; ++i) {
        unsigned char b = in->data[i];
        val |= (b << bits);
        bits += 8;
        if (bits >= 11) {
            push_back_uint16_vector(&out, val & 0x7FF);
            val >>= 11;
            bits -= 11;
        }
    }
    if (bits > 0) {
        push_back_uint16_vector(&out, val & 0x7FF);
    }
    return out;
}

Bytes b2048_decode(const Uint16Vector* in) {
    Bytes out;
    init_bytes(&out);

    int val = 0;
    int bits = 0;
    for (size_t i = 0; i < in->size; ++i) {
        uint16_t v = in->data[i];
        val |= (v << bits);
        bits += 11;
        while (bits >= 8) {
            push_back_bytes(&out, val & 0xFF);
            val >>= 8;
            bits -= 8;
        }
    }
    return out;
}

