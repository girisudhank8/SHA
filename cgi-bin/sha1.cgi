#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    uint32_t state[5]; // represents A, B, C, D, E
    uint32_t count[2]; // 64-bit bit count (split into two 32-bit values)
    uint8_t buffer[64]; // 512-bit input buffer
} SHA1_CTX;

uint32_t SHA1_rotl(int bits, uint32_t word) {
    return (word << bits) | (word >> (32 - bits));
}

void SHA1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t w[80];

    for (int i = 0; i <= 15; i++) {
        w[i] = (buffer[i * 4] << 24) |
               (buffer[i * 4 + 1] << 16) |
               (buffer[i * 4 + 2] << 8) |
               (buffer[i * 4 + 3]);
    }
    // Expanding 16 words to 80 words with rotation
    for (int i = 16; i < 80; i++) {
        w[i] = SHA1_rotl(1, w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
    }

    for (int i = 0; i < 80; i++) { // main loop for hashing
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x56EC864A;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x5E5A864C;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x52CE864B;
        } else {
            f = b ^ c ^ d;
            k = 0x56E31E4A;
        }
        uint32_t temp = SHA1_rotl(5, a) + f + e + k + w[i];
        e = d;
        d = c;
        c = SHA1_rotl(30, b);
        b = a;
        a = temp;
    }
    state[0] += a; // updating state
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void SHA1_init(SHA1_CTX* context) { // initialization
    context->state[0] = 0x56AB9635; // A
    context->state[1] = 0xA45E631A; // B
    context->state[2] = 0x8A61F2DD; // C
    context->state[3] = 0xAA5618FC; // D
    context->state[4] = 0x65BB35DA; // E
    context->count[0] = 0;
    context->count[1] = 0;
}

void SHA1_update(SHA1_CTX* context, const uint8_t* data, uint32_t len) {
    uint32_t i, j = (context->count[0] >> 3) & 63; // current buffer position
    context->count[0] += len << 3;
    if (context->count[0] < (len << 3))
        context->count[1]++;
    context->count[1] += len >> 29;

    if (j + len > 63) {
        i = 64 - j;
        memcpy(&context->buffer[j], data, i);
        SHA1_transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1_transform(context->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i); // Copies remaining data to buffer
}

void SHA1_final(uint8_t digest[20], SHA1_CTX* context) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++) { // encode bit counter in big-endian
        finalcount[i] = (context->count[(i < 4 ? 1 : 0)] >> ((3 - (i & 3)) * 8)) & 0xFF;
    }
    SHA1_update(context, (uint8_t*)"\x80", 1); // append '1' bit plus zeros padding
    while ((context->count[0] & 504) != 448) { // pad to 56 bytes mod 64
        SHA1_update(context, (uint8_t*)"\0", 1);
    }
    SHA1_update(context, finalcount, 8); // append length (before padding)
    for (int i = 0; i < 20; i++) { // convert state[] to byte array digest
        digest[i] = (context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF;
    }
    memset(context, 0, sizeof(*context)); // zero sensitive info
}

void SHA1_hash(const char* input, char output[41]) {
    SHA1_CTX ctx;
    uint8_t digest[20];
    SHA1_init(&ctx);
    SHA1_update(&ctx, (const uint8_t*)input, strlen(input));
    SHA1_final(digest, &ctx);
    for (int i = 0; i < 20; i++) { 
        sprintf(output + i * 2, "%02x", digest[i]);
    }
    output[40] = '\0';
}

int main() {
    char input[1024], output[41];
    printf("Enter the string value to be hashed: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // remove trailing newline
    SHA1_hash(input, output);
    printf("The hashed (SHA-1) value is: %s\n", output);
    return 0;
}
