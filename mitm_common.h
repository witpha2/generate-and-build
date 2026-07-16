/*
   mitm_common.h  —  v10 (FIXED calc_step128 with prepend)
*/

#pragma once
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <secp256k1.h>

/* ============================================================
   scalar256_t
   ============================================================ */
typedef struct { uint8_t b[32]; } scalar256_t;

static const uint8_t SECP256K1_N_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

static inline scalar256_t s256_zero(void) {
    scalar256_t r; memset(r.b, 0, 32); return r;
}

static inline scalar256_t s256_from_hex(const char *hex) {
    scalar256_t r; memset(r.b, 0, 32);
    if (!hex || !*hex) return r;
    if (hex[0]=='0' && (hex[1]=='x'||hex[1]=='X')) hex += 2;
    size_t len = strlen(hex);
    if (len > 64) len = 64;
    int bi = 31, pos = (int)len - 1;
    while (pos >= 0 && bi >= 0) {
        uint8_t n0 = 0, n1 = 0;
        char c = hex[pos];
        if (c >= '0' && c <= '9') n0 = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f') n0 = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') n0 = (uint8_t)(c - 'A' + 10);
        if (pos > 0) {
            c = hex[pos-1];
            if (c >= '0' && c <= '9') n1 = (uint8_t)(c - '0');
            else if (c >= 'a' && c <= 'f') n1 = (uint8_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') n1 = (uint8_t)(c - 'A' + 10);
        }
        r.b[bi--] = (n1 << 4) | n0;
        pos -= 2;
    }
    return r;
}

static inline void s256_to_hex(const scalar256_t *s, char out[65]) {
    for (int i = 0; i < 32; i++) sprintf(out + i*2, "%02x", s->b[i]);
    out[64] = '\0';
}

static inline int s256_cmp(const scalar256_t *a, const scalar256_t *b) {
    return memcmp(a->b, b->b, 32);
}

static inline scalar256_t s256_add_raw(const scalar256_t *a, const scalar256_t *b) {
    scalar256_t r; int carry = 0;
    for (int i = 31; i >= 0; i--) {
        int s = (int)a->b[i] + (int)b->b[i] + carry;
        r.b[i] = (uint8_t)(s & 0xFF); carry = s >> 8;
    }
    return r;
}

static inline scalar256_t s256_sub(const scalar256_t *a, const scalar256_t *b) {
    scalar256_t r; int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)a->b[i] - (int)b->b[i] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
        r.b[i] = (uint8_t)d;
    }
    return r;
}

static inline scalar256_t s256_add_modn(const scalar256_t *a, const scalar256_t *b) {
    scalar256_t r = s256_add_raw(a, b);
    scalar256_t n; memcpy(n.b, SECP256K1_N_BYTES, 32);
    if (s256_cmp(&r, &n) >= 0) r = s256_sub(&r, &n);
    return r;
}

static inline scalar256_t s256_negate_modn(const scalar256_t *a) {
    scalar256_t n; memcpy(n.b, SECP256K1_N_BYTES, 32);
    return s256_sub(&n, a);
}

static inline scalar256_t s256_from_u64(uint64_t v) {
    scalar256_t r; memset(r.b, 0, 32);
    r.b[24] = (v >> 56) & 0xFF;
    r.b[25] = (v >> 48) & 0xFF;
    r.b[26] = (v >> 40) & 0xFF;
    r.b[27] = (v >> 32) & 0xFF;
    r.b[28] = (v >> 24) & 0xFF;
    r.b[29] = (v >> 16) & 0xFF;
    r.b[30] = (v >> 8) & 0xFF;
    r.b[31] = v & 0xFF;
    return r;
}

static inline scalar256_t s256_from_u128(__uint128_t v) {
    scalar256_t r; memset(r.b, 0, 32);
    r.b[16] = (v >> 120) & 0xFF;
    r.b[17] = (v >> 112) & 0xFF;
    r.b[18] = (v >> 104) & 0xFF;
    r.b[19] = (v >> 96) & 0xFF;
    r.b[20] = (v >> 88) & 0xFF;
    r.b[21] = (v >> 80) & 0xFF;
    r.b[22] = (v >> 72) & 0xFF;
    r.b[23] = (v >> 64) & 0xFF;
    r.b[24] = (v >> 56) & 0xFF;
    r.b[25] = (v >> 48) & 0xFF;
    r.b[26] = (v >> 40) & 0xFF;
    r.b[27] = (v >> 32) & 0xFF;
    r.b[28] = (v >> 24) & 0xFF;
    r.b[29] = (v >> 16) & 0xFF;
    r.b[30] = (v >> 8) & 0xFF;
    r.b[31] = v & 0xFF;
    return r;
}

static inline scalar256_t s256_add_u128_modn(const scalar256_t *a, __uint128_t v) {
    scalar256_t b = s256_from_u128(v);
    return s256_add_modn(a, &b);
}

/* ============================================================
   calc_step128 — ใช้ step_bits bits สุดท้ายของ x-coordinate
   รองรับ step_bits 1..128

   หลักการ (เหมือน calc_step_scalar ในไฟล์ generate_babystep):
     - เอา `bytes` bytes สุดท้าย (full bytes) จาก x
     - เอา `rem` bits ของ byte ถัดขึ้นมา (partial byte)
     - partial อยู่ "เหนือ" full bytes ใน big-endian
       → ต้อง prepend: val |= partial << (bytes*8)
     - บวก 1 เพื่อให้ step ≥ 1 เสมอ
   ============================================================ */
static inline __uint128_t calc_step128(const uint8_t pub33[33], int step_bits) {
    const uint8_t *x = pub33 + 1;   /* x[0..31] big-endian */

    if (step_bits <= 0)   return 1;
    if (step_bits > 128)  step_bits = 128;

    int bytes = step_bits / 8;   /* จำนวน full bytes */
    int rem   = step_bits % 8;   /* เศษ bits          */

    __uint128_t val = 0;

    /* รวม full bytes จาก LSB ของ x (big-endian: index สูง = LSB) */
    for (int i = 0; i < bytes; i++) {
        val = (val << 8) | x[32 - bytes + i];
    }

    /* partial byte: อยู่ "เหนือ" full bytes → prepend ขึ้นข้างหน้า
       ❌ เดิม: val = (val << rem) | partial   ← append (ผิด)
       ✅ ใหม่: val |= partial << (bytes*8)    ← prepend (ถูก)       */
    if (rem > 0) {
        uint8_t mask    = (uint8_t)((1u << rem) - 1u);
        uint8_t partial = x[32 - bytes - 1] & mask;
        val |= (__uint128_t)partial << (bytes * 8);
    }

    return val + 1;
}

static inline uint64_t x_trunc(const uint8_t pub33[33]) {
    return ((uint64_t)pub33[1] << 56) | ((uint64_t)pub33[2] << 48) |
           ((uint64_t)pub33[3] << 40) | ((uint64_t)pub33[4] << 32) |
           ((uint64_t)pub33[5] << 24) | ((uint64_t)pub33[6] << 16) |
           ((uint64_t)pub33[7] << 8)  | (uint64_t)pub33[8];
}

/* ============================================================
   secp256k1 helpers
   ============================================================ */
static inline int pub_parse_hex(secp256k1_context *ctx, const char *hex, secp256k1_pubkey *pk) {
    uint8_t buf[33];
    if (!hex || strlen(hex) != 66) return 0;
    for (int i = 0; i < 33; i++)
        if (sscanf(hex + i*2, "%2hhx", &buf[i]) != 1) return 0;
    return secp256k1_ec_pubkey_parse(ctx, pk, buf, 33);
}

static inline void pub_ser33(secp256k1_context *ctx, const secp256k1_pubkey *pk, uint8_t out[33]) {
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &len, pk, SECP256K1_EC_COMPRESSED);
}

static inline void pub_ser_hex(secp256k1_context *ctx, const secp256k1_pubkey *pk, char out[67]) {
    uint8_t buf[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, buf, &len, pk, SECP256K1_EC_COMPRESSED);
    for (int i = 0; i < 33; i++) {
        sprintf(out + i*2, "%02x", buf[i]);
    }
    out[66] = '\0';
}

static inline int pub_tweak_add_step(secp256k1_context *ctx, secp256k1_pubkey *pk, __uint128_t step) {
    scalar256_t sc = s256_from_u128(step);
    return secp256k1_ec_pubkey_tweak_add(ctx, pk, sc.b);
}

static inline int pub_tweak_sub_step(secp256k1_context *ctx, secp256k1_pubkey *pk, __uint128_t step) {
    scalar256_t sc = s256_from_u128(step);
    scalar256_t neg = s256_negate_modn(&sc);
    return secp256k1_ec_pubkey_tweak_add(ctx, pk, neg.b);
}

/* ============================================================
   Bloom filter
   ============================================================ */
typedef struct {
    uint8_t *bits;
    uint64_t nbits;
} Bloom;

static inline uint64_t bloom_hash(const uint8_t pub33[33], int seed) {
    uint64_t h = (uint64_t)seed * 2654435761ULL;
    for (int i = 0; i < 33; i++) {
        h ^= pub33[i];
        h = h * 6364136223846793005ULL + 1442695040888963407ULL;
    }
    return h;
}

static inline void bloom_init(Bloom *bl, uint64_t nbytes) {
    bl->nbits = nbytes * 8;
    bl->bits = (uint8_t*)calloc(nbytes, 1);
}

static inline void bloom_set(Bloom *bl, const uint8_t pub33[33]) {
    for (int k = 0; k < 7; k++) {
        uint64_t h = bloom_hash(pub33, k) & (bl->nbits - 1);
        bl->bits[h >> 3] |= (1u << (h & 7));
    }
}

static inline int bloom_test(const Bloom *bl, const uint8_t pub33[33]) {
    for (int k = 0; k < 7; k++) {
        uint64_t h = bloom_hash(pub33, k) & (bl->nbits - 1);
        if (!(bl->bits[h >> 3] & (1u << (h & 7)))) return 0;
    }
    return 1;
}

/* ============================================================
   baby.bin file format
   ============================================================ */
#define BABY_MAGIC UINT64_C(0x4D49544D42360100)

#pragma pack(push, 1)

typedef struct __attribute__((packed)) {
    uint64_t magic;
    uint32_t n_walkers;
    uint32_t baby_bits;
    uint32_t step_bits;
    uint32_t _pad;
    uint64_t n_entries;
} BabyHeader;

typedef struct __attribute__((packed)) {
    char     pubkey_hex[67];
    uint8_t  g_sub[32];
} BabyWalker;

typedef struct __attribute__((packed)) {
    uint64_t xkey;
    uint8_t  parity;
    uint8_t  acc[32];
    uint32_t walker;
} BabyEntry;

#pragma pack(pop)

/* ============================================================
   StartKey
   ============================================================ */
typedef struct { char pubkey[67]; scalar256_t g_sub; } StartKey;

static inline int load_start_keys(const char *fn, StartKey **out, int *n_out) {
    FILE *fp = fopen(fn, "r");
    if (!fp) { perror(fn); return 0; }
    int cap = 256, n = 0;
    StartKey *arr = (StartKey*)malloc((size_t)cap * sizeof(StartKey));
    if (!arr) { fclose(fp); return 0; }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *cm = strchr(line, '#');
        if (cm) *cm = 0;
        line[strcspn(line, "\r\n")] = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) continue;
        char *comma = strchr(p, ',');
        if (!comma) continue;
        *comma = '\0';
        char *pub = p;
        char *gsub = comma + 1;
        int l = (int)strlen(pub);
        while (l > 0 && (pub[l-1] == ' ' || pub[l-1] == '\t')) pub[--l] = 0;
        while (*gsub == ' ' || *gsub == '\t') gsub++;
        if (strlen(pub) != 66) continue;
        if (n >= cap) {
            cap *= 2;
            StartKey *tmp = (StartKey*)realloc(arr, (size_t)cap * sizeof(StartKey));
            if (!tmp) { free(arr); fclose(fp); return 0; }
            arr = tmp;
        }
        memcpy(arr[n].pubkey, pub, 67);
        arr[n].g_sub = s256_from_hex(gsub);
        n++;
    }
    fclose(fp);
    *out = arr;
    *n_out = n;
    return n > 0;
}