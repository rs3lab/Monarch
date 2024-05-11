#include <stddef.h>
#include <stdint.h>
#include <endian.h>

#define DM_DELTA 0x9E3779B9
#define DM_FULLROUNDS 10 /* 32 is overkill, 16 is strong crypto */
#define DM_PARTROUNDS 6  /* 6 gets complete mixing */

/* Davies-Meyer hashing function implementation
 */
static int
dm_round(int rounds, uint32_t *array, uint32_t *h0, uint32_t *h1)
{
    uint32_t sum = 0;
    int n = 0;
    uint32_t b0 = 0;
    uint32_t b1 = 0;

    b0 = *h0;
    b1 = *h1;

    n = rounds;

    do {
        sum += DM_DELTA;
        b0 += ((b1 << 4) + array[0]) ^ (b1 + sum) ^ ((b1 >> 5) + array[1]);
        b1 += ((b0 << 4) + array[2]) ^ (b0 + sum) ^ ((b0 >> 5) + array[3]);
    } while (--n);

    *h0 += b0;
    *h1 += b1;

    return 0;
}

uint32_t
__pad(int len)
{
    uint32_t pad = 0;

    pad = (uint32_t)len | ((uint32_t)len << 8);
    pad |= pad << 16;

    return pad;
}

uint32_t
gf_dm_hashfn(const char *msg, int len)
{
    uint32_t h0 = 0x9464a485;
    uint32_t h1 = 0x542e1a94;
    uint32_t array[4];
    uint32_t pad = 0;
    int i = 0;
    int j = 0;
    int full_quads = 0;
    int full_words = 0;
    int full_bytes = 0;
    uint32_t *intmsg = NULL;
    uint32_t word = 0;

    intmsg = (uint32_t *)msg;
    pad = __pad(len);

    full_bytes = len;
    full_words = len / 4;
    full_quads = len / 16;

    for (i = 0; i < full_quads; i++) {
        for (j = 0; j < 4; j++) {
            word = le32toh(*intmsg);
            array[j] = word;
            intmsg++;
            full_words--;
            full_bytes -= 4;
        }
        dm_round(DM_PARTROUNDS, &array[0], &h0, &h1);
    }

    for (j = 0; j < 4; j++) {
        if (full_words) {
            word = le32toh(*intmsg);
            array[j] = word;
            intmsg++;
            full_words--;
            full_bytes -= 4;
        } else {
            array[j] = pad;
            while (full_bytes) {
                array[j] <<= 8;
                array[j] |= msg[len - full_bytes];
                full_bytes--;
            }
        }
    }
    dm_round(DM_FULLROUNDS, &array[0], &h0, &h1);

    return h0 ^ h1;
}


/****************************************
 *              CephFS                  *
 ***************************************/

/*
 * Robert Jenkin's hash function.
 * https://burtleburtle.net/bob/hash/evahash.html
 * This is in the public domain.
 */
#define mix(a, b, c)                        \
    do {                            \
        a = a - b;  a = a - c;  a = a ^ (c >> 13);  \
        b = b - c;  b = b - a;  b = b ^ (a << 8);   \
        c = c - a;  c = c - b;  c = c ^ (b >> 13);  \
        a = a - b;  a = a - c;  a = a ^ (c >> 12);  \
        b = b - c;  b = b - a;  b = b ^ (a << 16);  \
        c = c - a;  c = c - b;  c = c ^ (b >> 5);   \
        a = a - b;  a = a - c;  a = a ^ (c >> 3);   \
        b = b - c;  b = b - a;  b = b ^ (a << 10);  \
        c = c - a;  c = c - b;  c = c ^ (b >> 15);  \
    } while (0)

#if __has_attribute(__fallthrough__)
# define fallthrough                    __attribute__((__fallthrough__))
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif

typedef unsigned int __u32;

unsigned int ceph_str_hash_rjenkins(const char *str, unsigned int length)
{
    const unsigned char *k = (const unsigned char *)str;
    __u32 a, b, c;  /* the internal state */
    __u32 len;      /* how many key bytes still need mixing */

    /* Set up the internal state */
    len = length;
    a = 0x9e3779b9;      /* the golden ratio; an arbitrary value */
    b = a;
    c = 0;               /* variable initialization of internal state */

    /* handle most of the key */
    while (len >= 12) {
        a = a + (k[0] + ((__u32)k[1] << 8) + ((__u32)k[2] << 16) +
             ((__u32)k[3] << 24));
        b = b + (k[4] + ((__u32)k[5] << 8) + ((__u32)k[6] << 16) +
             ((__u32)k[7] << 24));
        c = c + (k[8] + ((__u32)k[9] << 8) + ((__u32)k[10] << 16) +
             ((__u32)k[11] << 24));
        mix(a, b, c);
        k = k + 12;
        len = len - 12;
    }

    /* handle the last 11 bytes */
    c = c + length;
    switch (len) {
    case 11:
        c = c + ((__u32)k[10] << 24);
        fallthrough;
    case 10:
        c = c + ((__u32)k[9] << 16);
        fallthrough;
    case 9:
        c = c + ((__u32)k[8] << 8);
        /* the first byte of c is reserved for the length */
        fallthrough;
    case 8:
        b = b + ((__u32)k[7] << 24);
        fallthrough;
    case 7:
        b = b + ((__u32)k[6] << 16);
        fallthrough;
    case 6:
        b = b + ((__u32)k[5] << 8);
        fallthrough;
    case 5:
        b = b + k[4];
        fallthrough;
    case 4:
        a = a + ((__u32)k[3] << 24);
        fallthrough;
    case 3:
        a = a + ((__u32)k[2] << 16);
        fallthrough;
    case 2:
        a = a + ((__u32)k[1] << 8);
        fallthrough;
    case 1:
        a = a + k[0];
        /* case 0: nothing left to add */
    }
    mix(a, b, c);

    return c;
}
