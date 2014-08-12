/* This file is included into nettls_nettle_bindings_stubs.c */

#include <nettle/nettle-types.h>
#include <nettle/nettle-meta.h>

#include "./config.h"

typedef struct nettle_cipher *net_nettle_cipher_t;
typedef void *net_nettle_cipher_ctx_t;

#define raise_null_pointer net_gnutls_null_pointer

static void net_gnutls_null_pointer(void) {
    caml_raise_constant(*caml_named_value
                          ("Nettls_nettle_bindings.Null_pointer"));
}

static net_nettle_cipher_ctx_t
         net_nettle_create_cipher_ctx(net_nettle_cipher_t cipher) {
    void *p;
    p = stat_alloc(cipher->context_size);
    return p;
}

static void net_nettle_destroy_cipher_ctx(net_nettle_cipher_ctx_t ctx) {
    stat_free(ctx);
}

static void net_nettle_destroy_cipher(net_nettle_cipher_t cipher) {
    /* do nothing, ciphers are non-destructable */
}

static void net_nettle_set_encrypt_key(net_nettle_cipher_t cipher,
                                       net_nettle_cipher_ctx_t ctx,
                                       unsigned int length,
                                       const uint8_t *key) {
    cipher->set_encrypt_key(ctx, length, key);
}


static void net_nettle_set_decrypt_key(net_nettle_cipher_t cipher,
                                       net_nettle_cipher_ctx_t ctx,
                                       unsigned int length,
                                       const uint8_t *key) {
    cipher->set_decrypt_key(ctx, length, key);
}

static void net_nettle_encrypt(net_nettle_cipher_t cipher,
                               net_nettle_cipher_ctx_t ctx,
                               unsigned int length,
                               uint8_t *dst,
                               const uint8_t *src) {
    cipher->encrypt(ctx, length, dst, src);
}

static void net_nettle_decrypt(net_nettle_cipher_t cipher,
                               net_nettle_cipher_ctx_t ctx,
                               unsigned int length,
                               uint8_t *dst,
                               const uint8_t *src) {
    cipher->decrypt(ctx, length, dst, src);
}

static const char *net_nettle_cipher_name(net_nettle_cipher_t cipher) {
    return cipher->name;
}

static void net_nettle_ciphers(net_nettle_cipher_t **ciphers,
                               size_t *n) {
    size_t k;
    k = 0;
    while (nettle_ciphers[k] != NULL) k++;
    *ciphers = (net_nettle_cipher_t *) nettle_ciphers;
    *n = k;
}
