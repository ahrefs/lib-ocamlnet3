/* This file is included into nettls_nettle_bindings_stubs.c */

#include "./config.h"

#include <nettle/nettle-types.h>
#include <nettle/nettle-meta.h>
#include <nettle/des.h>
#include <nettle/blowfish.h>

#ifdef HAVE_NETTLE_GCM_H
#include <nettle/gcm.h>
#endif

typedef struct nettle_cipher *net_nettle_cipher_t;
typedef void *net_nettle_cipher_ctx_t;
typedef void *net_nettle_gcm_aes_ctx_t;

#define raise_null_pointer net_gnutls_null_pointer

static void net_gnutls_null_pointer(void) {
    caml_raise_constant(*caml_named_value
                          ("Nettls_nettle_bindings.Null_pointer"));
}

/* Generic API */

static net_nettle_cipher_ctx_t
         net_nettle_create_cipher_ctx(net_nettle_cipher_t cipher) {
    void *p;
    p = stat_alloc(cipher->context_size);
    return p;
}

static void net_nettle_free(void *ctx) {
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

#ifndef HAVE_FUN_nettle_ciphers
const struct nettle_cipher * const nettle_ciphers[] = {
  &nettle_aes128,
  &nettle_aes192,
  &nettle_aes256,
  &nettle_camellia128,
  &nettle_camellia192,
  &nettle_camellia256,
  &nettle_cast128,
  &nettle_serpent128,
  &nettle_serpent192,
  &nettle_serpent256,
  &nettle_twofish128,
  &nettle_twofish192,
  &nettle_twofish256,
  &nettle_arctwo40,
  &nettle_arctwo64,
  &nettle_arctwo128,
  &nettle_arctwo_gutmann128,
  NULL
};
#endif


static void net_nettle_ciphers(net_nettle_cipher_t **ciphers,
                               size_t *n) {
    size_t k;
    k = 0;
    while (nettle_ciphers[k] != NULL) k++;
    *ciphers = (net_nettle_cipher_t *) nettle_ciphers;
    *n = k;
}


/* Extensions to the generic API */

static void net_des_set_key(void *ctx, unsigned int length,
                            const uint8_t *key) {
    struct des_ctx *dctx;
    dctx = (struct des_ctx *) ctx;
    des_set_key(dctx, key);
}

static void net_des_encrypt(void *ctx, unsigned int length,
                            uint8_t *dst, const uint8_t *src) {
    des_encrypt((struct des_ctx *) ctx, length, dst, src);
}

static void net_des_decrypt(void *ctx, unsigned int length,
                            uint8_t *dst, const uint8_t *src) {
    des_decrypt((struct des_ctx *) ctx, length, dst, src);
}

static const struct nettle_cipher net_nettle_des =
  { .name = "des",
    .context_size = sizeof(struct des_ctx),
    .block_size = 64,
    .key_size = 56,
    .set_encrypt_key = net_des_set_key,
    .set_decrypt_key = net_des_set_key,
    .encrypt = net_des_encrypt,
    .decrypt = net_des_decrypt
  };

static void net_des3_set_key(void *ctx, unsigned int length,
                             const uint8_t *key) {
    struct des3_ctx *dctx;
    dctx = (struct des3_ctx *) ctx;
    des3_set_key(dctx, key);
}

static void net_des3_encrypt(void *ctx, unsigned int length,
                            uint8_t *dst, const uint8_t *src) {
    des3_encrypt((struct des3_ctx *) ctx, length, dst, src);
}

static void net_des3_decrypt(void *ctx, unsigned int length,
                            uint8_t *dst, const uint8_t *src) {
    des3_decrypt((struct des3_ctx *) ctx, length, dst, src);
}

static const struct nettle_cipher net_nettle_des3 =
  { .name = "des3",
    .context_size = sizeof(struct des3_ctx),
    .block_size = 64,
    .key_size = 112,
    .set_encrypt_key = net_des3_set_key,
    .set_decrypt_key = net_des3_set_key,
    .encrypt = net_des3_encrypt,
    .decrypt = net_des3_decrypt
  };

static void net_blowfish_set_key(void *ctx, unsigned int length,
                                 const uint8_t *key) {
    struct blowfish_ctx *dctx;
    dctx = (struct blowfish_ctx *) ctx;
    blowfish_set_key(dctx, length, key);
}

static void net_blowfish_encrypt(void *ctx, unsigned int length,
                                 uint8_t *dst, const uint8_t *src) {
    blowfish_encrypt((struct blowfish_ctx *) ctx, length, dst, src);
}

static void net_blowfish_decrypt(void *ctx, unsigned int length,
                                uint8_t *dst, const uint8_t *src) {
    blowfish_decrypt((struct blowfish_ctx *) ctx, length, dst, src);
}

static const struct nettle_cipher net_nettle_blowfish =
  { .name = "blowfish",
    .context_size = sizeof(struct blowfish_ctx),
    .block_size = 64,
    .key_size = 16,  /* variable */
    .set_encrypt_key = net_blowfish_set_key,
    .set_decrypt_key = net_blowfish_set_key,
    .encrypt = net_blowfish_encrypt,
    .decrypt = net_blowfish_decrypt
  };

static const struct nettle_cipher * const ext_ciphers[] = {
    &net_nettle_des,
    &net_nettle_des3,
    &net_nettle_blowfish,
    NULL
};

static void net_ext_ciphers(net_nettle_cipher_t **ciphers,
                            size_t *n) {
    size_t k;
    k = 0;
    while (ext_ciphers[k] != NULL) k++;
    *ciphers = (net_nettle_cipher_t *) ext_ciphers;
    *n = k;
}


/* GCM */

static net_nettle_gcm_aes_ctx_t net_nettle_gcm_aes_init(void) {
#ifdef HAVE_NETTLE_GCM_H
    return stat_alloc(sizeof(struct gcm_aes_ctx));
#else
    return NULL
#endif
}


static int net_have_gcm_aes(void) {
#ifdef HAVE_NETTLE_GCM_H
    return 1;
#else
    return 0;
#endif
}
