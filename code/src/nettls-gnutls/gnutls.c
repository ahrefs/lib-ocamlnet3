/* This file is included into nettls_gnutls_bindings_stubs.c */

#include <gnutls/gnutls.h>
#include <gnutls/openpgp.h>
#include <gnutls/x509.h>

typedef int error_code;
typedef unsigned int gnutls_init_flags;
typedef unsigned int key_usage;
typedef const char * const_charp;
typedef gnutls_datum_t str_datum;
typedef gnutls_datum_t * str_datum_p;
typedef const gnutls_datum_t * const_str_datum_p;
   
#define wrap_const_str_datum_p wrap_str_datum_p
#define unwrap_const_str_datum_p unwrap_str_datum_p

static value wrap_error_code(error_code x);

static gnutls_session_t 
           unwrap_gnutls_session_t(value v);
static void
           attach_gnutls_session_t(value v, value aux);
static gnutls_certificate_credentials_t 
           unwrap_gnutls_certificate_credentials_t(value v);
static gnutls_srp_client_credentials_t 
           unwrap_gnutls_srp_client_credentials_t(value v);
static gnutls_srp_server_credentials_t 
           unwrap_gnutls_srp_server_credentials_t(value v);
static gnutls_psk_client_credentials_t 
           unwrap_gnutls_psk_client_credentials_t(value v);
static gnutls_psk_server_credentials_t 
           unwrap_gnutls_psk_server_credentials_t(value v);
static gnutls_anon_client_credentials_t 
           unwrap_gnutls_anon_client_credentials_t(value v);
static gnutls_anon_server_credentials_t 
           unwrap_gnutls_anon_server_credentials_t(value v);

#define raise_null_pointer net_gnutls_null_pointer

static void net_gnutls_null_pointer(void) {
    caml_raise_constant(*caml_named_value
                          ("Nettls_gnutls_bindings.Null_pointer"));
}


static const char * unwrap_charp(value dummy) { return NULL; }
   
static value wrap_str_datum(const gnutls_datum_t d) {
    value s;
    s = caml_alloc_string(d.size);
    memcpy(String_val(s), d.data, d.size);
    return s;
}

static value wrap_str_datum_p(const gnutls_datum_t *d) {
    if (d==NULL) net_gnutls_null_pointer();
    return wrap_str_datum(*d);
}
   
static gnutls_datum_t unwrap_str_datum(value v) {
    gnutls_datum_t d;
    d.size = caml_string_length(v);
    d.data = stat_alloc(d.size);
    memcpy(d.data, String_val(v), d.size);
    return d;
}
   
static gnutls_datum_t * unwrap_str_datum_p(value v) {
    gnutls_datum_t *d;
    d = stat_alloc(sizeof(gnutls_datum_t));
    *d = unwrap_str_datum(v);
    return d;
}
   
static void free_str_datum(gnutls_datum_t d) {
    if (d.data != NULL) { stat_free(d.data); d.data = NULL; };
}

static void free_str_datum_p(gnutls_datum_t *d) {
    if (d != NULL) {
        if (d->data != NULL) stat_free(d->data);
        stat_free(d);
    }
}
   
static void net_gnutls_error_check(int error_code) {
    if (error_code < 0) {
        caml_raise_with_arg(*caml_named_value("Nettls_gnutls_bindings.Error"),
                            wrap_error_code(error_code));
    }
}

static void net_gnutls_transport_set_int(gnutls_session_t s,long fd) {
    gnutls_transport_set_ptr(s, (gnutls_transport_ptr_t) fd);
}


value net_gnutls_credentials_set(value sess, value creds) {
    gnutls_session_t s;
    int error_code;
    CAMLparam2(sess,creds);
    s = unwrap_gnutls_session_t(sess);
    switch (Long_val(Field(creds,0))) {
    case H_Certificate:
        error_code = 
            gnutls_credentials_set(s,
                                   GNUTLS_CRD_CERTIFICATE,
                                   unwrap_gnutls_certificate_credentials_t 
                                     (Field(creds,1))
                                   );
        break;
    case H_Srp_client:
        error_code = 
            gnutls_credentials_set(s,
                                   GNUTLS_CRD_SRP,
                                   unwrap_gnutls_srp_client_credentials_t 
                                     (Field(creds,1))
                                   );
        break;
    case H_Srp_server:
        error_code = 
            gnutls_credentials_set(s,
                                   GNUTLS_CRD_SRP,
                                   unwrap_gnutls_srp_server_credentials_t 
                                     (Field(creds,1))
                                   );
        break;
    case H_Anon_client:
        error_code = 
            gnutls_credentials_set(s,
                                   GNUTLS_CRD_ANON,
                                   unwrap_gnutls_anon_client_credentials_t 
                                     (Field(creds,1))
                                   );
        break;
    case H_Anon_server:
        error_code = 
            gnutls_credentials_set(s,
                                   GNUTLS_CRD_ANON,
                                   unwrap_gnutls_anon_server_credentials_t 
                                     (Field(creds,1))
                                   );
        break;
    case H_Psk_client:
        error_code = 
            gnutls_credentials_set(s,
                                   GNUTLS_CRD_PSK,
                                   unwrap_gnutls_psk_client_credentials_t 
                                     (Field(creds,1))
                                   );
        break;
    case H_Psk_server:
        error_code = 
            gnutls_credentials_set(s,
                                   GNUTLS_CRD_CERTIFICATE,
                                   unwrap_gnutls_psk_server_credentials_t 
                                     (Field(creds,1))
                                   );
        break;
    default:
        failwith("net_gnutls_credentials_set");
    };
    net_gnutls_error_check(error_code);
    attach_gnutls_session_t(sess, creds);
    CAMLreturn(Val_unit);
}
