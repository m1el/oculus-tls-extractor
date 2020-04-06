/*
 ssl_inspector module is responsible for extracting private keys
 from ssl state.  It is a more robust approach to build a C module
 than maintaining a representation of OpenSSL structs in Rust or
 manually chase pointers in Rust.
 */
#include <stdio.h>
#include <stdint.h>
#include "ssl_locl.h"

typedef unsigned char u8;

/*
 private_keys struct is used to communicate with Rust code.
 The accomanying struct in Rust injectee is PkData.
 It bears information about two slices in memory --
 for client random and master key.
 */
typedef struct {
    u8* client_random;
    size_t client_random_size;
    u8* master_key;
    size_t master_key_size;
} private_keys;

/*
 ssl_read_pk_data: Extract private keys from openssl struct.
 this function populates output with pointers to-- and lengths
 of private key data.
 Arguments:
   ssl: pointer to ssl struct
   output: pointer to output struct
 */
extern
void ssl_read_pk_data(struct ssl_st* ssl, private_keys* output) {
    if (ssl == NULL || output == NULL) {
        return;
    }

    output->client_random = ssl->s3->client_random;
    output->client_random_size = SSL3_RANDOM_SIZE;

    struct ssl_session_st* session = ssl->session;
    if (session != NULL) {
        output->master_key = session->master_key;
        output->master_key_size = session->master_key_length;
    }
}

/* typedef of function pointer for easier use later */
typedef int (*ssl_connect_fn) (SSL *s);

/*
 ssl_connect_fn: extract function pointer from openssl state.
 Arguments:
   ssl: pointer to ssl struct
 Return value:
   pointer to ssl_connect function of ssl_method struct
 */
extern
ssl_connect_fn ssl_get_ssl_connect(struct ssl_st* ssl) {
    if (ssl != NULL && ssl->method != NULL) {
        return ssl->method->ssl_connect;
    }

    return 0;
}
