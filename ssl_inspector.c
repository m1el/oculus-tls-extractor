#include <stdio.h>
#include <stdint.h>
#include "ssl_locl.h"

typedef unsigned char u8;

typedef struct {
    u8* client_random;
    size_t client_random_size;
    u8* master_key;
    size_t master_key_size;
} private_keys;

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

typedef int (*ssl_connect_fn) (SSL *s);

extern
ssl_connect_fn ssl_get_ssl_connect(struct ssl_st* ssl) {
    if (ssl != NULL && ssl->method != NULL) {
        return ssl->method->ssl_connect;
    }

    return 0;
}
