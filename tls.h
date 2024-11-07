#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>

struct TLS
{
    SSL_CTX* Ctx;
    SSL*     Ssl;
};

_Bool TLS_Init(struct TLS* tls);
_Bool TLS_Handshake(struct TLS* tls, int sock, const char* domain);

