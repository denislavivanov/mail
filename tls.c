#include "tls.h"


_Bool TLS_Init(struct TLS* tls)
{
    SSL_CTX* ctx;

    tls->Ctx = SSL_CTX_new(TLS_client_method());
    ctx      = tls->Ctx;

    if (ctx == NULL)
        return 0;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);

    return 1;
}

_Bool TLS_Handshake(struct TLS* tls, int sock, const char* domain)
{
    SSL* ssl;

    tls->Ssl = SSL_new(tls->Ctx);
    ssl      = tls->Ssl;

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, domain);
    SSL_set1_host(ssl, domain);

    if (SSL_connect(ssl) != 1)
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}