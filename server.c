#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define CLOSE_SOCKET closesocket
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    typedef int socket_t;
    #define CLOSE_SOCKET close
    #define INVALID_SOCKET -1
#endif

#include "common.h"

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    socket_t     listenfd = INVALID_SOCKET;
    socket_t     connfd   = INVALID_SOCKET;
    struct sockaddr_in servAddr;
    char         buff[MSG_SIZE];
    const char*  reply = "Hello from TLS 1.3 server";
    int          ret;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return EXIT_FAILURE;
    }
#endif

    /*Initialize WolfSSL*/
    wolfSSL_Init();

    /*Create context*/
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /*Set hybrid ML-KEM key exchange group*/
    int groups[] = { WOLFSSL_SECP256R1MLKEM768 };
    if (wolfSSL_CTX_set_groups(ctx, groups, 1) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to set hybrid KEM group, error: %d\n",
                wolfSSL_get_error(NULL, 0));
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /*Load server certs*/
    if (wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM)
            != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load cert: %s\n", CERT_FILE);
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /*Load server private key*/
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM)
            != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load key: %s\n", KEY_FILE);
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /*Setup TCP listening socket*/
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_port        = htons(DEFAULT_PORT);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    printf("Setting up TCP listening socket...\n");

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    if (bind(listenfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) != 0) {
        fprintf(stderr, "bind() failed\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    if (listen(listenfd, 5) != 0) {
        fprintf(stderr, "listen() failed\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    printf("Server listening on port %d...\n", DEFAULT_PORT);

    for (;;) {
        /*Accept client connection*/
        connfd = accept(listenfd, NULL, NULL);
        if (connfd == INVALID_SOCKET) {
            fprintf(stderr, "accept() failed\n");
            ret = EXIT_FAILURE;
            goto cleanup;
        }

        printf("TCP connection accepted, starting handshake...\n");

        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "wolfSSL_new failed\n");
            ret = EXIT_FAILURE;
            goto cleanup;
        }

        /*Associate connected socket with SSL object*/
        wolfSSL_set_fd(ssl, (int)connfd);

        /*Perform handshake*/
        ret = wolfSSL_accept(ssl);
        if (ret != SSL_SUCCESS) {
            fprintf(stderr, "TLS handshake failed, error: %d\n",
                    wolfSSL_get_error(ssl, ret));
            ret = EXIT_FAILURE;
            goto cleanup;
        }

        printf("TLS 1.3 handshake successful!\n");
        printf("Cipher suite: %s\n", wolfSSL_get_cipher(ssl));
        printf("Key Exchange: %s\n", wolfSSL_get_curve_name(ssl));

        /*Exchange Messages*/
        memset(buff, 0, sizeof(buff));
        ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
        if (ret > 0) {
            printf("Client says: %s\n", buff);
        }
        else {
            fprintf(stderr, "wolfSSL_read failed, error: %d\n",
                    wolfSSL_get_error(ssl, ret));
        }

        /* Send reply*/
        wolfSSL_write(ssl, reply, (int)strlen(reply));
        printf("Reply sent.\n");

        wolfSSL_free(ssl);
        ssl = NULL;
        CLOSE_SOCKET(connfd);
        connfd = INVALID_SOCKET;
    }

cleanup:
    if (ssl)                        wolfSSL_free(ssl);
    if (ctx)                        wolfSSL_CTX_free(ctx);
    if (connfd   != INVALID_SOCKET) CLOSE_SOCKET(connfd);
    if (listenfd != INVALID_SOCKET) CLOSE_SOCKET(listenfd);
    wolfSSL_Cleanup();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}