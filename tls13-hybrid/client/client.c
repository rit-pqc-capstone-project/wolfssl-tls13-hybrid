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
#include <arpa/inet.h>
typedef int socket_t;
#define CLOSE_SOCKET close
#define INVALID_SOCKET -1
#endif

#include "common.h"

int main(void)
{
	WOLFSSL_CTX* ctx = NULL;
	WOLFSSL* ssl = NULL;
	socket_t sockfd = INVALID_SOCKET;
	struct sockaddr_in servAddr;
	char buff[MSG_SIZE];
	const char* msg = "Hello from TLS 1.3 client!";
	int ret;

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed\n");
		return EXIT_FAILURE;
	}
#endif

	/*Initialize wolfSSL*/
	wolfSSL_Init();

	/*Create context - TLS 1.3 client only*/
	ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
	if (ctx == NULL) {
		fprintf(stderr, "wolfSSL_CTX_new failed\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	int groups[] = { WOLFSSL_SECP256R1MLKEM768 };
	if (wolfSSL_CTX_set_groups(ctx, groups, 1) != SSL_SUCCESS) {
		fprintf(stderr, "Failed to set hybrid KEM group\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/*Load CA cert to verify server*/
	if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)
		!= SSL_SUCCESS) {
		fprintf(stderr, "Failed to load CA cert: %s\n", CA_CERT_FILE);
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/*Connect to server via TCP*/
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(DEFAULT_PORT);
	inet_pton(AF_INET, "127.0.0.1", &servAddr.sin_addr);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == INVALID_SOCKET) {
		fprintf(stderr, "socket() failed\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	if (connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) != 0) {
		fprintf(stderr, "TCP connect() failed - is the server running?\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	printf("TCP connected, starting TLS handshake...\n");

	/*TLS handshake*/
	ssl = wolfSSL_new(ctx);
	if (ssl == NULL) {
		fprintf(stderr, "wolfSSL_new failed\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	wolfSSL_set_fd(ssl, (int)sockfd);

	ret = wolfSSL_connect(ssl);
	if (ret != SSL_SUCCESS) {
		fprintf(stderr, "TLS handshake failed, error: %d\n",
			wolfSSL_get_error(ssl, ret));
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	printf("TLS 1.3 handshake successful\n");
	printf("Cipher suite: %s\n", wolfSSL_get_cipher(ssl));
	printf("Key Exchange: %s\n", wolfSSL_get_curve_name(ssl));

	/*Send message to server*/
	wolfSSL_write(ssl, msg, (int)strlen(msg));
	printf("Message sent: %s\n", msg);

	/*Read reply from server*/
	memset(buff, 0, sizeof(buff));
	ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
	if (ret > 0) {
		printf("Server says: %s\n", buff);
	}
	else {
		fprintf(stderr, "wolfSSL_read failed, error: %d\n",
			wolfSSL_get_error(ssl, ret));
	}

	ret = 0;

cleanup:
	if (ssl)                      wolfSSL_free(ssl);
	if (ctx)                      wolfSSL_CTX_free(ctx);
	if (sockfd != INVALID_SOCKET) CLOSE_SOCKET(sockfd);
	wolfSSL_Cleanup();

#ifdef _WIN32
	WSACleanup();
#endif

	return ret;
}