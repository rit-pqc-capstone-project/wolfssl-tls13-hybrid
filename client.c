#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

#define NUMBER_OF_RUNS 100

/* Simple selection sort for finding median */
void selectionSort(double arr[], int n)
{
	for (int i = 0; i < n - 1; i++)
	{
		int min = i;
		for (int j = i + 1; j < n; j++)
		{
			if (arr[j] < arr[min])
				min = j;
		}
		if (min != i)
		{
			double temp = arr[min];
			arr[min] = arr[i];
			arr[i] = temp;
		}
	}
}

int main(void)
{
	struct timespec start, end;
	double connect_time[NUMBER_OF_RUNS], handshake_time[NUMBER_OF_RUNS],
		data_send_time[NUMBER_OF_RUNS], data_recv_time[NUMBER_OF_RUNS],
		total_time[NUMBER_OF_RUNS];
	double total_connect_time = 0.0, total_handshake_time = 0.0,
		   total_data_send_time = 0.0, total_data_recv_time = 0.0,
		   total_total_time = 0.0;

	WOLFSSL_CTX *ctx = NULL;
	WOLFSSL *ssl = NULL;
	socket_t sockfd = INVALID_SOCKET;
	struct sockaddr_in servAddr;
	char buff[MSG_SIZE];
	const char *msg = "Hello from TLS 1.3 client!";
	int ret;

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		fprintf(stderr, "WSAStartup failed\n");
		return EXIT_FAILURE;
	}
#endif

	/*Initialize wolfSSL*/
	wolfSSL_Init();

	/*Create context - TLS 1.3 client only*/
	ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
	if (ctx == NULL)
	{
		fprintf(stderr, "wolfSSL_CTX_new failed\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/*Set hybrid ML-KEM key exchange group*/
	int groups[] = {WOLFSSL_SECP256R1MLKEM768};
	if (wolfSSL_CTX_set_groups(ctx, groups, 1) != SSL_SUCCESS)
	{
		fprintf(stderr, "Failed to set hybrid KEM group\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/*Load CA cert to verify server*/
	if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) != SSL_SUCCESS)
	{
		fprintf(stderr, "Failed to load CA cert: %s\n", CA_CERT_FILE);
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	for (int i = 0; i < NUMBER_OF_RUNS; i++)
	{
		clock_gettime(CLOCK_MONOTONIC, &start);

		/*Connect to server via TCP*/
		memset(&servAddr, 0, sizeof(servAddr));
		servAddr.sin_family = AF_INET;
		servAddr.sin_port = htons(DEFAULT_PORT);
		inet_pton(AF_INET, "127.0.0.1", &servAddr.sin_addr);

		clock_gettime(CLOCK_MONOTONIC, &end);
		connect_time[i] = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1e-9;
		total_connect_time += connect_time[i];

		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd == INVALID_SOCKET)
		{
			fprintf(stderr, "socket() failed\n");
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		if (connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) != 0)
		{
			fprintf(stderr, "TCP connect() failed\n");
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		if (i == 0)
			printf("TCP connected, starting TLS handshake...\n");

		/*TLS handshake*/
		clock_gettime(CLOCK_MONOTONIC, &start);

		ssl = wolfSSL_new(ctx);
		if (ssl == NULL)
		{
			fprintf(stderr, "wolfSSL_new failed\n");
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		wolfSSL_set_fd(ssl, (int)sockfd);

		ret = wolfSSL_connect(ssl);
		if (ret != SSL_SUCCESS)
		{
			fprintf(stderr, "TLS handshake failed, error: %d\n",
					wolfSSL_get_error(ssl, ret));
			ret = EXIT_FAILURE;
			goto cleanup;
		}

		clock_gettime(CLOCK_MONOTONIC, &end);
		handshake_time[i] = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1e-9;
		total_handshake_time += handshake_time[i];

		/* Only print details for first run */
		if (i == 0)
		{
			printf("TLS 1.3 handshake successful\n");
			printf("Cipher suite: %s\n", wolfSSL_get_cipher(ssl));
			printf("Key Exchange: %s\n", wolfSSL_get_curve_name(ssl));
		}

		/*Send message to server*/
		clock_gettime(CLOCK_MONOTONIC, &start);
		wolfSSL_write(ssl, msg, (int)strlen(msg));
		clock_gettime(CLOCK_MONOTONIC, &end);
		data_send_time[i] = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1e-9;
		total_data_send_time += data_send_time[i];

		if (i == 0)
			printf("Message sent: %s\n", msg);

		/*Read reply from server*/
		memset(buff, 0, sizeof(buff));
		clock_gettime(CLOCK_MONOTONIC, &start);
		ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
		clock_gettime(CLOCK_MONOTONIC, &end);
		data_recv_time[i] = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) * 1e-9;
		total_data_recv_time += data_recv_time[i];

		if (ret > 0)
		{
			if (i == 0)
			{
				printf("Server says: %s\n", buff);
			}
		}
		else
		{
			fprintf(stderr, "wolfSSL_read failed, error: %d\n",
					wolfSSL_get_error(ssl, ret));
		}

		wolfSSL_free(ssl);
		ssl = NULL;
		CLOSE_SOCKET(sockfd);
		sockfd = INVALID_SOCKET;
	}

	for (int i = 0; i < NUMBER_OF_RUNS; i++)
	{
		total_time[i] = connect_time[i] + handshake_time[i] + data_send_time[i] + data_recv_time[i];
		total_total_time += total_time[i];
	}

	selectionSort(connect_time, NUMBER_OF_RUNS);
	selectionSort(handshake_time, NUMBER_OF_RUNS);
	selectionSort(data_send_time, NUMBER_OF_RUNS);
	selectionSort(data_recv_time, NUMBER_OF_RUNS);
	selectionSort(total_time, NUMBER_OF_RUNS);

	printf("\n--- Performance Metrics (Hybrid ML-KEM) ---\n");
	printf("TCP Connect Time (Average) : %.10f seconds\n", total_connect_time / NUMBER_OF_RUNS);
	printf("TCP Connect Time (Median)  : %.10f seconds\n", (connect_time[NUMBER_OF_RUNS / 2] + connect_time[(NUMBER_OF_RUNS / 2) - 1]) / 2.0);
	printf("TLS Handshake Time (Average): %.10f seconds\n", total_handshake_time / NUMBER_OF_RUNS);
	printf("TLS Handshake Time (Median) : %.10f seconds\n", (handshake_time[NUMBER_OF_RUNS / 2] + handshake_time[(NUMBER_OF_RUNS / 2) - 1]) / 2.0);
	printf("Data Send Time (Average)   : %.10f seconds\n", total_data_send_time / NUMBER_OF_RUNS);
	printf("Data Send Time (Median)    : %.10f seconds\n", (data_send_time[NUMBER_OF_RUNS / 2] + data_send_time[(NUMBER_OF_RUNS / 2) - 1]) / 2.0);
	printf("Data Receive Time (Average): %.10f seconds\n", total_data_recv_time / NUMBER_OF_RUNS);
	printf("Data Receive Time (Median) : %.10f seconds\n", (data_recv_time[NUMBER_OF_RUNS / 2] + data_recv_time[(NUMBER_OF_RUNS / 2) - 1]) / 2.0);
	printf("Total Time (Average)       : %.10f seconds\n", total_total_time / NUMBER_OF_RUNS);
	printf("Total Time (Median)        : %.10f seconds\n", (total_time[NUMBER_OF_RUNS / 2] + total_time[(NUMBER_OF_RUNS / 2) - 1]) / 2.0);
	printf("--------------------------------------------\n");

	ret = 0;

cleanup:
	if (ssl)
		wolfSSL_free(ssl);
	if (ctx)
		wolfSSL_CTX_free(ctx);
	if (sockfd != INVALID_SOCKET)
		CLOSE_SOCKET(sockfd);
	wolfSSL_Cleanup();

#ifdef _WIN32
	WSACleanup();
#endif

	return ret;
}