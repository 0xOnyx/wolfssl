
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <bits/socket.h>
#include <fcntl.h>

#include <signal.h>

#define MAX_CONN 4000
#define PORT 5454
#define TIMEOUT 400
#define BUFF_SIZE 255

int cleanup = 1;

struct	s_cert_file {
	char *server_cert;
	char *server_key;
};

struct	s_socket {
	int sockfd;
	WOLFSSL *ssl;
};

void	ft_fail(char *str)
{
	char error[255];

	strcpy(error, "[ERROR]\terror to ");
	strncpy(error, str, 200);
	strcpy(error, " : ");
	perror(error);

	exit(EXIT_FAILURE);
}

int	set_nonblocking(int fd)
{
	if(fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | O_NONBLOCK) < 0)
		return (-1);
	return (0);
}

void	set_sockaddr(struct sockaddr_in *sockaddr)
{
	memset(sockaddr, 0, sizeof(struct sockaddr_in));
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_addr.s_addr = htonl(INADDR_ANY);
	sockaddr->sin_port = htons(PORT);
}

int	init_socket(int *sockfd_back)
{
	int yes;
	int sockfd;

	struct sockaddr_in host_addr;

	sockfd = socket(PF_INET, SOCK_STREAM, 0);

	if(sockfd < 0)
		ft_fail("sockfd create");
	
	yes = 1;

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
		return (-1);

	set_sockaddr(&host_addr);

	if(bind(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) < 0)
		return (-1);

	set_nonblocking(sockfd);

	if(listen(sockfd, MAX_CONN) < 0)
		return (-1);

	*sockfd_back = sockfd;
	return (0);
}

void	*handle_sock(void *smtp_arg)
{
	struct s_socket *socket;
	int sockfd;
	int err;
	WOLFSSL *ssl;

	socket = (struct s_socket *)smtp_arg;
	sockfd = socket->sockfd;
	ssl = socket->ssl;

	int n;
	char buf[BUFF_SIZE + 1];

	n = wolfSSL_accept(ssl);
	if(n != SSL_SUCCESS)
	{
		err = wolfSSL_get_error(ssl, n);
		fprintf(stderr, "[ERROR]\tsocket failed to handshake error => %d string => %s\n", n, wolfSSL_ERR_error_string(err, buf));
	}

	n = 0;
	while((n = wolfSSL_read(ssl, buf, BUFF_SIZE)) > 0)
	{
		if(wolfSSL_write(ssl, buf, n) != n)
			fprintf(stderr, "[ERROR]\tsocket failed to write\n");
	}

	if(n < 0)
	{
		err = wolfSSL_get_error(ssl, n);
		fprintf(stderr, "[ERROR]\tsocket failed to read error => %d string => %s\n", n, wolfSSL_ERR_error_string(err, buf));
	}


	free(smtp_arg);
	
	wolfSSL_free(ssl);
	close(sockfd);

	pthread_exit((void *)EXIT_SUCCESS);
}

void	sig_handler(int sig)
{
	printf("[INFO]\tSIGINT handled \t");
	cleanup = 0;
}

int	main(int argc, char **argv)
{
	struct sigaction act;
	act.sa_handler = sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);

	int sockfd;
	int new_sockfd;
	struct s_socket *thread_arg;
	char buf[BUFF_SIZE + 1];

	struct sockaddr_in client_addr;
	socklen_t sin_size;
	
	pthread_t last_thread;
	

	struct s_cert_file cert_file;

	cert_file.server_cert	= "./certs/certificate.pem";
	cert_file.server_key 	= "./certs/key.pem";

	WOLFSSL_METHOD *method;
	WOLFSSL_CTX *ctx;
	WOLFSSL *ssl;

	if(init_socket(&sockfd) < 0)
		ft_fail("init socket");
	
	sin_size = sizeof(struct sockaddr_in);


	wolfSSL_Init();
	
	method = wolfTLSv1_3_client_method();
	ctx = wolfSSL_CTX_new(method);

	if(ctx == NULL)
		ft_fail("create ctx wolfssl");

	if(wolfSSL_CTX_use_certificate_file(ctx, cert_file.server_cert, SSL_FILETYPE_PEM) != SSL_SUCCESS)
		ft_fail("import server_cert");
	
	if(wolfSSL_CTX_use_PrivateKey_file(ctx, cert_file.server_key, SSL_FILETYPE_PEM) != SSL_SUCCESS)
		ft_fail("import server_key");


	while(cleanup)
	{
		new_sockfd = accept(sockfd, (struct sockaddr*)&client_addr, &sin_size);
		set_nonblocking(new_sockfd);
		if(new_sockfd < 0)
		{
			printf("[ERROR]\tError to accept connexion for socket => %d\n", new_sockfd);
			continue;
		}

		inet_ntop(AF_INET, &(client_addr.sin_addr), buf, sin_size);
		printf("[INFO]\tnew connexion %s:%d\n", buf, ntohs(client_addr.sin_port));
		
		thread_arg = (struct s_socket *)malloc(sizeof(struct s_socket));
		thread_arg->sockfd = new_sockfd;
		thread_arg->ssl = wolfSSL_new(ctx);

		if(thread_arg->ssl == NULL)
			continue;

		wolfSSL_set_fd(ssl, sockfd);
		
		if(pthread_create(&last_thread, NULL, &handle_sock, (void *)thread_arg) < 0)
		{
			printf("[ERROR]\tError to create thread for socket => %d\n", new_sockfd);
			continue;
		}
		
	}

	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();

	close(sockfd);

	return (EXIT_SUCCESS);
}
