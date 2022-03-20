
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <bits/socket.h>
#include <fcntl.h>


#define MAX_CONN 4000
#define PORT 5454
#define TIMEOUT 400
#define BUFF_SIZE 255
#define 

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
	sockaddr->sin_addr.s_addr = htonl(INADR_ANY);
	sockaddr->sin_port = htons(PORT);
}

int	init_socket(int *sockfd_back)
{
	int yes;
	int sockfd;

	struct sockaddr_in host_addr;

	sockfd = socket(PF_INET, SOCK_STREAM, 0);

	if(sockfd < 0)
		ft_fail();
	
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

void	*handle_smtp(void *smtp_arg)
{
	int sockfd;
	sockfd = *(int *)smtp_arg;
	free(smtp_arg);
	
	close(sockfd);
	pthread_exit((void *)EXIT_SUCCESS);
}

int	main(int argc, char **argv)
{
	int sockfd;
	int new_sockfd;
	int *thread_arg;
	char buf[BUFF_SIZE + 1];

	struct scokaddr_in client_addr;
	socklen_t sin_size;
	pthread_t last_thread;
	
	WOLFSSL_METHOD *method;
	WOLFSSL_CTX *ctx;
	WOLFSSL *ssl;

	if(init_sockfd(&sockfd) < 0)
		ft_fail();
	
	sin_size = sizeof(struct sockaddr_in);


	wolfSSL_Init();
	
	method = wolfTLSv1_3_client_method();
	ctx = wolfSSL_CTX_new(method);

	if(ctx == NULL)
		ft_fail();

	if(wolfSSL_CTX_load_verify_location(ctx, , 0) != SSL_SUCCESS)
		ft_fail();
	



	while(1)
	{
		new_sockfd = accept(sockfd, (struct sockaddr*)&client_addr, &sin_size);
		if(new_socfd < 0)
		{
			printf("[ERROR]\tError to accept connexion for socket => %d\n", new_sockfd);
			continue;
		}

		buf = inet_ntoa((struct in_addr)client_addr.sin_addr);
		printf("[INFO]\tnew connexion %s:%d\n", buf, ntohs(client_addr.sin_port));
		
		thread = (int *)malloc(sizeof(int));
		*thread = new_sockfd;
		
		if(pthread_create(&last_thread, NULL, &handle_sock, (void *)thread_arg) < 0)
		{
			printf("[ERROR]\tError to create thread for socket => %d\n", new_sockfd);
			continue;
		}
		
	}

	close(sockfd);

	return (EXIT_SUCCESS);
}
