#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <errno.h>
#define SERV_PORT 11111
#define MAX_LINE 4096

int main(int argc, char** argv)
{
int listenfd, connfd;
WOLFSSL_CTX* ctx;
WOLFSSL* ssl;
int n;
char buf[MAX_LINE];
WOLFSSL_METHOD* method;

    /* Initialize wolfSSL library */
wolfSSL_Init();

    /* Get encryption method */
method = wolfTLSv1_2_server_method();

    /* Create wolfSSL_CTX */
if ( (ctx = wolfSSL_CTX_new(method)) == NULL)
     err_sys("wolfSSL_CTX_new error");

    /* Load server certs into ctx */
if (wolfSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem",
SSL_FILETYPE_PEM) != SSL_SUCCESS)
     err_sys("Error loading certs/server-cert.pem");

    /* Load server key into ctx */
if (wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem",
SSL_FILETYPE_PEM) != SSL_SUCCESS)
     err_sys("Error loading certs/server-key.pem");

tcp_accept(&listenfd, &connfd, NULL, SERV_PORT, 0, 0, 0);

    /* Create wolfSSL object */
if ( (ssl = wolfSSL_new(ctx)) == NULL)
     err_sys("wolfSSL_new error");

    wolfSSL_set_fd(ssl, connfd);

    if ( (n = wolfSSL_read(ssl, buf, (sizeof(buf) -1))) > 0) {
printf("%s\n", buf);
if (wolfSSL_write(ssl, buf, n) != n)
     err_sys("wolfSSL_write error");
}
if (n <0)
        printf("wolfSSL_read error = %d\n", wolfSSL_get_error(ssl, n));
else if (n == 0)
     printf("Connection close by peer\n");

    wolfSSL_free(ssl);
close(connfd);
wolfSSL_CTX_free(ctx);
wolfSSL_Cleanup();
exit(EXIT_SUCCESS);
}
