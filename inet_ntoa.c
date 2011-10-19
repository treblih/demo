/* =========================================================
 *       Filename:  inet_ntoa.c
 *
 *    Description:  
 *
 *         Author:  Yang Zhang, armx86@gmail.com
 *        Created:  26.07.11
 *       Revision:  
 * ======================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, const char *argv[])
{
    if (2 != argc) {
        fprintf(stderr, "inet_ntoa num\n");
        return 1;
    }
    unsigned num = strtoul(argv[1], NULL, 10);
    struct in_addr addr;
    addr.s_addr = num;
    printf("%s\n", inet_ntoa(addr));
    return 0;
}
