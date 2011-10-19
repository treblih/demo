/* =========================================================
 *       Filename:  inet_addr.c
 *
 *    Description:  
 *
 *         Author:  Yang Zhang, armx86@gmail.com
 *        Created:  26.07.11
 *       Revision:  
 * ======================================================== */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, const char *argv[])
{
    if (3 != argc) {
        fprintf(stderr, "inet_addr xx.xx.xx.xx (n|h)\n");
        return 1;
    }
    unsigned addr = inet_addr(argv[1]);
    switch (*argv[2]) {
    case 'h':
        addr = ntohl(addr);
    break;
    default:
    break;
    }
    printf("%u\n", addr);
    return 0;
}
