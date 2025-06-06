#ifndef NET_CAPTURE_H
#define NET_CAPTURE_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pthread.h>

#define MAX_PACKETS 1000

typedef struct {
    char time[20];
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    char proto[10];
    const u_char *raw_data;
    int raw_len;
} PacketInfo;

extern PacketInfo packets[MAX_PACKETS];
extern int packet_count;
extern pthread_mutex_t lock;

int matches_filter(PacketInfo *p, const char *filter_input);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void *capture_thread_func(void *arg);

#endif
