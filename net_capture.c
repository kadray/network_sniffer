#include "net_capture.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>

PacketInfo packets[MAX_PACKETS];
int packet_count = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int matches_filter(PacketInfo *p, const char *filter_input) {
    if (strlen(filter_input) == 0)
        return 1;

    char input_copy[256];
    strncpy(input_copy, filter_input, sizeof(input_copy));
    input_copy[sizeof(input_copy) - 1] = '\0';

    char *token = strtok(input_copy, " ");
    while (token != NULL) {
        if (strncmp(token, "src=", 4) == 0 && strstr(p->src, token + 4) == NULL)
            return 0;
        else if (strncmp(token, "dst=", 4) == 0 && strstr(p->dst, token + 4) == NULL)
            return 0;
        else if (strncmp(token, "proto=", 6) == 0 &&
                 strncasecmp(p->proto, token + 6, strlen(token + 6)) != 0)
            return 0;
        token = strtok(NULL, " ");
    }
    return 1;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    pthread_mutex_lock(&lock);
    if (packet_count >= MAX_PACKETS) {
        pthread_mutex_unlock(&lock);
        return;
    }

    PacketInfo *p = &packets[packet_count];
    time_t rawtime = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&rawtime);
    strftime(p->time, sizeof(p->time), "%H:%M:%S", timeinfo);

    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        strncpy(p->src, inet_ntoa(ip_header->ip_src), sizeof(p->src));
        strncpy(p->dst, inet_ntoa(ip_header->ip_dst), sizeof(p->dst));

        switch (ip_header->ip_p) {
            case IPPROTO_TCP: strcpy(p->proto, "TCP"); break;
            case IPPROTO_UDP: strcpy(p->proto, "UDP"); break;
            case IPPROTO_ICMP: strcpy(p->proto, "ICMP"); break;
            default: strcpy(p->proto, "Other"); break;
        }
    } else {
        strcpy(p->src, "-");
        strcpy(p->dst, "-");
        strcpy(p->proto, "Non-IP");
    }

    p->raw_data = malloc(header->len);
    memcpy((u_char *)p->raw_data, packet, header->len);
    p->raw_len = header->len;

    packet_count++;
    pthread_mutex_unlock(&lock);
}

void *capture_thread_func(void *arg) {
    pcap_loop((pcap_t *)arg, -1, packet_handler, NULL);
    return NULL;
}
