#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <ncurses.h>
#include <string.h>
#include <pthread.h>

#define MAX_PACKETS 1000

typedef struct {
    char time[20];
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    char proto[10];
} PacketInfo;

PacketInfo packets[MAX_PACKETS];
int packet_count = 0;
int scroll_offset = 0;

WINDOW *win;
pcap_t *handle;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void draw_table() {
    werase(win);
    box(win, 0, 0);

    mvwprintw(win, 1, 1, "%-5s %-19s %-15s %-15s %-8s", "No.", "Time", "Source", "Destination", "Proto");

    int max_rows = getmaxy(win) - 3;

    pthread_mutex_lock(&lock);
    for (int i = 0; i < max_rows; i++) {
        int idx = i + scroll_offset;
        if (idx >= packet_count) break;

        PacketInfo *p = &packets[idx];
        mvwprintw(win, i + 2, 1, "%-5d %-19s %-15s %-15s %-8s",
                  idx + 1, p->time, p->src, p->dst, p->proto);
    }
    pthread_mutex_unlock(&lock);

    wrefresh(win);
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

    packet_count++;
    pthread_mutex_unlock(&lock);
}

void *capture_thread_func(void *arg) {
    pcap_loop(handle, -1, packet_handler, NULL);
    return NULL;
}

int main() {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net, mask;
    struct pcap_if *alldevs, *device;

    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(FALSE);
    keypad(stdscr, TRUE);

    int height = LINES - 2, width = COLS - 2;
    win = newwin(height, width, 1, 1);
    box(win, 0, 0);
    wrefresh(win);

    // Get device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        endwin();
        fprintf(stderr, "Device error: %s\n", errbuf);
        return 1;
    }
    dev = alldevs->name;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        endwin();
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        endwin();
        fprintf(stderr, "Filter error\n");
        return 3;
    }

    // Start packet capture in a separate thread
    pthread_t capture_thread;
    pthread_create(&capture_thread, NULL, capture_thread_func, NULL);

    timeout(100); // 100 ms getch wait

    // UI loop
    int ch;
    while ((ch = getch()) != 'q') {
        switch (ch) {
            case KEY_UP:
                if (scroll_offset > 0)
                    scroll_offset--;
                break;
            case KEY_DOWN:
                pthread_mutex_lock(&lock);
                if (scroll_offset < packet_count - (LINES - 4))
                    scroll_offset++;
                pthread_mutex_unlock(&lock);
                break;
        }
        draw_table();
    }

    pcap_breakloop(handle);
    pthread_join(capture_thread, NULL);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    endwin();
    return 0;
}
