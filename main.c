#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <ncurses.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

#define MAX_PACKETS 1000

typedef struct {
    char time[20];
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    char proto[10];
    const u_char *raw_data;
    int raw_len;
    struct pcap_pkthdr header;  // store header for saving packets later
} PacketInfo;

PacketInfo packets[MAX_PACKETS];
int packet_count = 0;
int scroll_offset = 0;
int selected_index = 0;

WINDOW *win;
pcap_t *handle;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

char filter_input[256] = "";
int editing_filter = 0;

int matches_filter(PacketInfo *p) {
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

void show_packet_details(PacketInfo *p) {
    WINDOW *detail_win = newwin(LINES - 4, COLS - 4, 2, 2);
    box(detail_win, 0, 0);
    mvwprintw(detail_win, 1, 2, "Packet Details:");
    mvwprintw(detail_win, 3, 4, "Timestamp: %s", p->time);
    mvwprintw(detail_win, 4, 4, "Source IP: %s", p->src);
    mvwprintw(detail_win, 5, 4, "Destination IP: %s", p->dst);
    mvwprintw(detail_win, 6, 4, "Protocol: %s", p->proto);

    struct ether_header *eth = (struct ether_header *)p->raw_data;
    mvwprintw(detail_win, 8, 2, "[Ethernet]");
    mvwprintw(detail_win, 9, 4, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x",
              eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
              eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    mvwprintw(detail_win, 10, 4, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x",
              eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
              eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_hdr = (struct ip *)(p->raw_data + sizeof(struct ether_header));
        mvwprintw(detail_win, 12, 2, "[IP]");
        mvwprintw(detail_win, 13, 4, "Header Length: %d bytes", ip_hdr->ip_hl * 4);
        mvwprintw(detail_win, 14, 4, "TTL: %d", ip_hdr->ip_ttl);
        mvwprintw(detail_win, 15, 4, "Protocol: %d", ip_hdr->ip_p);

        if (ip_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
            mvwprintw(detail_win, 17, 2, "[TCP]");
            mvwprintw(detail_win, 18, 4, "Source Port: %d", ntohs(tcp_hdr->th_sport));
            mvwprintw(detail_win, 19, 4, "Destination Port: %d", ntohs(tcp_hdr->th_dport));
        } else if (ip_hdr->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_hdr = (struct udphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
            mvwprintw(detail_win, 17, 2, "[UDP]");
            mvwprintw(detail_win, 18, 4, "Source Port: %d", ntohs(udp_hdr->uh_sport));
            mvwprintw(detail_win, 19, 4, "Destination Port: %d", ntohs(udp_hdr->uh_dport));
        }
    }

    int y = 21;
    mvwprintw(detail_win, y++, 2, "[Raw Packet Dump]");

    for (int i = 0; i < p->raw_len; i += 16) {
        char hex[49] = {0};
        char ascii[17] = {0};

        for (int j = 0; j < 16 && (i + j) < p->raw_len; j++) {
            sprintf(&hex[j * 3], "%02x ", p->raw_data[i + j]);
            ascii[j] = isprint(p->raw_data[i + j]) ? p->raw_data[i + j] : '.';
        }

        ascii[16] = '\0';
        mvwprintw(detail_win, y++, 4, "%04x  %-48s  %s", i, hex, ascii);

        if (y >= getmaxy(detail_win) - 2)
            break;
    }

    mvwprintw(detail_win, getmaxy(detail_win) - 2, 2, "[Press q or ESC to return]");
    wrefresh(detail_win);

    int ch;
    while ((ch = getch()) != 'q' && ch != 27)
        ;

    delwin(detail_win);
}

void draw_help_bar() {
    int y = LINES - 1;
    move(y, 0);
    clrtoeol();
    attron(A_REVERSE);
    mvprintw(y, 0,
             " Arrow Keys, PgUp/PgDn: Navigate | Enter: Packet Details | /: Filter, src=IP dst=IP proto=TCP/UDP... | q: Quit");
    attroff(A_REVERSE);
}

void draw_table() {
    werase(win);
    box(win, 0, 0);

    mvwprintw(win, 0, 2, " Filter: %s", filter_input);
    mvwprintw(win, 1, 1, "%-5s %-19s %-15s %-15s %-8s", "No.", "Time", "Source", "Destination", "Proto");

    int max_rows = getmaxy(win) - 4;
    int shown = 0, matched = 0;

    pthread_mutex_lock(&lock);
    for (int i = 0; i < packet_count && shown < max_rows; i++) {
        if (!matches_filter(&packets[i])) continue;
        if (matched++ < scroll_offset) continue;

        int highlight = (shown == selected_index);
        if (highlight) wattron(win, A_REVERSE);

        mvwprintw(win, shown + 2, 1, "%-5d %-19s %-15s %-15s %-8s",
                  i + 1, packets[i].time, packets[i].src, packets[i].dst, packets[i].proto);

        if (highlight) wattroff(win, A_REVERSE);
        shown++;
    }
    pthread_mutex_unlock(&lock);

    wrefresh(win);
    draw_help_bar();
    refresh();
}

void add_packet_and_autoscroll(const struct pcap_pkthdr *header, const u_char *packet) {
    if (packet_count >= MAX_PACKETS) return;

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

    // Store the original pcap header for saving later
    memcpy(&p->header, header, sizeof(struct pcap_pkthdr));

    packet_count++;

    int visible_rows = getmaxy(win) - 4;
    int visible_packets = 0;
    for (int i = 0; i < packet_count; i++)
        if (matches_filter(&packets[i])) visible_packets++;

    if (selected_index >= visible_rows - 1) {
        scroll_offset = visible_packets > visible_rows ? visible_packets - visible_rows : 0;
        selected_index = visible_rows - 1;
    } else {
        selected_index = visible_packets <= visible_rows ? visible_packets - 1 : selected_index;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    pthread_mutex_lock(&lock);
    add_packet_and_autoscroll(header, packet);
    pthread_mutex_unlock(&lock);
}

void *capture_thread_func(void *arg) {
    pcap_loop(handle, -1, packet_handler, NULL);
    return NULL;
}

// Function to save captured packets to a pcap file
void save_pcap() {
    // Generate filename with current date/time
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char filename[128];
    strftime(filename, sizeof(filename), "capture%Y%m%d_%H%M%S.pcap", t);

    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (!dumper) {
        endwin();
        fprintf(stderr, "Error opening dump file: %s\n", pcap_geterr(handle));
        return;
    }

    pthread_mutex_lock(&lock);
    for (int i = 0; i < packet_count; i++) {
        pcap_dump((u_char *)dumper, &packets[i].header, packets[i].raw_data);
    }
    pthread_mutex_unlock(&lock);

    pcap_dump_close(dumper);

    endwin();
    printf("Saved captured packets to file: %s\n", filename);
}

int main() {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net, mask;
    struct pcap_if *alldevs;

    initscr();
    cbreak();
    noecho();
    curs_set(FALSE);
    keypad(stdscr, TRUE);

    win = newwin(LINES - 2, COLS - 2, 1, 1);
    box(win, 0, 0);
    wrefresh(win);
    draw_help_bar();

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        endwin();
        fprintf(stderr, "Device error: %s\n", errbuf);
        return 1;
    }
    dev = alldevs->name;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0; mask = 0;
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

    pthread_t capture_thread;
    pthread_create(&capture_thread, NULL, capture_thread_func, NULL);

    timeout(100);
    int ch;
    while ((ch = getch()) != 'q') {
        if (editing_filter) {
            if (ch == 27 || ch == '\n') {
                editing_filter = 0;
            } else if (ch == KEY_BACKSPACE || ch == 127) {
                int len = strlen(filter_input);
                if (len > 0) filter_input[len - 1] = '\0';
            } else if (isprint(ch) && strlen(filter_input) < sizeof(filter_input) - 1) {
                size_t len = strlen(filter_input);
                filter_input[len] = ch;
                filter_input[len + 1] = '\0';
            }
        } else {
            switch (ch) {
                case '/':
                    editing_filter = 1;
                    memset(filter_input, 0, sizeof(filter_input));
                    selected_index = 0;
                    scroll_offset = 0;
                    break;
                case KEY_UP:
                    if (selected_index > 0) selected_index--;
                    else if (scroll_offset > 0) scroll_offset--;
                    break;
                case KEY_DOWN:
                    selected_index++;
                    break;
                case '\n': {
                    int matched = 0;
                    PacketInfo *selected = NULL;
                    pthread_mutex_lock(&lock);
                    for (int i = 0; i < packet_count; i++) {
                        if (!matches_filter(&packets[i])) continue;
                        if (matched++ == scroll_offset + selected_index) {
                            selected = &packets[i];
                            break;
                        }
                    }
                    pthread_mutex_unlock(&lock);
                    if (selected) show_packet_details(selected);
                    break;
                }
            }
        }
        draw_table();
    }

    pcap_breakloop(handle);
    pthread_join(capture_thread, NULL);

    // Ask user if they want to save capture
    timeout(-1);  // blocking getch
    endwin();
    printf("Do you want to save the captured packets? (y/n): ");
    int answer = getchar();

    if (answer == 'y' || answer == 'Y') {
        // Reinitialize curses temporarily for a message (optional)
        printf("Saving packets...\n");
        save_pcap();
    } else {
        printf("Captured packets were not saved.\n");
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    // Free allocated packet raw data
    for (int i = 0; i < packet_count; i++) {
        free((void *)packets[i].raw_data);
    }

    return 0;
}
