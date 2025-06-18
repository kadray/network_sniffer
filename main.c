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

// Struktura przechowująca przetworzone informacje o pakiecie
typedef struct {
    char time[20];              // Czas przechwycenia
    char src[INET_ADDRSTRLEN];  // Źródłowy adres IP
    char dst[INET_ADDRSTRLEN];  // Docelowy adres IP
    char proto[10];             // Protokół (TCP, UDP, etc.)
    const u_char *raw_data;     // Wskaźnik na surowe dane pakietu
    int raw_len;                // Długość surowych danych
    struct pcap_pkthdr header;  // Oryginalny nagłówek pcap (do zapisu)
} PacketInfo;

PacketInfo packets[MAX_PACKETS];

// UI
int packet_count = 0;
int scroll_offset = 0;      // Przesunięcie widoku listy pakietów
int selected_index = 0;     // Aktualnie wybrany wiersz w widocznym oknie
WINDOW *win;                // Główne okno ncurses


pcap_t *handle;             // Uchwyt sesji pcap
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; // Mutex do synchronizacji wątków

char filter_input[256] = ""; // Tekst aktualnego filtra
int editing_filter = 0;      // Flaga trybu edycji filtra
char source_name[256] = "";  // Nazwa źródła (interfejs lub plik)

/**
 * @brief Sprawdza, czy pakiet pasuje do wprowadzonego filtra.
 * @param p Wskaźnik do pakietu do sprawdzenia.
 * @return 1 jeśli pakiet pasuje lub filtr jest pusty, 0 w przeciwnym razie.
 */
int matches_filter(PacketInfo *p) {
    if (strlen(filter_input) == 0) return 1;

    char input_copy[256];
    strncpy(input_copy, filter_input, sizeof(input_copy));
    input_copy[sizeof(input_copy) - 1] = '\0';

    char *token = strtok(input_copy, " ");
    while (token != NULL) {
        if (strncmp(token, "src=", 4) == 0 && strstr(p->src, token + 4) == NULL) return 0;
        if (strncmp(token, "dst=", 4) == 0 && strstr(p->dst, token + 4) == NULL) return 0;
        if (strncmp(token, "proto=", 6) == 0 && strncasecmp(p->proto, token + 6, strlen(token + 6)) != 0) return 0;
        token = strtok(NULL, " ");
    }
    return 1;
}

/**
 * @brief Wyświetla szczegółowe okno z danymi wybranego pakietu.
 * @param p Wskaźnik do pakietu, którego szczegóły mają być wyświetlone.
 */
void show_packet_details(PacketInfo *p) {
    WINDOW *detail_win = newwin(LINES - 4, COLS - 4, 2, 2);
    box(detail_win, 0, 0);
    mvwprintw(detail_win, 1, 2, "Packet Details:");
    mvwprintw(detail_win, 3, 4, "Timestamp: %s", p->time);
    mvwprintw(detail_win, 4, 4, "Source IP: %s", p->src);
    mvwprintw(detail_win, 5, 4, "Destination IP: %s", p->dst);
    mvwprintw(detail_win, 6, 4, "Protocol: %s", p->proto);

    // Dekodowanie i wyświetlanie nagłówków warstw
    struct ether_header *eth = (struct ether_header *)p->raw_data;
    mvwprintw(detail_win, 8, 2, "[Ethernet]");
    mvwprintw(detail_win, 9, 4, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    mvwprintw(detail_win, 10, 4, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_hdr = (struct ip *)(p->raw_data + sizeof(struct ether_header));
        mvwprintw(detail_win, 12, 2, "[IP]");
        mvwprintw(detail_win, 13, 4, "Header Length: %d bytes", ip_hdr->ip_hl * 4);
        mvwprintw(detail_win, 14, 4, "TTL: %d", ip_hdr->ip_ttl);

        if (ip_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
            mvwprintw(detail_win, 16, 2, "[TCP]");
            mvwprintw(detail_win, 17, 4, "Source Port: %d", ntohs(tcp_hdr->th_sport));
            mvwprintw(detail_win, 18, 4, "Destination Port: %d", ntohs(tcp_hdr->th_dport));
        } else if (ip_hdr->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_hdr = (struct udphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
            mvwprintw(detail_win, 16, 2, "[UDP]");
            mvwprintw(detail_win, 17, 4, "Source Port: %d", ntohs(udp_hdr->uh_sport));
            mvwprintw(detail_win, 18, 4, "Destination Port: %d", ntohs(udp_hdr->uh_dport));
        }
    }

    // Wyświetlanie surowych danych (hex dump)
    int y = 21;
    mvwprintw(detail_win, y++, 2, "[Raw Packet Dump]");
    for (int i = 0; i < p->raw_len && y < getmaxy(detail_win) - 2; i += 16) {
        char hex_line[49] = {0}, ascii_line[17] = {0};
        for (int j = 0; j < 16 && (i + j) < p->raw_len; j++) {
            sprintf(&hex_line[j * 3], "%02x ", p->raw_data[i + j]);
            ascii_line[j] = isprint(p->raw_data[i + j]) ? p->raw_data[i + j] : '.';
        }
        mvwprintw(detail_win, y++, 4, "%04x  %-48s  %s", i, hex_line, ascii_line);
    }

    mvwprintw(detail_win, getmaxy(detail_win) - 2, 2, "[Press q or ESC to return]");
    wrefresh(detail_win);

    int ch;
    while ((ch = getch()) != 'q' && ch != 27);
    delwin(detail_win);
}

/**
 * @brief Rysuje dolny pasek pomocy w odwróconych kolorach.
 */
void draw_help_bar() {
    attron(A_REVERSE);
    mvprintw(LINES - 1, 0, " Arrows: Navigate | Enter: Details | /: Filter | q: Quit ");
    clrtoeol(); // Czyści resztę linii
    attroff(A_REVERSE);
}

/**
 * @brief Rysuje główną tabelę z listą pakietów.
 */
void draw_table() {
    werase(win);
    box(win, 0, 0);

    mvwprintw(win, 0, 2, " Source: %s | Filter: %s", source_name, filter_input);
    mvwprintw(win, 1, 1, "%-5s %-19s %-15s %-15s %-8s", "No.", "Time", "Source", "Destination", "Proto");

    int max_rows = getmaxy(win) - 4, shown = 0, matched = 0;

    pthread_mutex_lock(&lock);
    for (int i = 0; i < packet_count && shown < max_rows; i++) {
        if (!matches_filter(&packets[i])) continue;
        if (matched++ < scroll_offset) continue;

        if (shown == selected_index) wattron(win, A_REVERSE);
        mvwprintw(win, shown + 2, 1, "%-5d %-19s %-15s %-15s %-8s", i + 1, packets[i].time, packets[i].src, packets[i].dst, packets[i].proto);
        if (shown == selected_index) wattroff(win, A_REVERSE);
        shown++;
    }
    pthread_mutex_unlock(&lock);

    wrefresh(win);
    draw_help_bar();
    refresh();
}

/**
 * @brief Przetwarza nowy pakiet, dodaje go do globalnej tablicy i obsługuje autoscroll.
 * @param header Nagłówek pcap przechwyconego pakietu.
 * @param packet Wskaźnik na surowe dane pakietu.
 */
void add_packet_and_autoscroll(const struct pcap_pkthdr *header, const u_char *packet) {
    if (packet_count >= MAX_PACKETS) return;

    PacketInfo *p = &packets[packet_count];
    struct tm *timeinfo = localtime(&header->ts.tv_sec);
    strftime(p->time, sizeof(p->time), "%Y-%m-%d %H:%M:%S", timeinfo);

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    strncpy(p->src, inet_ntoa(ip_header->ip_src), sizeof(p->src));
    strncpy(p->dst, inet_ntoa(ip_header->ip_dst), sizeof(p->dst));
    switch (ip_header->ip_p) {
        case IPPROTO_TCP: strcpy(p->proto, "TCP"); break;
        case IPPROTO_UDP: strcpy(p->proto, "UDP"); break;
        case IPPROTO_ICMP: strcpy(p->proto, "ICMP"); break;
        default: strcpy(p->proto, "Other"); break;
    }

    p->raw_data = malloc(header->len);
    memcpy((u_char *)p->raw_data, packet, header->len);
    p->raw_len = header->len;
    memcpy(&p->header, header, sizeof(struct pcap_pkthdr));
    packet_count++;
}


/**
 * @brief Funkcja zwrotna (callback) dla pcap_loop, wywoływana dla każdego pakietu.
 * @param args Argumenty użytkownika (nieużywane).
 * @param header Nagłówek pcap.
 * @param packet Surowe dane pakietu.
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    pthread_mutex_lock(&lock);
    add_packet_and_autoscroll(header, packet);
    pthread_mutex_unlock(&lock);
}

/**
 * @brief Główna funkcja wątku przechwytującego pakiety w trybie na żywo.
 * @param arg Argumenty wątku (nieużywane).
 * @return Zawsze NULL.
 */
void *capture_thread_func(void *arg) {
    pcap_loop(handle, -1, packet_handler, NULL);
    return NULL;
}

/**
 * @brief Zapisuje przechwycone pakiety do pliku .pcap z unikalną nazwą.
 */
void save_pcap() {
    char filename[128];
    time_t now = time(NULL);
    strftime(filename, sizeof(filename), "capture_%Y%m%d_%H%M%S.pcap", localtime(&now));

    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (!dumper) {
        fprintf(stderr, "Error opening dump file: %s\n", pcap_geterr(handle));
        return;
    }
    for (int i = 0; i < packet_count; i++) {
        pcap_dump((u_char *)dumper, &packets[i].header, packets[i].raw_data);
    }
    pcap_dump_close(dumper);
    printf("Saved captured packets to file: %s\n", filename);
}

/**
 * @brief Główna funkcja programu.
 * @param argc Liczba argumentów wiersza poleceń.
 * @param argv Tablica argumentów wiersza poleceń.
 * @return 0 w przypadku powodzenia, >0 w przypadku błędu.
 */
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int is_live_capture = (argc == 1);

    // Inicjalizacja ncurses
    initscr(); cbreak(); noecho(); curs_set(FALSE); keypad(stdscr, TRUE);
    win = newwin(LINES - 2, COLS - 2, 1, 1);

    // Inicjalizacja Pcap (na żywo lub z pliku)
    if (is_live_capture) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            endwin(); fprintf(stderr, "Device error: %s\n", errbuf); return 1;
        }
        snprintf(source_name, sizeof(source_name), "Live Capture (%s)", alldevs->name);
        handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
        pcap_freealldevs(alldevs);
    } else {
        snprintf(source_name, sizeof(source_name), "File: %s", argv[1]);
        handle = pcap_open_offline(argv[1], errbuf);
    }

    if (!handle) {
        endwin(); fprintf(stderr, "Pcap Error: %s\n", errbuf); return 2;
    }
    
    // Uruchomienie przechwytywania (wątek) lub wczytanie z pliku
    pthread_t capture_thread;
    if (is_live_capture) {
        pthread_create(&capture_thread, NULL, capture_thread_func, NULL);
    } else {
        pcap_loop(handle, -1, packet_handler, NULL); // Wczytaj wszystkie pakiety
        scroll_offset = 0; selected_index = 0; // Resetuj widok na początek
    }
    
    // Główna pętla interfejsu użytkownika
    int ch;
    timeout(100); // Odświeżanie co 100ms
    while ((ch = getch()) != 'q') {
        if (editing_filter) {
            if (ch == 27 || ch == '\n') { // ESC lub Enter kończy edycję
                editing_filter = 0;
            } else if (ch == KEY_BACKSPACE || ch == 127) {
                int len = strlen(filter_input);
                if (len > 0) filter_input[len - 1] = '\0';
            } else if (isprint(ch) && strlen(filter_input) < sizeof(filter_input) - 1) {
                size_t len = strlen(filter_input);
                filter_input[len] = ch; filter_input[len+1] = '\0';
            }
        } else {
            switch (ch) {
                case '/': editing_filter = 1; filter_input[0] = '\0'; selected_index = scroll_offset = 0; break;
                case KEY_UP: if (selected_index > 0) selected_index--; else if (scroll_offset > 0) scroll_offset--; break;
                case KEY_DOWN: {
                    int visible_packets = 0;
                    for(int i=0; i<packet_count; i++) if(matches_filter(&packets[i])) visible_packets++;
                    if (scroll_offset + selected_index < visible_packets - 1) selected_index++;
                    break;
                }
                case '\n': {
                    int matched = 0;
                    PacketInfo *selected = NULL;
                    for (int i = 0; i < packet_count; i++) {
                        if (matches_filter(&packets[i]) && matched++ == scroll_offset + selected_index) {
                            selected = &packets[i]; break;
                        }
                    }
                    if (selected) show_packet_details(selected);
                    break;
                }
            }
        }
        draw_table();
    }

    // Czyszczenie zasobów
    endwin();
    if (is_live_capture) {
        pcap_breakloop(handle);
        pthread_join(capture_thread, NULL);
        printf("Do you want to save the captured packets? (y/n): ");
        if (getchar() == 'y') save_pcap();
        else printf("Packets not saved.\n");
    } else {
        printf("Closed pcap file.\n");
    }
    
    pcap_close(handle);
    for (int i = 0; i < packet_count; i++) free((void *)packets[i].raw_data);

    return 0;
}