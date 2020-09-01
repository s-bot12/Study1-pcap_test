#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "pcap_struct.h"

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void printMac(u_int8_t* ether_host) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", ether_host[0], ether_host[1], ether_host[2], ether_host[3], ether_host[4], ether_host[5]);
}

struct libnet_ipv4_hdr* iph;
struct libnet_tcp_hdr* tcph;

int main(int argc, char* argv[]) {
    if (argc != 2) {
    usage();
    return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
    }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n\n---%u bytes captured---\n", header->caplen);

    struct libnet_ethernet_hdr *ep;
    u_int16_t ether_type;

        // 이더넷 헤더를 가져온다.
        ep = (struct libnet_ethernet_hdr *)packet;

        // 프로토콜 타입을 알아낸다.
        ether_type = ntohs(ep->ether_type);

        // MAC print
        printf("\n=============Ethernet Header==============\n");
        printf("==  Source ==\n");
        printMac(ep->ether_shost);
        printf("==  Destination ==\n");
        printMac(ep->ether_dhost);

        // 만약 IP 패킷X 라면
        if (ether_type != ETHERTYPE_IP)
            continue;

        // IP 헤더에서 데이타 정보를 출력한다
        iph = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        printf("=============IP 패킷==============\n");
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

        // 만약 TCP 패킷X 라면
        if (iph->ip_p != IP_TCP)
            continue;

        // TCP 정보를 출력한다.
        tcph = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (iph->ip_hl)*4);
        printf("Src Port : %d\n" , ntohs(tcph->th_sport));
        printf("Dst Port : %d\n" , ntohs(tcph->th_dport));

        // Packet 데이타 를 출력한다.
        packet += (iph->ip_hl)*4 + (tcph->th_off)*4 + sizeof(struct libnet_ethernet_hdr);
      
        for(int i = 0; i <16 && i < ntohs(iph->ip_len) - (iph->ip_hl)*4 - (tcph->th_off)*4; i++)
            printf("%02x", *(packet++));
        printf("\n");
    }
    
     pcap_close(handle);
     return 0;
}

