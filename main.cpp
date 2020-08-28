#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "pcap_struct.h"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct libnet_ipv4_hdr* iph;
struct libnet_tcp_hdr* tcph;

// 패킷을 받아들일경우 이 함수를 호출한다.
// packet 가 받아들인 패킷이다.


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

        // IP 헤더를 가져오기 위해서
        // 이더넷 헤더 크기만큼 offset 한다.
        //packet += sizeof(struct libnet_ethernet_hdr);

        // 프로토콜 타입을 알아낸다.
        ether_type = ntohs(ep->ether_type);

        // MAC print
        printf("\n=============Ethernet Header==============\n");
        printf("==  Source ==\n");
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
                ep->ether_shost[0],
                ep->ether_shost[1],
                ep->ether_shost[2],
                ep->ether_shost[3],
                ep->ether_shost[4],
                ep->ether_shost[5]);
        printf("==  Destination ==\n");
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
                ep->ether_dhost[0],
                ep->ether_dhost[1],
                ep->ether_dhost[2],
                ep->ether_dhost[3],
                ep->ether_dhost[4],
                ep->ether_dhost[5]);

        // 만약 IP 패킷이라면
        if (ether_type == ETHERTYPE_IP)
        {
            // IP 헤더에서 데이타 정보를 출력한다.
            iph = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
            printf("=============IP 패킷==============\n");
            printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
            printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

            // 만약 TCP 데이타 라면
            // TCP 정보를 출력한다.

            tcph = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
            printf("Src Port : %d\n" , ntohs(tcph->th_sport));
            printf("Dst Port : %d\n" , ntohs(tcph->th_dport));

            // Packet 데이타 를 출력한다.
            // IP 헤더 부터 출력한다.

            for(int i = 0; i <16; i++)
                printf("%02x", *((packet++) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + sizeof(struct libnet_ethernet_hdr)));
            printf("\n");
        }
        else printf("\n==Not TCP/IP Packet==\n");

  }

  return 0;
}
