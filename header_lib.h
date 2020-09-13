#include <stdint.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#define ETHER_ALEN 6
#define SIZE_ETHERNET 14
#define IP_TCP 6
#define NORMAL 0
#define ABNORMAL 1
#define IP_V 4
#define ARPH_ETHER 1

struct sniff_ethernet {
    uint8_t ether_dhost[ETHER_ALEN];
    uint8_t ether_shost[ETHER_ALEN];
    uint16_t type;
};


struct sniff_ip_hdr {
    uint8_t ip_hl:4;
    uint8_t ip_v:4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct sniff_tcp_hdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_x2:4;
    uint8_t th_off:4;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

struct sniff_arp_hdr {
    uint16_t arp_htype;
    uint16_t arp_ptype;
    uint8_t arp_hlen;
    uint8_t arp_plen;
    uint16_t arp_opcode;
    u_char send_mac[6];
    u_char send_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};

struct eth_hdr{
    uint8_t dst[ETHER_ALEN];
    uint8_t src[ETHER_ALEN];
    uint16_t type;
    uint8_t data[0];
} __attribute__((packed));
