#include <stdint.h>
#include <stdio.h>

#include <stdlib.h>
#ifndef NET_STRUCT_H
#define NET_STRUCT_H

/* eth */
#define ETH_ALEN 6
#define ETH_HLEN 14


/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM	0		/* From KA9Q: NET/ROM pseudo. */
#define ARPHRD_ETHER 	1		/* Ethernet 10/100Mbps.  */
#define	ARPHRD_EETHER	2		/* Experimental Ethernet.  */
#define	ARPHRD_AX25	3		/* AX.25 Level 2.  */
#define	ARPHRD_PRONET	4		/* PROnet token ring.  */
#define	ARPHRD_CHAOS	5		/* Chaosnet.  */
#define	ARPHRD_IEEE802	6		/* IEEE 802.2 Ethernet/TR/TB.  */
#define	ARPHRD_ARCNET	7		/* ARCnet.  */
#define	ARPHRD_APPLETLK	8		/* APPLEtalk.  */
#define	ARPHRD_DLCI	15		/* Frame Relay DLCI.  */
#define	ARPHRD_ATM	19		/* ATM.  */
#define	ARPHRD_METRICOM	23		/* Metricom STRIP (new IANA id).  */
#define ARPHRD_IEEE1394	24		/* IEEE 1394 IPv4 - RFC 2734.  */
#define ARPHRD_EUI64		27		/* EUI-64.  */
#define ARPHRD_INFINIBAND	32		/* InfiniBand.  */






struct eth_hdr{
        uint8_t dst[ETH_ALEN];
        uint8_t src[ETH_ALEN];
        uint16_t type;
        uint8_t data[0];
} __attribute__((packed));

/* ipv4 */
#define IPV4_VER(XX) ((uint8_t)(((XX)->VIHL & 0xF0) >> 4))
#define IPV4_HL(XX)  ((uint8_t)(((XX)->VIHL & 0x0F) << 2))

#define IPV4_HL_MIN 20
#define IPV4_ALEN 0x04


struct ipv4_hdr {
        uint8_t VIHL;
        uint8_t DSCP_ECN;
        uint16_t length;
        uint16_t id;
        uint16_t FF;
        uint8_t TTL;
        uint8_t protocol;
        uint16_t checksum;
        uint8_t src[4];
        uint8_t dst[4];
        uint8_t data[0];
} __attribute__((packed));

/* tcp */
#define TCP_HL(XX) ((uint8_t)((((uint8_t*)(&(XX)->DRF))[0] & 0xF0) >> 2))
#define TCP_PAYLOAD_MAXLEN 16

struct tcp_hdr {
        uint16_t src;
        uint16_t dst;
        uint32_t seq;
        uint32_t ack;
        uint16_t DRF;
        uint16_t wsize;
        uint16_t checksum;
        uint16_t urg;
        uint8_t payload[0];
} __attribute__((packed));

#define	ARPOP_REQUEST	1	/* request to resolve address */
#define	ARPOP_REPLY	2	/* response to previous request */
struct arp_hdr{
        uint16_t arp_hrd;
        uint16_t arp_pro;
        uint8_t  arp_hln;
        uint8_t  arp_pln;
        uint16_t arp_op;
        u_char  arp_sha[6]; /* sender hardware address */
        u_char  arp_spa[4];	/* sender protocol address */
        u_char  arp_tha[6];	/* target hardware address */
        u_char  arp_tpa[4];	/* target protocol address */
}__attribute__((packed));


#endif
