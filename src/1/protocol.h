#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <netinet/in.h> /* for in_addr */
#include <arpa/inet.h> /* for inet_ntoa */
#include <iostream>
#include <pcap.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <QString>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QList>
#include <QPlainTextEdit>
/* default snap length(maximum bytes per packet to capture) */
#define SNAP_LEN 1518
/* ethernet headers are always 14 bytes [1] */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes
*#define ETHER_ADDR_LEN 6
*but it is defined in the header /usr/include/net/ethernet.h which is included
*/

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type; /* IP? ARP? RARP? etc */
};
#define     IPV4        0x0800
#define     ARP         0x0806
#define     IPV6        0x08dd

/* IP header */
/* IP header */
struct sniff_ipv4 {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
		#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp
{
    u_short udp_sp;              	/*source port */
    u_short udp_dp;                	/* destination port*/
	u_short udp_l;                	/* udp length */
    u_short udp_cs;                	/* check sum*/
};

/* ICMP header */
struct sniff_icmp
{
    u_char	icmp_t;             /*type*/
    u_char	icmp_c;             /*code*/
    u_short	icmp_cs;            /*check sum*/
};

/* ARP header */
struct sniff_arp
{
	u_short arp_ht,arp_pt;		/*hardware type & protocol type*/
	u_char	arp_htlen,ptlen;	/*hardware length & protocol length*/
	u_short arp_opcode;		/*type*/
    u_char	arp_sp[ETHER_ADDR_LEN];		/*source physics*/
    char    arp_sip[4];		/*source ip */
    u_char	arp_tp[ETHER_ADDR_LEN];		/*target physics*/
    char    arp_tip[4];		/*target ip*/
};

/* IPv6 header */
struct sniff_ipv6 {
    uint32_t    ip6_vtcfl;          //version, traffic class, flow label
    uint16_t    ip6_len;			//The length of the payload
    uint8_t     ip6_p;              //The next header
    uint8_t     ip6_hop;			//The hop limit
    char        ip6_src[16];		//The 128 bit source address
    char        ip6_dst[16];		//The 128 bit destination address
#define IPV6_HEADER_LENGTH 	40
#define IPV6_VERSION(ip6) 	((ip6)->ip6_vtcfl & 0xf0000000)
#define IPV6_TC(ip6) 	((ip6)->ip6_vtcfl & 0x0ff00000)
#define IPV6_FL(ip6) 	((ip6)->ip6_vtcfl & 0x000fffff)
};


void packet_info(const struct pcap_pkthdr *header,const u_char *packet,QList<QStandardItem *>*row);
void handle_ipv4(const u_char *packet,QList<QStandardItem *> *row);
void handle_ipv6(const u_char *packet,QList<QStandardItem *> *row);
void handle_arp(const u_char *packet,QList<QStandardItem *> *row);
void handle_tcp(const u_char *packet,QList<QStandardItem *> *row);
void handle_udp(const u_char *packet,QList<QStandardItem *> *row);
void handle_icmp(const u_char *packet,QList<QStandardItem *> *row);

void packet_details(const u_char *packet,QStandardItemModel *details);
void ipv4_details(const u_char *packet,QStandardItemModel *details);
void ipv6_details(const u_char *packet,QStandardItemModel *details);
void arp_details(const u_char *packet,QStandardItemModel *details);
void tcp_details(const u_char *packet,QStandardItemModel *details);
void udp_details(const u_char *packet,QStandardItemModel *details);
void icmp_details(const u_char *packet,QStandardItemModel *details);
#endif
