#ifndef INIT_H
#define INIT_H
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

using namespace std;
//std::string str;


extern char *device; /* Name of device (e.g. eth0, wlan0) */
extern char ip[13];
extern char subnet_mask[13];
extern bpf_u_int32 ip_raw; /* IP address as integer */
extern bpf_u_int32 subnet_mask_raw;  /* Subnet mask as integer */
extern int lookup_return_code;
extern char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
extern struct in_addr address; /* used for both ip & subnet */

extern pcap_t *handle;
extern const u_char *packet;
extern struct pcap_pkthdr packet_header;
//extern int packet_count_limit = 1;
//int timeout_limit = 10000;  /* In milliseconds */

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

void print_all_devices();

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet
);

void determin_packet_type_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet
);
#endif
