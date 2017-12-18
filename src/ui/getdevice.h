#ifndef GETDEVICE_H
#define GETDEVICE_H

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

class getdevice
{
public:
    getdevice();
    ~getdevice();
    void set_all_device();



public:

    char **device_all;
    int device_count;
    char *device; /* Name of device (e.g. eth0, wlan0) */
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw;  /* Subnet mask as integer */
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    struct in_addr address; /* used for both ip & subnet */

    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
};

#endif // SNIFFER_H
