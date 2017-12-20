#ifndef SNIFFER_H
#define SNIFFER_H

#include <QtCore>
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

#include <list>

#include "protocol.h"
//#include <QtWidgets>
#include "listtreeview.h"

//#include "protocol.h"

using namespace std;

//got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

struct s_packet {
    int num;
    //struct pcap_pkthdr *header;
    int caplen;
    u_char *packet;
    s_packet(int i, const struct pcap_pkthdr *header_get, const u_char *packet_get)
    {
        num = i;
        caplen = header_get->caplen;
        packet = (u_char *) malloc((sizeof (unsigned char)) * (header_get->caplen));
        memcpy(packet, packet_get, caplen);
        //header = (struct pcap_pkther *) malloc(sizeof (struct pcap_pkthdr));
        //memcpy(header, header_get, sizeof(struct pcap_pkthdr));
    }
    ~s_packet()
    {
        delete packet;
    }
};

class sniffer: public QThread
{
private:
    char *device;
    int snapshot_len = 1028;
    int promiscuous = 0;
    int timeout = 1000;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    const u_char *packet;
    struct pcap_pkthdr header;

    ListTreeView *mainTreeView;
private:
    void run();
public:
    char *filter_exp;
    volatile bool stopped;
    list<struct s_packet>packet_list;
public:
    sniffer();
    sniffer(char *device_selected, char *filter_exp_entered);
    sniffer(ListTreeView *mymainTreeView);
};

#endif // SNIFFER_H
