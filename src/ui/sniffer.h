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

using namespace std;

class sniffer: public QThread
{
private:
    char *device;
    int snapshot_len = 1028;
    int promiscuous = 0;
    int timeout = 1000;
    char error_buffer[PCAP_ERRBUF_SIZE];
private:
    void run();
public:
    sniffer();
};

#endif // SNIFFER_H
