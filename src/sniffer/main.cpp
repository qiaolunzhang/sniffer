#include "mainwindow.h"
#include <QApplication>
#include <iostream>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>


/* default snap length (maximum bytes per packet to capture)
 * The maximum size originally specified according to IEEE 802.3
 * was 1518*/
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6


int main(int argc, char *argv[])
{
    char *dev = NULL;   /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
    pcap_t *handle; /* packet capture handle */

    char filter_exp[] = "ip";   /* filter expression */
    struct bpf_program fp;  /* compiled filter program(expression */
    bpf_u_int32 mask;   /* subnet mask */
    bpf_u_int32 net;    /* ip */
    int num_packets;    /* number of packets to capture */

    /* find the capture device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprint(stderr, "Couldn't find default device: %s\n",
               errbuf);
        exit(EXIT_FAILURE);
    }
    printf("\nEnter no. of packets you want to capture: ");
        scanf("%d", &num_packets);
        printf("\nWhich kind of packets you want to capture: ");
        scanf("%s", filter_exp);
    /* get netwrok number and mask associated with capture device */
    if (pcap_lookupdev(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %s\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}

