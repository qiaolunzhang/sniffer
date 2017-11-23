#include "mainwindow.h"
#include <QApplication>
#include <iostream>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[])
{
    char *device;
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct in_addr address; /* Used for both ip & subnet */
    /* for capture */
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* in milliseconds */

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* Get device info */
    lookup_return_code = pcap_lookupnet(
                device,
                &ip_raw,
                &subnet_mask_raw,
                error_buffer);
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }

    /* Get ip in human readable form */
    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); /* print error */
    }

    /* Get subnet mask in human readble form */
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }

    printf("Device: %s\n", device);
    printf("IP addresss: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);

    /* Open device for live capture*/
    handle = pcap_open_live(
                device,
                BUFSIZ,
                packet_count_limit,
                timeout_limit,
                error_buffer);
    packet = pcap_next(handle, &packet_header);
    if (packet == NULL) {
        printf("No packet found.\n");
        return 2;
    }

    /* Our function to output some info */
    print_packet_info(packet, packet_header);
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}
