/* Compile with: g++ find_device.cpp -lpcap */
#include <netinet/in.h> /* for in_addr */
#include <arpa/inet.h> /* for inet_ntoa */
#include <iostream>
#include <pcap.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

using namespace std;

int main(int argc, char **argv) {
    char *device; /* Name of device (e.g. eth0, wlan0) */
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw;  /* Subnet mask as integer */
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    struct in_addr address; /* used for both ip & subnet */

    /* Find all the device */
    struct if_nameindex *if_ni, *i;

    if_ni = if_nameindex();
    if (if_ni == NULL) {
        perror("if_nameindex");
        exit(EXIT_FAILURE);
    }

    cout << "This computer has the following devices: " << endl;
    for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++)
        printf("%u: %s\n", i->if_index, i->if_name);
    if_freenameindex(if_ni);

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        cout << "Error finding device: " << error_buffer << endl;
        return 1;
    }

    cout << "The network device that is using: " <<  device << endl;

    /* Get device info */
    lookup_return_code = pcap_lookupnet(
      device,
      &ip_raw,
      &subnet_mask_raw,
      error_buffer
    );
    if (lookup_return_code == -1) {
      cout << error_buffer << endl;
      return 1;
    }

    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
      perror("inet_ntoa");  /* print error */
      return 1;
    }

    /* Get subnet mask in human readable form */
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
      perror("inet_ntoa");
      return 1;
    }
    cout << "IP address: " << ip << endl;
    cout << "Subnet mask: " << subnet_mask << endl;
    return 0;
}
