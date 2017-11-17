/* Compile with: gcc find-device.c -lpcap */
#include <stdio.h>
#include <pcap.h>

int main(int argc, char **argv) {
    char *device;   /* name of  device (e.g. eth0, enp1s0, wlan0, wlp2s0) */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* size defined in pcap.h */

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    printf("Network device found: %s\n", device);
    return 0;
}
