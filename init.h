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
int packet_count_limit = 1;
int timeout_limit = 10000;  /* In milliseconds */

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

void print_all_devices();

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
);

/* Find all the device */
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}


void print_all_devices()
{
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
}


void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    print_packet_info(packet_body, *packet_header);
    return;
}
