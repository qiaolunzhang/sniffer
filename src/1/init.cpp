
#include "init.h"
/* Find all the device */

char *device;
pcap_t *handle;
const u_char *packet;
char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

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

void determin_packet_type_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet
)
{
    print_packet_info(packet, *packet_header);
    return;
}

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr* header,
    const u_char* packet
) {
    print_packet_info(packet, *header);
    struct ether_header *eth_header;
    /* The packet is larger than the ether_header struct,
       but we just want to look at the first part of the packet
       that contains the header. We force the compiler
       to treat the pointer to the packet as just a pointer
       to the ether_header. The data payload of the packet comes
       after the headers. Different packet types have different header
       lengths though, but the ethernet header is always the same (14 bytes) */
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("ARP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Reverse ARP\n");
    }
}
