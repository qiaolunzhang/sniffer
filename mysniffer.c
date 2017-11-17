/*sniffer.c*/
//To compile: gcc -o sniffer sniffer.c -lpcap
//for linux, we need to install libpcap-dev package
//To run: ./sniffer [interface-name]

#include <stdio.h>

int int main(int argc, char const *argv[]) {
  char *dev = NULL;       /* capture device name */
  char errbuff[PCAP_ERRBUF_SIZE];     /* error buffer */
  pcap_t *handle;         /* packet capture handle */

  char filter_exp[] = "ip";   /* filter expression*/
  struct bpf_program fp;
  return 0;
}
