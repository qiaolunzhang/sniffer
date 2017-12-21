#include "ip_defrag.h"

bool 	ip_is_fragment(unsigned char *data_check) {
    const struct sniff_ethernet *ethernet_check;
    /* define ethernet header */
    ethernet_check = (struct sniff_ethernet*)(data_check);
    switch(ntohs(ethernet_check->ether_type)) {
    case IPV4: return ip_is_fragment_ipv4(data_check);
    case ARP: return false;
    case IPV6: return false;
    }
}

bool	ip_is_fragment_ipv4(unsigned char *data_check) {
    static int ip_frag_num = 0;
    const struct sniff_ipv4 *ipv4_check;
    ipv4_check = (struct sniff_ipv4 *)(data_check + SIZE_ETHERNET);
    if ((ipv4_check->ip_off & IP_MF) || (ipv4_check->ip_off & 0x00ff)) {
        return true;
    }
    else {
        ip_frag_num += 1;
        std::bitset<16> test(ipv4_check->ip_off);
        std::cout << test<< std::endl;
        std::cout << "didn't fragmented packet " << ip_frag_num << "th ip fragment" << std::endl;
        std::cout << "total length is" << ipv4_check->ip_len << std::endl;
        return false;
    }
}

void 	ip_defrag(const char *data_check) {
    // find if this ip is belong to an packet
    // function: ip_find

}

int		ip_find(const char *data_check) {
    // use hash to check

    // if exist, add to it

    // if not exist, create it and insert
}
