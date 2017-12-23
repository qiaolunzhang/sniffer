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
    return false;
}

bool	ip_is_fragment_ipv4(unsigned char *data_check) {
    static int ip_frag_num = 0;
    const struct sniff_ipv4 *ipv4_check;
    ipv4_check = (struct sniff_ipv4 *)(data_check + SIZE_ETHERNET);

    short ip_offset_host = ntohs(ipv4_check->ip_off);

    std::bitset<16> test(ip_offset_host);
    //std::bitset<16> test(ipv4_check->ip_off);
    std::cout << test<< std::endl;

    if ((ip_offset_host & IP_MF) || (ip_offset_host & 0x00ff)) {
        ip_frag_num += 1;
        std::bitset<16> test(ip_offset_host);
        std::cout << test<< std::endl;
        std::cout << "didn't fragmented packet " << ip_frag_num << "th ip fragment" << std::endl;
        std::cout << "total length is" << ipv4_check->ip_len << std::endl;
        return true;
    }
    else {

        return false;
    }
}

size_t	ip_defrag(unsigned char *data_check) {
    const struct sniff_ipv4 *ipv4_check;
    ipv4_check = (struct sniff_ipv4 *)(data_check + SIZE_ETHERNET);
    //int length = 2(ip_id: short) + 1 (ip_tos: char) + 4 (dst) + 4(src) = 11
    char buffer[11];
    memcpy(buffer+0, &(ipv4_check->ip_id), 2);
    memcpy(buffer+2, &(ipv4_check->ip_tos), 1);
    memcpy(buffer+3, &(ipv4_check->ip_src), 4);
    memcpy(buffer+7, &(ipv4_check->ip_dst), 4);

    std::string buffer_string(buffer, 11);
    std::hash<std::string> h;
    size_t n = h(buffer_string);
    std::cout << "the hash is " << n << std::endl;
    return n;

    // find if this ip is belong to an packet
    // function: ip_find

}

int		ip_find(const char *data_check) {
    // use hash to check

    // if exist, add to it

    // if not exist, create it and insert
}
