#ifndef IP_DEFRAG_H
#define IP_DEFRAG_H

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <bitset>

#include "protocol.h"

bool				ip_is_fragment(unsigned char * data_check);
bool				ip_is_fragment_ipv4(unsigned char * data_check);
void				ip_defrag(const char* data_check);
int					ip_find(const char* data_check);

#endif // IP_DEFRAG_H
