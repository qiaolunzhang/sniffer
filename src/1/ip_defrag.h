#ifndef IP_DEFRAG_H
#define IP_DEFRAG_H

#include <bitset>
#include <functional>
#include <string>

#include "protocol.h"

struct ip_vector {
    std::vector<int> ip_vector_fragment;
    int hash_fragment;
};

bool				ip_is_fragment(unsigned char * data_check);
bool				ip_is_fragment_ipv4(unsigned char * data_check);
int					ip_defrag(unsigned char* data_check);
int					ip_find(const char* data_check);

#endif // IP_DEFRAG_H
