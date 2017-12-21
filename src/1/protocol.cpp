#include "protocol.h"

/* dissect/print packet*/
void packet_info(const struct pcap_pkthdr *header, const u_char *packet, QList<QStandardItem *> *row)
{
    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    row->append(new QStandardItem(QString::number(count++)));
    row->append(new QStandardItem(QString(ctime((const time_t *)&header->ts.tv_sec))));

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    switch(ntohs(ethernet->ether_type)){
    case IPV4:  handle_ipv4((packet+SIZE_ETHERNET),row);break;
    case ARP:   handle_arp(packet+SIZE_ETHERNET,row);break;
    case IPV6:  handle_ipv6(packet+SIZE_ETHERNET,row);break;
    }
    row->insert(5,new QStandardItem(QString::number(header->caplen)));
}
void handle_ipv4(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_ipv4 *ip;
    int size_ip;
    ip = (struct sniff_ipv4*)packet;
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
     printf("   * Invalid IP header length: %u bytes\n", size_ip);
     return;
    }
    /* source and destination IP addresses */
    row->append(new QStandardItem(QString(inet_ntoa(ip->ip_src))));
    row->append(new QStandardItem(QString(inet_ntoa(ip->ip_dst))));
    /* determine protocol */
    switch(ip->ip_p) {
    case IPPROTO_TCP:
       //printf("   Protocol: TCP\n");
       handle_tcp((packet+size_ip),row);
       break;
     case IPPROTO_UDP:
       //printf("   Protocol: UDP\n");
       handle_udp((packet+size_ip),row);
       break;
     case IPPROTO_ICMP:
       //printf("   Protocol: ICMP\n");
       handle_icmp((packet+size_ip),row);
       break;
     default:
       //printf("   Protocol: unknown\n");
       row->append(new QStandardItem("UNKNOWN"));
       break;
    }
}
void handle_ipv6(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_ipv6 *ip;
    ip = (struct sniff_ipv6 *)packet;

    /* source and destination IPV6 addresses */
    char buffer[INET6_ADDRSTRLEN];
    printf("     Source:%s\n", inet_ntop(AF_INET6, ip->ip6_src, buffer, sizeof(buffer)));
    row->append(new QStandardItem(QString(buffer)));
    printf("Destination:%s\n", inet_ntop(AF_INET6, ip->ip6_dst, buffer, sizeof(buffer)));
    row->append(new QStandardItem(QString(buffer)));

    /* determine protocol */
    switch(ip->ip6_p) {
    case IPPROTO_TCP:
       //printf("   Protocol: TCP\n");
       handle_tcp((packet+IPV6_HEADER_LENGTH),row);
       break;
     case IPPROTO_UDP:
       //printf("   Protocol: UDP\n");
       handle_udp((packet+IPV6_HEADER_LENGTH),row);
       break;
     case IPPROTO_ICMP:
       //printf("   Protocol: ICMP\n");
       handle_icmp((packet+IPV6_HEADER_LENGTH),row);
       break;
     default:
       //printf("   Protocol: unknown\n");
       row->append(new QStandardItem("UNKNOWN"));
       break;
    }
}
void handle_arp(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_arp *arp;
    arp = (struct sniff_arp *)packet;
    row->append(new QStandardItem(QString(inet_ntoa(arp->arp_sip))));
    row->append(new QStandardItem(QString(inet_ntoa(arp->arp_tip))));
    row->append(new QStandardItem(QString("ARP")));
}
void handle_tcp(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_tcp *tcp;
    tcp = (struct sniff_tcp *)packet;
    row->append(new QStandardItem(QString("TCP")));
}
void handle_udp(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_udp *udp;
    udp = (struct sniff_udp *)packet;
    row->append(new QStandardItem(QString("UDP")));
}
void handle_icmp(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_icmp *icmp;
    icmp = (struct sniff_icmp *)packet;
    row->append(new QStandardItem(QString("ICMP")));
}

/* insert packet details into model */
void packet_details(const u_char *packet,QStandardItemModel *details){
    /* add root to details */
    QStandardItem *root = new QStandardItem(QString("Ethernet II"));
    details->appendRow(root);

    const struct sniff_ethernet *ethernet;
    ethernet = (struct sniff_ethernet*)(packet);

    /* add leaf */
    int i;
    QString dh("Destination Address:  "),
            sh("Source Address:  "),
            pro("Ethernet Type:  ");
    char tmp[4];
    for(i=0;i<6;i++){
        snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(ethernet->ether_dhost+i));
        dh.append(tmp);
        snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(ethernet->ether_shost+i));
        sh.append(tmp);
    }
    QStandardItem *dhitem = new QStandardItem(dh);
    QStandardItem *shitem = new QStandardItem(sh);
    root->appendRow(dhitem);
    root->appendRow(shitem);

    switch(ntohs(ethernet->ether_type)){
    case IPV4:{
        pro.append(QString("IPV4(0x0800)"));
        QStandardItem *proitem = new QStandardItem(pro);
        root->appendRow(proitem);
        ipv4_details(packet+SIZE_ETHERNET,details);
        break;
    }
    case ARP:{
        pro.append(QString("ARP(0x0806)"));
        QStandardItem *proitem = new QStandardItem(pro);
        root->appendRow(proitem);
        arp_details(packet+SIZE_ETHERNET,details);
        break;
    }
    case IPV6:{
        pro.append(QString("IPV6(0x86dd)"));
        QStandardItem *proitem = new QStandardItem(pro);
        root->appendRow(proitem);
        ipv6_details(packet+SIZE_ETHERNET,details);
        break;
    }
    }

}
void ipv4_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Internet Protocol Version 4"));
    details->appendRow(root);

    const struct sniff_ipv4 *ip;
    int size_ip;
    ip = (struct sniff_ipv4*)packet;
    size_ip = IP_HL(ip)*4;

    QString ver("IP Version:  "),
            hl("Header Length:  "),
            tos("Type Of Service:  "),
            tl("Total Length:  "),
            id("Identification:  "),
            flag("Flags:  "),
            fo("Fragment Offset:  "),
            ttl("Time To Live:  "),
            pro("Protocol:  "),
            hc("Header Checksum:  "),
            sip("Source IP:  "),
            dip("Destination IP:  ");
    QStandardItem   *veritem = new QStandardItem(ver),
                    *hlitem = new QStandardItem(hl),
                    *tositem = new QStandardItem(tos),
                    *tlitem = new QStandardItem(tl),
                    *iditem = new QStandardItem(id),
                    *flagitem = new QStandardItem(flag),
                    *foitem = new QStandardItem(fo),
                    *ttlitem = new QStandardItem(ttl),
                    *proitem = new QStandardItem(pro),
                    *hcitem = new QStandardItem(hc),
                    *sipitem = new QStandardItem(sip),
                    *dipitem = new QStandardItem(dip);
    root->appendRow(veritem);
    root->appendRow(hlitem);
    root->appendRow(tositem);
    root->appendRow(tlitem);
    root->appendRow(iditem);
    root->appendRow(flagitem);
    root->appendRow(foitem);
    root->appendRow(ttlitem);

    switch(ip->ip_p) {
    case IPPROTO_TCP:{
       tcp_details((packet+size_ip),details);
       break;
    }
     case IPPROTO_UDP:{
       udp_details((packet+size_ip),details);
       break;
    }
     case IPPROTO_ICMP:{
       icmp_details((packet+size_ip),details);
       break;
    }
    }
    root->appendRow(proitem);
    root->appendRow(hcitem);
    root->appendRow(sipitem);
    root->appendRow(dipitem);
}
void ipv6_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Internet Protocol Version 6"));
    details->appendRow(root);
}
void arp_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Address Resolution Protocol"));
    details->appendRow(root);
}
void tcp_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Transmission Control Protocol"));
    details->appendRow(root);
}
void udp_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("User Datagram Protocol"));
    details->appendRow(root);
}
void icmp_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Internet Control Message Protocol"));
    details->appendRow(root);
}
