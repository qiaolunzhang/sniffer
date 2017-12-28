#include "protocol.h"

/* dissect/print packet*/
void packet_info(const struct pcap_pkthdr *header, const u_char *packet, QList<QStandardItem *> *row)
{
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
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
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &arp->arp_sip, buffer, INET_ADDRSTRLEN);
    row->append(new QStandardItem(buffer));
    inet_ntop(AF_INET, &arp->arp_tip, buffer, INET_ADDRSTRLEN);
    row->append(new QStandardItem(QString(buffer)));
    row->append(new QStandardItem(QString("ARP")));

    QString info;
    switch(ntohs(arp->arp_opcode)){
    case ARP_REQ:{
        info.append(QString("Who has "));
        inet_ntop(AF_INET, &arp->arp_tip, buffer, INET_ADDRSTRLEN);
        info.append(buffer);
        info.append(QString("? Tell "));
        inet_ntop(AF_INET, &arp->arp_sip, buffer, INET_ADDRSTRLEN);
        info.append(buffer);
        break;
    }
    case ARP_REP:{
        inet_ntop(AF_INET, &arp->arp_tip, buffer, INET_ADDRSTRLEN);
        info.append(buffer);
        info.append(QString(" is at "));
        char tmp[4];
        for(int i=0;i<6;i++){
            snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(arp->arp_tp+i));
            info.append(tmp);
        }
        break;
    }
    default:info.append(QString("UNKNOWN"));
    }
    row->append(new QStandardItem(QString(info)));
}
void handle_tcp(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_tcp *tcp;
    tcp = (struct sniff_tcp *)packet;
    row->append(new QStandardItem(QString("TCP")));

    QString info;
    info.append(QString::number(ntohs(tcp->th_sport)));
    info.append(QString(" to "));
    info.append(QString::number(ntohs(tcp->th_dport)));
    info.append(" [ ");
    if((tcp->th_flags&TH_FIN)==TH_FIN)info.append("FIN ");
    if((tcp->th_flags&TH_SYN)==TH_SYN)info.append("SYN ");
    if((tcp->th_flags&TH_RST)==TH_RST)info.append("RST ");
    if((tcp->th_flags&TH_PUSH)==TH_PUSH)info.append("PUSH ");
    if((tcp->th_flags&TH_ACK)==TH_ACK)info.append("ACK ");
    if((tcp->th_flags&TH_URG)==TH_URG)info.append("URG ");
    if((tcp->th_flags&TH_ECE)==TH_ECE)info.append("ECE ");
    if((tcp->th_flags&TH_CWR)==TH_CWR)info.append("CWR ");
    info.append("] Seq=");
    info.append(QString::number(ntohl(tcp->th_seq)));
    info.append(" Ack=");
    info.append(QString::number(ntohl(tcp->th_ack)));
    info.append(" Win=");
    info.append(QString::number(ntohs(tcp->th_win)));

    row->append(new QStandardItem(info));
}
void handle_udp(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_udp *udp;
    udp = (struct sniff_udp *)packet;
    row->append(new QStandardItem(QString("UDP")));

    QString info;
    info.append(QString::number(ntohs(udp->udp_sp)));
    info.append(QString(" to "));
    info.append(QString::number(ntohs(udp->udp_dp)));
    info.append(QString(" Len="));
    info.append(QString::number(ntohs(udp->udp_l)));
    row->append(new QStandardItem(info));

}
void handle_icmp(const u_char *packet,QList<QStandardItem *> *row){
    const struct sniff_icmp *icmp;
    icmp = (struct sniff_icmp *)packet;
    row->append(new QStandardItem(QString("ICMP")));
    switch(icmp->icmp_t){
    case ICMP_REPLY:row->append(new QStandardItem(QString("Echo (ping) reply)")));break;
    case ICMP_REQUEST:row->append(new QStandardItem(QString("Echo (ping) request)")));break;
    }
}

/* insert packet details into model */
void packet_details(const u_char *packet, QStandardItemModel *details){
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

    root->appendRow(new QStandardItem(dh));
    root->appendRow(new QStandardItem(sh));

    switch(ntohs(ethernet->ether_type)){
    case IPV4:{
        pro.append(QString("IPV4(0x0800)"));
        ipv4_details(packet+SIZE_ETHERNET,details);
        break;
    }
    case ARP:{
        pro.append(QString("ARP(0x0806)"));
        arp_details(packet+SIZE_ETHERNET,details);
        break;
    }
    case IPV6:{
        pro.append(QString("IPV6(0x86dd)"));
        ipv6_details(packet+SIZE_ETHERNET,details);
        break;
    }
    default:pro.append(QString("UNKNOWN"));
    }
    root->appendRow(new QStandardItem(pro));
}
void ipv4_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Internet Protocol Version 4"));
    details->appendRow(root);

    const struct sniff_ipv4 *ip;
    ip = (struct sniff_ipv4*)packet;
    int size_ip;
    size_ip = IP_HL(ip)*4;

    QString ver("IP Version:  "),
            hl("Header Length:  "),
            tos("Type Of Service:  "),
            tl("Total Length:  "),
            id("Identification:  "),
            flag("Flags:  "),
            of("Fragment Offset:  "),
            ttl("Time To Live:  "),
            pro("Protocol:  "),
            hc("Header Checksum:  "),
            sip("Source IP:  "),
            dip("Destination IP:  ");

    ver.append(QString::number(IP_V(ip)));
    hl.append(QString::number(size_ip));
    hl.append(QString(" bytes"));
    char tmp5[5],tmp7[7];
    snprintf(tmp5,sizeof(tmp5),"0x%02x",ip->ip_tos);
    tos.append(tmp5);
    tl.append(QString::number(ntohs(ip->ip_len)));
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(ip->ip_id));
    id.append(tmp7);
    switch(ntohs(ip->ip_off)&0xe000){
    case IP_RF: {
        snprintf(tmp5,sizeof(tmp5),"0x%02x",IP_RF>>13);
        flag.append(tmp5);
        flag.append(QString("(Reserved bit)"));
        break;
    }
    case IP_DF: {
        snprintf(tmp5,sizeof(tmp5),"0x%02x",IP_DF>>13);
        flag.append(tmp5);
        flag.append(QString("(Don't fragment)"));
        break;
    }
    case IP_MF: {
        snprintf(tmp5,sizeof(tmp5),"0x%02x",IP_MF>>13);
        flag.append(tmp5);
        flag.append(QString("(More fragments)"));
        break;
    }
    default:flag.append(QString("0x00"));
    }
    of.append(QString::number(ntohs(ip->ip_off)&IP_OFFMASK));
    ttl.append(QString::number(ip->ip_ttl));
    switch(ip->ip_p) {
    case IPPROTO_TCP:{
        pro.append(QString("TCP(6)"));
        tcp_details((packet+size_ip),details,ntohs(ip->ip_len)-size_ip);
        break;
    }
    case IPPROTO_UDP:{
        pro.append(QString("UDP(17)"));
        udp_details((packet+size_ip),details,ntohs(ip->ip_len)-size_ip);
        break;
    }
    case IPPROTO_ICMP:{
        pro.append(QString("ICMP(1)"));
        icmp_details((packet+size_ip),details,ntohs(ip->ip_len)-size_ip);
        break;
    }
    default:pro.append(QString("UNKNOWN"));
    }
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(ip->ip_sum));
    hc.append(tmp7);
    sip.append(QString(inet_ntoa(ip->ip_src)));
    dip.append(QString(inet_ntoa(ip->ip_dst)));

    root->appendRow(new QStandardItem(ver));
    root->appendRow(new QStandardItem(hl));
    root->appendRow(new QStandardItem(tos));
    root->appendRow(new QStandardItem(tl));
    root->appendRow(new QStandardItem(id));
    root->appendRow(new QStandardItem(flag));
    root->appendRow(new QStandardItem(of));
    root->appendRow(new QStandardItem(ttl));
    root->appendRow(new QStandardItem(pro));
    root->appendRow(new QStandardItem(hc));
    root->appendRow(new QStandardItem(sip));
    root->appendRow(new QStandardItem(dip));
}
void ipv6_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Internet Protocol Version 6"));
    details->appendRow(root);

    const struct sniff_ipv6 *ip;
    ip = (struct sniff_ipv6*)packet;

    QString ver("Version:  "),
            tc("Traffic Class:  "),
            f("Flowlabel:  "),
            pl("Payload Length:  "),
            nh("Next Header:  "),
            hl("Hop Limit:  "),
            sip("Source IP:  "),
            dip("Destination IP:  ");

    ver.append(QString::number(IPV6_VERSION(ip)));
    char tmp5[5],tmp8[8];
    snprintf(tmp5,sizeof(tmp5),"0x%02x",IPV6_TC(ip));
    tc.append(tmp5);
    snprintf(tmp8,sizeof(tmp8),"0x%05x",IPV6_FL(ip));
    tc.append(tmp8);
    pl.append(QString::number(ntohs(ip->ip6_len)));
    switch(ip->ip6_p) {
    case IPPROTO_TCP:{
        nh.append(QString("TCP(6)"));
        tcp_details((packet+IPV6_HEADER_LENGTH),details,ntohs(ip->ip6_len));
        break;
    }
    case IPPROTO_UDP:{
        nh.append(QString("UDP(17)"));
        udp_details((packet+IPV6_HEADER_LENGTH),details,ntohs(ip->ip6_len));
        break;
    }
    case IPPROTO_ICMP:{
        nh.append(QString("ICMP(1)"));
        icmp_details((packet+IPV6_HEADER_LENGTH),details,ntohs(ip->ip6_len));
        break;
    }
    default:nh.append(QString("UNKNOWN"));
    }
    hl.append(QString::number(ip->ip6_hop));
    char buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip->ip6_src, buffer, sizeof(buffer));
    sip.append(QString(buffer));
    inet_ntop(AF_INET6, ip->ip6_dst, buffer, sizeof(buffer));
    dip.append(QString(buffer));

    root->appendRow(new QStandardItem(ver));
    root->appendRow(new QStandardItem(tc));
    root->appendRow(new QStandardItem(f));
    root->appendRow(new QStandardItem(pl));
    root->appendRow(new QStandardItem(nh));
    root->appendRow(new QStandardItem(hl));
    root->appendRow(new QStandardItem(sip));
    root->appendRow(new QStandardItem(dip));
}
void arp_details(const u_char *packet,QStandardItemModel *details){
    QStandardItem *root = new QStandardItem(QString("Address Resolution Protocol"));
    details->appendRow(root);

    const struct sniff_arp *arp;
    arp = (struct sniff_arp *)packet;

    QString ht("Hardware Type:  "),
            pt("Protocol Type:  "),
            hs("Hardware Size:  "),
            ps("Protocol Size:  "),
            o("Opcode:  "),
            sm("Sender MAC:  "),
            sip("Sender IP:  "),
            tm("Target MAC:  "),
            tip("Target IP:  ");

    if(ntohs(arp->arp_ht)==0x0001)ht.append(QString("Ethernet(1)"));
    else ht.append(QString("UNKNOWN"));
    if(ntohs(arp->arp_pt)==IPV4)pt.append(QString("IPV4(0x0800)"));
    else pt.append(QString("UNKNOWN"));
    hs.append(QString::number(arp->arp_htlen));
    ps.append(QString::number(arp->ptlen));
    switch(ntohs(arp->arp_opcode)){
    case ARP_REQ:o.append(QString("request(1)"));break;
    case ARP_REP:o.append(QString("reply(2)"));break;
    default:o.append(QString("UNKNOWN"));
    }
    int i;
    char tmp[4];
    for(i=0;i<6;i++){
        snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(arp->arp_sp+i));
        sm.append(tmp);
    }
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &arp->arp_sip, buffer, INET_ADDRSTRLEN);
    sip.append(buffer);
    for(i=0;i<6;i++){
        snprintf(tmp,sizeof(tmp),((i==5)?"%02x":"%02x:"),*(arp->arp_tp+i));
        tm.append(tmp);
    }
    inet_ntop(AF_INET, &arp->arp_tip, buffer, INET_ADDRSTRLEN);
    tip.append(buffer);

    root->appendRow(new QStandardItem(ht));
    root->appendRow(new QStandardItem(pt));
    root->appendRow(new QStandardItem(hs));
    root->appendRow(new QStandardItem(ps));
    root->appendRow(new QStandardItem(o));
    root->appendRow(new QStandardItem(sm));
    root->appendRow(new QStandardItem(sip));
    root->appendRow(new QStandardItem(tm));
    root->appendRow(new QStandardItem(tip));

}
void tcp_details(const u_char *packet,QStandardItemModel *details,int size){
    QStandardItem *root = new QStandardItem(QString("Transmission Control Protocol"));
    details->appendRow(root);

    const struct sniff_tcp *tcp;
    tcp = (struct sniff_tcp *)packet;
    int size_tcp = TH_OFF(tcp)*4;

    QString sp("Source Port:  "),
            dp("Destination Port:  "),
            sn("Sequence Number:  "),
            an("Acknowledgment Number:  "),
            hl("Header Length:  "),
            flag("Flags:  "),
            ws("Window Size value:  "),
            cs("Checksum:  "),
            up("Urgent Pointer:  ");
    sp.append(QString::number(ntohs(tcp->th_sport)));
    dp.append(QString::number(ntohs(tcp->th_dport)));
    sn.append(QString::number(ntohl(tcp->th_seq)));
    an.append(QString::number(ntohl(tcp->th_ack)));
    hl.append(QString::number(size_tcp));
    hl.append(QString("(bytes)"));

    char tmp5[5],tmp7[7];
    snprintf(tmp5,sizeof(tmp5),"0x%02x",tcp->th_flags);
    flag.append(tmp5);
    flag.append('(');
    if((tcp->th_flags&TH_FIN)==TH_FIN)flag.append("FIN ");
    if((tcp->th_flags&TH_SYN)==TH_SYN)flag.append("SYN ");
    if((tcp->th_flags&TH_RST)==TH_RST)flag.append("RST ");
    if((tcp->th_flags&TH_PUSH)==TH_PUSH)flag.append("PUSH ");
    if((tcp->th_flags&TH_ACK)==TH_ACK)flag.append("ACK ");
    if((tcp->th_flags&TH_URG)==TH_URG)flag.append("URG ");
    if((tcp->th_flags&TH_ECE)==TH_ECE)flag.append("ECE ");
    if((tcp->th_flags&TH_CWR)==TH_CWR)flag.append("CWR ");
    flag.append(')');
    ws.append(QString::number(ntohs(tcp->th_win)));
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(tcp->th_sum));
    cs.append(tmp7);
    up.append(QString::number(ntohs(tcp->th_urp)));

    root->appendRow(new QStandardItem(sp));
    root->appendRow(new QStandardItem(dp));
    root->appendRow(new QStandardItem(sn));
    root->appendRow(new QStandardItem(an));
    root->appendRow(new QStandardItem(hl));
    root->appendRow(new QStandardItem(flag));
    root->appendRow(new QStandardItem(ws));
    root->appendRow(new QStandardItem(cs));
    root->appendRow(new QStandardItem(up));

    printf("tcp size:%d\n",size);
    if(size>size_tcp){
        int len = size-size_tcp;
        QString dataroot("Data(");
        QString data;
        dataroot.append(QString::number(size-size_tcp));
        dataroot.append(" bytes)");
        QStandardItem *datarootitem = new QStandardItem(dataroot);
        details->appendRow(datarootitem);
        char tmp[2];
        const u_char *ch=packet+size_tcp;
        for(int i =0;i<len;i++){
            if(isprint(*ch)){
                snprintf(tmp,sizeof(tmp),"%c",*ch);
                data.append(tmp);
            }
            else
                data.append('.');
            ch++;
        }
        datarootitem->appendRow(new QStandardItem(data));
    }
}
void udp_details(const u_char *packet,QStandardItemModel *details,int size){
    QStandardItem *root = new QStandardItem(QString("User Datagram Protocol"));
    details->appendRow(root);

    const struct sniff_udp *udp;
    udp = (struct sniff_udp *)packet;

    QString sp("Source Port:  "),
            dp("Destination Port:  "),
            len("Length:  "),
            cs("Checksum:  ");

    sp.append(QString::number(ntohs(udp->udp_sp)));
    dp.append(QString::number(ntohs(udp->udp_dp)));
    len.append(QString::number(ntohs(udp->udp_l)));
    char tmp7[7];
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(udp->udp_cs));
    cs.append(tmp7);

    root->appendRow(new QStandardItem(sp));
    root->appendRow(new QStandardItem(dp));
    root->appendRow(new QStandardItem(len));
    root->appendRow(new QStandardItem(cs));

    if(size>8){
        int len = size-8;
        QString dataroot("Data(");
        QString data;
        dataroot.append(QString::number(len));
        dataroot.append(" bytes)");
        QStandardItem *datarootitem = new QStandardItem(dataroot);
        details->appendRow(datarootitem);
        char tmp[2];
        const u_char *ch=packet+8;
        for(int i =0;i<len;i++){
            if(isprint(*ch)){
                snprintf(tmp,sizeof(tmp),"%c",*ch);
                data.append(tmp);
            }
            else
                data.append('.');
            ch++;
        }
        datarootitem->appendRow(new QStandardItem(data));
    }
}
void icmp_details(const u_char *packet, QStandardItemModel *details, int size){
    QStandardItem *root = new QStandardItem(QString("Internet Control Message Protocol"));
    details->appendRow(root);

    const struct sniff_icmp *icmp;
    icmp = (struct sniff_icmp *)packet;
    QString t("Type:  "),
            c("Code:  "),
            cs("Checksum:  ");

    t.append(QString::number(icmp->icmp_t));
    switch(icmp->icmp_t){
    case ICMP_REPLY:t.append("(Echo (ping) reply)");break;
    case ICMP_REQUEST:t.append("(Echo (ping) request)");break;
    }
    c.append(QString::number(icmp->icmp_c));
    char tmp7[7];
    snprintf(tmp7,sizeof(tmp7),"0x%04x",ntohs(icmp->icmp_cs));
    cs.append(tmp7);

    root->appendRow(new QStandardItem(t));
    root->appendRow(new QStandardItem(c));
    root->appendRow(new QStandardItem(cs));

    if(size>8){
        int len = size-8;
        QString dataroot("Data(");
        QString data;
        dataroot.append(QString::number(len));
        dataroot.append(" bytes)");
        QStandardItem *datarootitem = new QStandardItem(dataroot);
        details->appendRow(datarootitem);
        char tmp[2];
        const u_char *ch=packet+8;
        for(int i =0;i<len;i++){
            if(isprint(*ch)){
                snprintf(tmp,sizeof(tmp),"%c",*ch);
                data.append(tmp);
            }
            else
                data.append('.');
            ch++;
        }
        datarootitem->appendRow(new QStandardItem(data));
    }
}
