#include "snifferthread.h"

#include <pcap/pcap.h>

SnifferThread::SnifferThread(QStandardItemModel *packetmodel,char *device){
    this->packetmodel = packetmodel;
    this->device = device;
    stop = false;
    packetnum = 0;
    printf("initialized\n");
}
SnifferThread::~SnifferThread(){

}
void SnifferThread::stopcapture(void){
    stop = true;
}
void SnifferThread::run(){
    int promiscuous = 0;
    int timeout = 1000;
    int snapshot_len = 1028;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t  *handle;
    pcap_pkthdr *packet_header;
    const u_char *packet;

    printf("open device\n");
//open ad device
    handle = pcap_open_live(device,snapshot_len,promiscuous,timeout,error_buffer);
    if(handle==NULL){
        printf("Couldn't open device %s, %s",device,error_buffer);
        return;
    }
    printf("device open\n");

//capture packet
    int tmp;
    while((tmp=pcap_next_ex(handle,&packet_header,&packet))>=0&&stop==false){
        QList<QStandardItem *>row;
        packet_info(packet_header,packet,&row);
        while(row.size() < 6){
            row.append(new QStandardItem("Unknown"));
        }
        packetmodel->appendRow(row);
    }

    stop = false;
    pcap_close(handle);
}
