#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <QThread>
#include <QStandardItem>
#include <pcap.h>
#include "protocol.h"
#include "ip_defrag.h"
#include <vector>
#include <QList>
#include <QPlainTextEdit>
#include <netinet/in.h> /* for in_addr */
#include <arpa/inet.h> /* for inet_ntoa */
#include <cmath>

class SnifferThread : public QThread{
public:
    SnifferThread(QStandardItemModel *packetmodel,char *device, char *filter_exp_entered);
    ~SnifferThread();
    void                stopcapture();
    void                FillData(QPlainTextEdit *text,int index,int size);
    void                FillDetails(QStandardItemModel *packetdetails,int index,int size);
    void				IpDefragment();
private:
    char                *device;
    char				*filter_exp;
    bool                stop;
    void                run();
    int                 packetnum;
    struct bpf_program 	fp;
    bpf_u_int32 		mask;
    bpf_u_int32 		net;
    QStandardItemModel  *packetmodel;
    QStandardItemModel  *packetdetails;
    std::vector<unsigned char *> Data;
    std::vector<unsigned char *> Data_after_reasm;
    std::vector<ip_vector> ip_vector_queue;


    void				ip_frag_reasm();
    void				ip_belong_to_packet(size_t hash, int index_packet);
};

#endif // SNIFFERTHREAD_H
