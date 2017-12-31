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
#include <cmath>
#include <sstream>

class SnifferThread : public QThread{
public:
    SnifferThread(QStandardItemModel *packetmodel,char *device, char *filter_exp_entered);
    ~SnifferThread();
    void                stopcapture();
    void                FillData(QPlainTextEdit *text,int index,int size);
    void                FillDetails(QStandardItemModel *packetdetails,int index);
    void				IpDefragment();
    int                 Ip_Vec_Size();
    void                Fill_IP_Fragments(QStandardItemModel  *packetmodel);
    void                Fill_IP_Data(QPlainTextEdit *text,int index,int size);
    void                Fill_IP_Details(QStandardItemModel *packetdetails,int index);
    void				SaveSelectedPacket(QString file_name_to_save, struct std::vector<int> packet_index_save);
    void				FindTextInPackets(QString text_get);
    int                 Find_Vec_Size();
    void                Fill_Find_Info(QStandardItemModel *packetmodel);
    void                Fill_Find_Data(QPlainTextEdit *text,int index,int size);
    void                Fill_Find_Details(QStandardItemModel *packetdetails,int index);

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
    std::vector<unsigned char *> Data_Finded;
    std::vector<ip_vector> ip_vector_queue;
    QString				text_to_find;

    // variable for write the file
    FILE 				*logfile;
    struct sockaddr_in 	source,dest;
    struct icmphdr 		*icmph;
    struct iphdr 		*iph;
    struct tcphdr 		*tcph;
    struct ethhdr 		*eth;
    struct udphdr 		*udph;

    void				ip_frag_reasm();
    void				check_ip_queue(struct ip_vector * ip_vector_check);
    void				ip_belong_to_packet(size_t hash, int index_packet);
    void				craft_packet(int ip_vector_craft);


    // write the file
    void 				process_packet(const u_char *);
    void 				process_ip_packet(const u_char * , int);
    void				print_ethernet_header(const u_char *Buffer, int Size);
    void				print_ip_header(const u_char * Buffer, int Size);
    void 				print_ip_packet(const u_char * , int);
    void 				print_tcp_packet(const u_char *  , int );
    void 				print_udp_packet(const u_char * , int);
    void 				print_icmp_packet(const u_char * , int );
    void 				PrintData (const u_char * , int);

    // find text
    void				find_packet(const u_char *buffer, int data_number);
    void				find_tcp_packet(const u_char * Buffer, int Size, int data_number);
    void				find_udp_packet(const u_char *Buffer , int Size, int data_number);
    void				find_icmp_packet(const u_char * Buffer , int Size, int data_number);
    void				FindData (const u_char * data , int Size, int data_number);
};

#endif // SNIFFERTHREAD_H
