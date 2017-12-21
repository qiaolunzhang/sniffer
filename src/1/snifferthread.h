#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <QThread>
#include <QStandardItem>
#include <pcap.h>
#include "protocol.h"
#include <vector>
#include <QList>
#include <QPlainTextEdit>
#include <netinet/in.h> /* for in_addr */
#include <arpa/inet.h> /* for inet_ntoa */
#include <cmath>

class SnifferThread : public QThread{
public:
    SnifferThread(QStandardItemModel *packetmodel,char *device);
    ~SnifferThread();
    void                stopcapture();
    void                FillData(QPlainTextEdit *text,int index,int size);
    void                FillDetails(QStandardItemModel *packetdetails,int index,int size);
private:
    char                *device;
    bool                stop;
    void                run();
    int                 packetnum;
    QStandardItemModel  *packetmodel;
    QStandardItemModel  *packetdetails;
    std::vector<unsigned char *> Data;

};

#endif // SNIFFERTHREAD_H
