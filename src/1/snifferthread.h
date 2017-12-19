#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <QThread>
#include <QStandardItem>
#include <pcap.h>
#include "protocol.h"
#include <vector>
#include <QList>
#include <netinet/in.h> /* for in_addr */
#include <arpa/inet.h> /* for inet_ntoa */


class SnifferThread : public QThread{
public:
    SnifferThread(QStandardItemModel *packetmodel,char *device);
    ~SnifferThread();
    void            stopcapture();
private:
    char                *device;
    bool                stop;
    void                run();
    int                 packetnum;
    QStandardItemModel  *packetmodel;
    std::vector<char *> data;

};

#endif // SNIFFERTHREAD_H
