#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <QThread>
#include <QStandardItem>
#include <pcap.h>
#include "listtreeview.h"
#include "protocol.h"
#include <netinet/in.h> /* for in_addr */
#include <arpa/inet.h> /* for inet_ntoa */


class SnifferThread : public QThread{
public:
    SnifferThread(ListTreeView *packetmodel,char *device);
    ~SnifferThread();
    void            stopcapture();
private:
    char            *device;
    bool            stop;
    void            run();
    int             packetnum;
    ListTreeView   *packetmodel;

};

#endif // SNIFFERTHREAD_H
