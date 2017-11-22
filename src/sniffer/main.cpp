#include "mainwindow.h"
#include <QApplication>
#include <iostream>
#include <pcap.h>

int main(int argc, char *argv[])
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }
    printf("Network device found: %s\n", device);
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
