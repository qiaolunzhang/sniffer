#include "sniffer.h"

sniffer::sniffer()
{
    stopped = false;
}

void sniffer::run()
{
    struct pcap_pkthdr header;
    const u_char *packet;
    if (!stopped) {
        //mainTreeView->addOneCaptureItem("1", "2", "3", "4", "5", "6");
        device = pcap_lookupdev(error_buffer);
        if (device == NULL) {
            cout << "Error finding device: " << error_buffer << endl;
            return;
        }
        cout << device << endl;
        handle = pcap_open_live(
                    device,
                    snapshot_len,
                    promiscuous,
                    timeout,
                    error_buffer);
        if (handle == NULL) {
            fprintf(stderr,"Could not open device %s: %s\n", device, error_buffer);
        }

        packet = pcap_next(handle, &header);
    }
    //mainTreeView->addOneCaptureItem("1", "2", "3", "4", "5", "6");
}

sniffer::sniffer(ListTreeView *mymainTreeView)
{
    mainTreeView = mymainTreeView;
    stopped = false;
}


