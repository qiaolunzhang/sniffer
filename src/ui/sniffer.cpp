#include "sniffer.h"

sniffer::sniffer()
{

}

void sniffer::run()
{
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

    pcap_loop(handle, 0, got_packet, NULL);
}
