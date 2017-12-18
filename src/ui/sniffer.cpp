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
}
