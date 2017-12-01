#include "init.h"

using namespace std;

int main(int argc, char *argv[]) {
    // print_all_devices();
    check_device(device);

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        cout << "Error finding device: " << error_buffer << endl;
        return 1;
    }

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
         return 2;
     }

    pcap_loop(handle, 0, my_packet_handler, NULL);

    return 0;
}
