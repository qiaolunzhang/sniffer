#include "sniffer.h"

sniffer::sniffer()
{
    stopped = false;
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        cout << "Error finding device: " << error_buffer << endl;
        return;
    }
    // create handle
    handle = pcap_open_live(
                device,
                snapshot_len,
                promiscuous,
                timeout,
                error_buffer);
    if (handle == NULL) {
        fprintf(stderr,"Could not open device %s: %s\n", device, error_buffer);
    }
}

sniffer::sniffer(char *device_selected, char *filter_exp_entered)
{
    cout << "filter_exp_entered" << filter_exp_entered << endl;

    stopped = false;
    //device = malloc(strlen(device_selected)+1);
    device = new char[strlen(device_selected)+1];
    memcpy(device, device_selected, strlen(device_selected));
    filter_exp = new char[strlen(filter_exp_entered) + 1];
    memcpy(filter_exp, filter_exp_entered, strlen(filter_exp_entered));

    filter_exp[strlen(filter_exp_entered)] = '\0';

    if (device == NULL) {
        cout << "Error finding device: " << error_buffer << endl;
        return;
    }

    cout << "length of filter_exp at last" << strlen(filter_exp) << endl;
    // find properties for the device
    if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, error_buffer);
        net = 0;
        mask = 0;
    }

    // create handle
    handle = pcap_open_live(
                device,
                snapshot_len,
                promiscuous,
                timeout,
                error_buffer);
    if (handle == NULL) {
        fprintf(stderr,"Could not open device %s: %s\n", device, error_buffer);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net)==-1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
}

void sniffer::run()
{
    static int num = 0;
     while (!stopped) {
        //pcap_loop(handle, 0, got_packet, NULL);
        num = num + 1;
        packet = pcap_next(handle, &header);
        s_packet packet_now(num, &header, packet);
        packet_list.push_back(packet_now);
        //cout << header.len << endl;
    }
}
