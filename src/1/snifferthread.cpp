#include "snifferthread.h"


SnifferThread::SnifferThread(QStandardItemModel *packetmodel,char *device, char *filter_exp_entered = NULL){
    this->packetmodel = packetmodel;
    this->device = device;
    this->filter_exp = filter_exp_entered;

    stop = false;
    packetnum = 0;
    printf("initialized\n");

}
SnifferThread::~SnifferThread(){
    for(size_t i=0; i<Data.size(); i++){
        free(Data.at(i));
    }
    for(size_t j=0; j<Data_after_reasm.size(); j++) {
        free(Data_after_reasm.at(j));
    }
    fclose(this->logfile);
    Data.clear();
    Data_after_reasm.clear();
}
void    SnifferThread::stopcapture(void){
    stop = true;
}
void    SnifferThread::run(){
    int static num;
    int promiscuous = 0;
    int timeout = 1000;
    int snapshot_len = 66535;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t  *handle;
    pcap_pkthdr *packet_header;
    const u_char *packet;

    /* open device */
    handle = pcap_open_live(device,snapshot_len,promiscuous,timeout,error_buffer);
    if(handle==NULL){
        printf("Couldn't open device %s, %s",device,error_buffer);
        return;
    }

    // find properties for the device
    if (pcap_lookupnet(device, &this->net, &this->mask, error_buffer) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, error_buffer);
        net = 0;
        mask = 0;
    }

    /* setup filter */
    if (pcap_compile(handle, &this->fp, filter_exp, 0, net)==-1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &this->fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }

    /* capture packet */
    /********************************test*/
    this->logfile = fopen("origin_data.txt", "w");
    if(logfile==NULL)
    {
        printf("Unable to create file.");
    }
    fprintf(this->logfile, "second time");

    int tmp;
    while((tmp=pcap_next_ex(handle,&packet_header,&packet))>=0&&stop==false){

        QList<QStandardItem *>row;
        row.append(new QStandardItem(QString::number(++packetnum)));
        packet_info(packet_header,packet,&row);

        /* insert full size of row */
        while(row.size() < 7){
            row.append(new QStandardItem("Unknown"));
        }

        /* save data in vector */
        u_char *newData = (u_char *)malloc(packet_header->len);
        if(newData == NULL){
            printf("ERROR: Malloc failed\n");
            exit(1);
        }
        memcpy(newData, (void*)packet, packet_header->len);
        Data.push_back(newData);
        packetmodel->appendRow(row);
        /*************************************test*/
        num = num + 1;
        if (num < 20) {
            this->process_packet((const u_char *)(newData));
        }
        else if (num == 20){
            fclose(this->logfile);
        }
    }

    stop = false;
    pcap_close(handle);
}
void    SnifferThread::FillData(QPlainTextEdit *text,int index,int size){
    text->clear();
    QString add;
    char d[4],o[9];
    int i,j;
    int offset = 0;
    printf("index:%d & size:%d\n",index,size);
    for(i=0;i<size;i+=16){
        snprintf(o,sizeof(o),"%04x    ",offset);
        add.append(o);
        j=0;
        while(j<(((size-i)<16)?(size-i):16)){
            snprintf(d,sizeof(d),"%02x ",Data.at(index)[offset+j]);
            add.append(d);
            j++;
        }
        add.append(QString('\n'));
        offset +=16;
    }

    text->appendPlainText(add);
}
void    SnifferThread::FillDetails(QStandardItemModel *packetdetails,int index,int size){
    packetdetails->clear();
    packet_details(Data.at(index),packetdetails);
}

void	SnifferThread::IpDefragment() {
    std::vector <unsigned char *> :: iterator i;
    size_t hash_returned;
    int index_packet = 0;
    for (i = this->Data.begin(); i != this->Data.end(); i++) {
        if (ip_is_fragment(*i)) {
            hash_returned = ip_defrag(*i);
            std::cout << "check if hash is same " << hash_returned << std::endl;
            // check if the hash exists, if not create
            this->ip_belong_to_packet(hash_returned, index_packet);
        }
        index_packet = index_packet + 1;
    }

    // check hash
    /*
    std::vector<ip_vector> :: iterator j;
    for (j = ip_vector_queue.begin(); j != ip_vector_queue.end(); ++j) {
        std::cout << "the hash stored now is " << j->hash_fragment << std::endl;
    }
    */
    this->ip_frag_reasm();
    std::cout << "now data_after_defrag's length is " << Data_after_reasm.size() << std::endl;
}

void	SnifferThread::ip_belong_to_packet(size_t hash, int index_packet) {
    std::vector<ip_vector> :: iterator i;
    if (ip_vector_queue.empty()) {
        struct ip_vector ip_vector_new;
        ip_vector_new.hash_fragment = hash;
        // need to change
        ip_vector_new.flag = true;
        ip_vector_queue.push_back(ip_vector_new);

    }
    else {
        for (i = ip_vector_queue.begin(); i != ip_vector_queue.end(); ++i) {
            if (i->hash_fragment == hash) {
                i->ip_vector_fragment.push_back(index_packet);
                std::cout << "a same hash" << std::endl;
                std::cout << "****************************" << std::endl;
                std::cout << "after insert has" << i->ip_vector_fragment.size() << "segment" << std::endl;
                return;
            }
        }
        struct ip_vector ip_vector_new;
        ip_vector_new.hash_fragment = hash;
        // need to change
        ip_vector_new.flag = true;
        ip_vector_new.ip_vector_fragment.push_back(index_packet);
        ip_vector_queue.push_back(ip_vector_new);
    }
}

void	SnifferThread::check_ip_queue(struct ip_vector * ip_vector_check) {
    // sort the ip_queue_fragment with its offset

    // declare a new ip_queue
    // replace the old with the new
    ip_vector_check->flag = true;
}

void 	SnifferThread::craft_packet(int ip_vector_craft) {
    // craft packet
    /* how to construct the data
    1. calculate size
    2. memcpy header
    3. memcpy ip_offset
    4.
      */
    std::cout << "now we are crafting" << std::endl;
    struct ip_vector ip_vector_now = ip_vector_queue[ip_vector_craft];
    unsigned short length_total = 0;
    unsigned short length_ipv4_header = sizeof(struct sniff_ipv4);
    unsigned short length_header = length_ipv4_header + SIZE_ETHERNET;
    unsigned short length_frag;
    length_total += length_header;
    std::vector<int> ::iterator i;
    const u_char * packet_frag;
    const u_char * data_frag;
    const struct sniff_ipv4 *ip;
    /* define ethernet header */

    int index_packet;
    std::cout << "size of this ip_vector is" << ip_vector_now.ip_vector_fragment.size() << std::endl;
    for (i = ip_vector_now.ip_vector_fragment.begin(); i != ip_vector_now.ip_vector_fragment.end(); ++i) {
        index_packet = *i;
        packet_frag = Data[index_packet];
        ip = (struct sniff_ipv4*)(packet_frag + SIZE_ETHERNET);
        printf("src ip: %s\n", inet_ntoa(ip->ip_src));
        length_frag = ntohs(ip->ip_len);
        std::cout << "size of this packet is" << length_frag << std::endl;
        length_total += length_frag - SIZE_ETHERNET;
    }

    u_char *newData = (u_char *)malloc(length_total);
    int copy_index = 0;
    if(newData == NULL) {
        printf("ERROR: Malloc failed\n");
        exit(1);
    }

    memcpy(newData, (void*) Data[index_packet], length_header);

    ip = (struct sniff_ipv4*)(newData + SIZE_ETHERNET);
    // craft header
    copy_index = SIZE_ETHERNET + 16;
    unsigned short length_total_network = htons(length_total);
    memcpy(newData+copy_index, (void*)(&length_total_network), 2);

    copy_index = SIZE_ETHERNET + 48;
    unsigned short offset_packet = htons(0x8000);
    memcpy(newData+copy_index, (void*)(&offset_packet), 2);

    // craft data
    copy_index = length_header;
    for (i = ip_vector_now.ip_vector_fragment.begin(); i != ip_vector_now.ip_vector_fragment.end(); ++i) {
        index_packet = *i;
        packet_frag = Data[index_packet];
        //ip = (struct sniff_ipv4*)(packet_frag + SIZE_ETHERNET);
        data_frag = packet_frag + length_header;
        length_frag = ntohs(ip->ip_len);
        memcpy(newData+copy_index, data_frag, length_frag-length_header);
        copy_index += length_frag - length_header;
    }

    std::cout << "total length of this packet is " << length_total << std::endl;
    Data_after_reasm.push_back(newData);
}


void	SnifferThread::ip_frag_reasm() {
    std::vector<ip_vector> :: iterator j;
    int index_reasm = 0;
    std::cout << "size of ip_vector_queue is " << ip_vector_queue.size() << std::endl;
    for (j = ip_vector_queue.begin(); j != ip_vector_queue.end(); ++j) {
        //this->check_ip_queue(*j);
        if (j->flag) {
            std::cout << "to craft packet" << std::endl;
            this->craft_packet(index_reasm);
        }
        index_reasm = index_reasm + 1;
    }
}
