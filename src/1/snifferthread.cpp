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
    Data.clear();
}
void    SnifferThread::stopcapture(void){
    stop = true;
}
void    SnifferThread::run(){
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
    int tmp;
    while((tmp=pcap_next_ex(handle,&packet_header,&packet))>=0&&stop==false){

        QList<QStandardItem *>row;
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
    for (i = this->Data.begin(); i != this->Data.end(); i++) {
        if (ip_is_fragment(*i)) {
            //this->ip_defrag(i);
        }
    }
    // this->ip_frag_reasm();
}



void	SnifferThread::ip_frag_reasm() {
    // for each queue
    // sort with offset
    // new data
    // add the pointer to the vector
}
