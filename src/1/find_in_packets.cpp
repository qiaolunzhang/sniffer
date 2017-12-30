#include "snifferthread.h"

void SnifferThread::FindTextInPackets(QString text_get) {
    this->text_to_find = text_get;
    std::vector<unsigned char*> ::iterator i;
    std::cout << "now we are finding" << std::endl;
    /*
    std::string file_name_to_save_string = file_name_to_save.toStdString();
    const char * file_name_to_save_p = file_name_to_save_string.c_str();
    */
    int data_number = 0;
    for (i = this->Data.begin(); i != this->Data.end(); i++) {
        this->find_packet(*i, data_number);
    }
}

void SnifferThread::find_packet(const u_char *buffer, int data_number)
{

    //Get the IP Header part of this packet , excluding the ethernet header
    iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    int size = ntohs(iph->tot_len) + 14;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            //std::cout << "saving icmp" << std::endl;
            find_icmp_packet( buffer , size, data_number);
            break;

        case 2:  //IGMP Protocol
            break;

        case 6:  //TCP Protocol
            //std::cout << "saving tcp" << std::endl;
            find_tcp_packet(buffer , size, data_number);
            break;

        case 17: //UDP Protocol
            //std::cout << "saving udp" << std::endl;
            find_udp_packet(buffer , size, data_number);
            break;

        default: //Some Other Protocol like ARP etc.
            //std::cout << "other protocol" << std::endl;
            break;
    }
}

void SnifferThread::find_tcp_packet(const u_char * Buffer, int Size, int data_number)
{
    unsigned short iphdrlen;

    iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

   FindData(Buffer + header_size , Size - header_size, data_number);
}

void SnifferThread::find_udp_packet(const u_char *Buffer , int Size, int data_number)
{

    unsigned short iphdrlen;

    iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    //Move the pointer ahead and reduce the size of string
    FindData(Buffer + header_size , Size - header_size, data_number);
}

void SnifferThread::find_icmp_packet(const u_char * Buffer , int Size, int data_number)
{
    unsigned short iphdrlen;

    //struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    //struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    //Move the pointer ahead and reduce the size of string
    FindData(Buffer + header_size , (Size - header_size) , data_number);
}

void SnifferThread::FindData (const u_char * data , int Size, int data_number)
{
    QString result = "";
    int lengthOfString = Size;
    // print string in reverse order
    QString s;
    for( int i = 0; i < lengthOfString; i++ ){
        s = QString( "%1" ).arg( data[i], 0, 16 );

        // account for single-digit hex values (always must serialize as two digits)
        if( s.length() == 1 )
            result.append( "0" );

        result.append( s );
    }

    if (this->text_to_find.toStdString().find(result.toStdString())) {
        //std::cout << result.toStdString() << std::endl;
        this->Data_Finded.push_back(Data[data_number]);
    }
}

