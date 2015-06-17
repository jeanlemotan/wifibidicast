#include <array>
#include <algorithm>
#include <iterator>
#include <iostream>

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <string.h>
#include <fcntl.h>

extern "C"
{
#include "ieee80211_radiotap.h"
#include "radiotap.h"
}


#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 700

// this is the template radiotap header we send packets out with
static constexpr uint8_t k_radiotap_header[] =
{

    0x00, 0x00, // <-- radiotap version
    0x0c, 0x00, // <- radiotap header lengt
    0x04, 0x80, 0x00, 0x00, // <-- bitmap
    0x22,
    0x0,
    0x18, 0x00
};

// Penumbra IEEE80211 header
static constexpr uint8_t k_ieee_header[] =
{
    0x08, 0x01, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x10, 0x86,
};

// this is where we store a summary of the
// information from the radiotap header

#pragma pack(push, 1)

struct Penumbra_Radiotap_Header
{
    int32_t channel = 0;
    int32_t channel_flags = 0;
    int32_t rate = 0;
    int32_t antenna = 0;
    int32_t radiotap_flags = 0;
};

#pragma pack(pop)

constexpr char const* k_tx_fifo_name = "tx";
constexpr char const* k_rx_fifo_name = "rx";

pcap_t* g_pcap = nullptr;
int g_tx_fifo = 0;
int g_rx_fifo = 0;
size_t g_80211_header_length = 0;
int g_selectable_fd = 0;


static void usage()
{
    std::cout <<
R"((c)2015 leflambeur. Based on befinitiv wifibroadcast.

    Usage:
        wifibidicast <interface>
    Example:
        wifibidicast wlan0
)";
}


static bool prepare_filter()
{
    struct bpf_program program;
    std::string program_src;

    int link_encap = pcap_datalink(g_pcap);

    switch (link_encap)
    {
    case DLT_PRISM_HEADER:
        std::cout << "DLT_PRISM_HEADER Encap\n";
        g_80211_header_length = 0x20; // ieee80211 comes after this
        program_src = "radio[0x4a:4]==0x13223344";
        break;

    case DLT_IEEE802_11_RADIO:
        std::cout << "DLT_IEEE802_11_RADIO Encap\n";
        g_80211_header_length = 0x18; // ieee80211 comes after this
        program_src = "ether[0x0a:4]==0x13223344 ";
        break;

    default:
        std::cout << "!!! unknown encapsulation\n";
        return false;
    }

    if (pcap_compile(g_pcap, &program, program_src.c_str(), 1, 0) == -1)
    {
        std::cout << "Failed to compile program: " << program_src << ": " << pcap_geterr(g_pcap) << "\n";
        return false;
    }
    if (pcap_setfilter(g_pcap, &program) == -1)
    {
        pcap_freecode(&program);
        std::cout << "Failed to set program: " << program_src << ": " << pcap_geterr(g_pcap) << "\n";
        return false;
    }
    pcap_freecode(&program);

    g_selectable_fd = pcap_get_selectable_fd(g_pcap);
    return true;
}

static bool prepare_fifos()
{
    std::cout << "Deleting " << k_rx_fifo_name << " fifo\n";
    unlink(k_rx_fifo_name);
    std::cout << "Creating " << k_rx_fifo_name << " fifo\n";
    if (mkfifo(k_rx_fifo_name, 0444) < 0)
    {
        std::cout << "Unable to create fifo " << k_rx_fifo_name << ": " << strerror(errno) << "\n";
        return false;
    }
    std::cout << "Opening " << k_rx_fifo_name << " fifo\n";
    g_rx_fifo = open(k_rx_fifo_name, O_RDWR | O_NONBLOCK);
    if (g_rx_fifo < 0)
    {
        std::cout << "Unable to open fifo " << k_rx_fifo_name << ": " << strerror(errno) << "\n";
        return false;
    }

    std::cout << "Deleting " << k_tx_fifo_name << " fifo\n";
    unlink(k_tx_fifo_name);
    std::cout << "Creating " << k_tx_fifo_name << " fifo\n";
    if (mkfifo(k_tx_fifo_name, 0222) < 0)
    {
        std::cout << "Unable to create fifo " << k_tx_fifo_name << ": " << strerror(errno) << "\n";
        return false;
    }
    std::cout << "Opening " << k_tx_fifo_name << " fifo\n";
    g_tx_fifo = open(k_tx_fifo_name, O_RDONLY | O_NONBLOCK);
    if (g_tx_fifo < 0)
    {
        std::cout << "Unable to open fifo " << k_tx_fifo_name << ": " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

static size_t prepare_tx_packet(uint8_t* data)
{
    //prepare the buffers with headers
    uint8_t* pu8 = data;
    memcpy(pu8, k_radiotap_header, sizeof(k_radiotap_header));
    pu8 += sizeof(k_radiotap_header);
    memcpy(pu8, k_ieee_header, sizeof (k_ieee_header));
    pu8 += sizeof (k_ieee_header);

    return pu8 - data;
}


static bool process_rx_packet()
{
    struct pcap_pkthdr * ppcapPacketHeader = NULL;
    ieee80211_radiotap_iterator rti;
    Penumbra_Radiotap_Header prh;
    uint8_t payloadBuffer[MAX_PACKET_LENGTH];
    uint8_t* pu8Payload = payloadBuffer;
    int bytes;
    int n;
    uint32_t seq_nr;
    int checksum_correct;
    int u16HeaderLen;

    // receive


    int retval = pcap_next_ex(g_pcap, &ppcapPacketHeader, (const u_char**)&pu8Payload);
    if (retval < 0)
    {
        std::cout << "Socket broken: " << pcap_geterr(g_pcap) << "\n";
        return false;
    }
    if (retval != 1)
    {
        return true;
    }


    u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

    if (ppcapPacketHeader->len < (u16HeaderLen + g_80211_header_length))
    {
        return true;
    }

    bytes = ppcapPacketHeader->len - (u16HeaderLen + g_80211_header_length);
    if (bytes < 0)
    {
        return true;
    }

    if (ieee80211_radiotap_iterator_init(&rti,
                                         (struct ieee80211_radiotap_header *)pu8Payload,
                                         ppcapPacketHeader->len) < 0)
    {
        return true;
    }

    while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0)
    {

        switch (rti.this_arg_index)
        {
        case IEEE80211_RADIOTAP_RATE:
            prh.rate = (*rti.this_arg);
            break;

        case IEEE80211_RADIOTAP_CHANNEL:
            prh.channel = (*((uint16_t *)rti.this_arg));
            prh.channel_flags = (*((uint16_t *)(rti.this_arg + 2)));
            break;

        case IEEE80211_RADIOTAP_ANTENNA:
            prh.antenna = (*rti.this_arg) + 1;
            break;

        case IEEE80211_RADIOTAP_FLAGS:
            prh.radiotap_flags = *rti.this_arg;
            break;
        }
    }
    pu8Payload += u16HeaderLen + g_80211_header_length;

    if (prh.radiotap_flags & IEEE80211_RADIOTAP_F_FCS)
    {
        bytes -= 4;
    }

    checksum_correct = (prh.radiotap_flags & 0x40) == 0;

//    block_num = seq_nr / param_retransmission_block_size;//if retr_block_size would be limited to powers of two, this could be replaced by a logical AND operation

    //printf("rec %x bytes %d crc %d\n", seq_nr, bytes, checksum_correct);

//    std::cout << "RX>>";
    std::copy(pu8Payload, pu8Payload + bytes, std::ostream_iterator<uint8_t>(std::cout));
//    std::cout << "<<RX";

/*
    //we have received a block number that exceeds the currently seen ones -> we need to make room for this new block
    //or we have received a block_num that is several times smaller than the current window of buffers -> this indicated that either the window is too small or that the transmitter has been restarted
    int tx_restart = (block_num + 128*param_retransmission_block_buffers < max_block_num);
    if((block_num > max_block_num || tx_restart) && checksum_correct)
    {
        if(tx_restart)
        {
            fprintf(stderr, "TX RESTART: Detected blk %x that lies outside of the current retr block buffer window (max_block_num = %x) (if there was no tx restart, increase window size via -d)\n", block_num, max_block_num);


            //clear the old buffers TODO: move this into a function
            for(i=0; i<param_retransmission_block_buffers; ++i)
            {
                retransmission_block_buffer_t *rb = retransmission_block_buffer_list + i;
                rb->block_num = -1;

                int j;
                for(j=0; j<param_retransmission_block_size; ++j)
                {
                    packet_buffer_t *p = rb->packet_buffer_list + j;
                    p->valid = 0;
                    p->crc_correct = 0;
                    p->len = 0;
                }
            }
        }

        //first, find the minimum block num in the buffers list. this will be the block that we replace
        int min_block_num = INT_MAX;
        int min_block_num_idx;
        for(i=0; i<param_retransmission_block_buffers; ++i)
        {
            if(retransmission_block_buffer_list[i].block_num < min_block_num)
            {
                min_block_num = retransmission_block_buffer_list[i].block_num;
                min_block_num_idx = i;
            }
        }

        debug_print("removing block %x at index %i for block %x\n", min_block_num, min_block_num_idx, block_num);

        packet_buffer_t *packet_buffer_list = retransmission_block_buffer_list[min_block_num_idx].packet_buffer_list;
        int last_block_num = retransmission_block_buffer_list[min_block_num_idx].block_num;

        if(last_block_num != -1)
        {
            //write out old block
            for(i=0; i<param_retransmission_block_size; ++i)
            {
                packet_buffer_t *p = packet_buffer_list + i;
                num_sent++;
                if(p->valid)
                {
                    write(STDOUT_FILENO, p->data, p->len);
                    if(p->crc_correct == 0)
                        fprintf(stderr, "wrong crc on pkg %x in block %x\n", last_block_num * param_retransmission_block_size + i, last_block_num);
                }
                else
                {
                    fprintf(stderr, "Lost a packet %x! Lossrate: %f\t(%d / %d)\n", i + last_block_num * param_retransmission_block_size, 1.0 * num_lost / num_sent, num_lost, num_sent);
                    num_lost++;
                }

                p->valid = 0;
                p->crc_correct = 0;
                p->len = 0;
            }
        }

        retransmission_block_buffer_list[min_block_num_idx].block_num = block_num;
        max_block_num = block_num;
    }


    //find the buffer into which we have to write this packet
    retransmission_block_buffer_t *rbb = retransmission_block_buffer_list;
    for(i=0; i<param_retransmission_block_buffers; ++i)
    {
        if(rbb->block_num == block_num)
        {
            break;
        }
        rbb++;
    }

    //check if we have actually found the corresponding block. this could not be the case due to a corrupt packet
    if(i != param_retransmission_block_buffers)
    {
        packet_buffer_t *packet_buffer_list = rbb->packet_buffer_list;
        packet_num = seq_nr % param_retransmission_block_size; //if retr_block_size would be limited to powers of two, this could be replace by a locical and operation

        //only overwrite packets where the checksum is not yet correct. otherwise the packets are already received correctly
        if(packet_buffer_list[packet_num].crc_correct == 0)
        {
            memcpy(packet_buffer_list[packet_num].data, pu8Payload, bytes);
            packet_buffer_list[packet_num].len = bytes;
            packet_buffer_list[packet_num].valid = 1;
            packet_buffer_list[packet_num].crc_correct = checksum_correct;
        }
    }

    */

    return true;
}


int main(int argc, char const* argv[])
{
    if (argc == 1)
    {
        usage();
        return 0;
    }

    umask(0000);

    std::cout << "Opening pcap on " << argv[1] << "\n";

    char pcap_error[PCAP_ERRBUF_SIZE] = {0};
    g_pcap = pcap_open_live(argv[1], 800, 1, -1, pcap_error);
    if (g_pcap == NULL)
    {
        std::cout << "Unable to open interface " << argv[1] << " in pcap: " << pcap_error << "\n";
        return (1);
    }

    std::cout << "Setting nonblocking pcap\n";
    if(pcap_setnonblock(g_pcap, 1, pcap_error) < 0)
    {
        std::cout << "Error setting " << argv[1] << " to nonblocking mode: " << pcap_error << "\n";
        return 1;
    }

    if (!prepare_filter())
    {
        return 1;
    }

    if (!prepare_fifos())
    {
        return 1;
    }

    std::array<uint8_t, MAX_PACKET_LENGTH> tx_packet = {0};
    size_t tx_packet_header_length = prepare_tx_packet(tx_packet.data());

//    std::vector<uint8_t, MAX_USER_PACKET_LENGTH> user_tx_buffer;
    size_t user_tx_packet_size = 0;

    std::cout << "Starting main loop\n";
    while (true)
    {
        ssize_t r = read(g_tx_fifo, tx_packet.data() + tx_packet_header_length + user_tx_packet_size, MAX_USER_PACKET_LENGTH - user_tx_packet_size);
        if (r < 0 || r >= 0)
        {
            if (r > 0)
            {
                user_tx_packet_size += r;
            }

            if (r < 0 || user_tx_packet_size > 0)
            {
                int total_size = tx_packet_header_length + user_tx_packet_size;

//                std::cout << "TX>>";
//                std::copy(tx_packet.data(), tx_packet.data() + total_size, std::ostream_iterator<uint8_t>(std::cout));
//                std::cout << "<<TX";


                int r = pcap_inject(g_pcap, tx_packet.data(), total_size);
                if (r != total_size)
                {
                    std::cout << "Trouble injecting packet: " << r << " / " << total_size << " : " << pcap_geterr(g_pcap) << "\n";
                    return (1);
                }
                user_tx_packet_size = 0;
            }
        }


        {
            fd_set readset;
            struct timeval to;

            to.tv_sec = 0;
            to.tv_usec = 1e5;

            FD_ZERO(&readset);
            FD_SET(g_selectable_fd, &readset);

            int n = select(30, &readset, NULL, NULL, &to);
            if (n != 0)
            {
                if (FD_ISSET(g_selectable_fd, &readset))
                {
                    if (!process_rx_packet())
                    {
                        return 1;
                    }
                }
            }
        }
    }

//    //send out the retransmission block several times
//    for(ret=0; ret < param_num_retr; ++ret)
//    {
//        for(i=0; i< param_retransmission_block_size; ++i)
//        {
//            r = pcap_inject(ppcap, packet_buffer_list[i].data, packet_buffer_list[i].len);
//            if (r != packet_buffer_list[i].len)
//            {
//                pcap_perror(ppcap, "Trouble injecting packet");
//                return (1);
//            }

//        }
//    }


    return 0;
}

