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


#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 1470

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

//the last byte of the mac address is recycled as a port number
#define SRC_MAC_LASTBYTE 15
#define DST_MAC_LASTBYTE 21

static constexpr uint8_t k_ieee_header[] =
{
    0x08, 0x01, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x10, 0x86,
};

constexpr char const* k_tx_fifo_name = "tx";
constexpr char const* k_rx_fifo_name = "rx";

pcap_t* g_pcap = nullptr;
int g_tx_fifo = 0;
int g_rx_fifo = 0;

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
    g_pcap = pcap_open_live(argv[1], 800, 1, 20, pcap_error);
    if (g_pcap == NULL)
    {
        std::cout << "Unable to open interface " << argv[1] << " in pcap: " << pcap_error << "\n";
        return (1);
    }

    std::cout << "Setting nonblocking pcap\n";
    pcap_setnonblock(g_pcap, 1, pcap_error);

    std::cout << "Deleting " << k_rx_fifo_name << " fifo\n";
    unlink(k_rx_fifo_name);
    std::cout << "Creating " << k_rx_fifo_name << " fifo\n";
    if (mkfifo(k_rx_fifo_name, 0444) < 0)
    {
        std::cout << "Unable to create fifo " << k_rx_fifo_name << ": " << strerror(errno) << "\n";
        return 1;
    }
    std::cout << "Opening " << k_rx_fifo_name << " fifo\n";
    g_rx_fifo = open(k_rx_fifo_name, O_RDWR | O_NONBLOCK);
    if (g_rx_fifo < 0)
    {
        std::cout << "Unable to open fifo " << k_rx_fifo_name << ": " << strerror(errno) << "\n";
        return 1;
    }

    std::cout << "Deleting " << k_tx_fifo_name << " fifo\n";
    unlink(k_tx_fifo_name);
    std::cout << "Creating " << k_tx_fifo_name << " fifo\n";
    if (mkfifo(k_tx_fifo_name, 0222) < 0)
    {
        std::cout << "Unable to create fifo " << k_tx_fifo_name << ": " << strerror(errno) << "\n";
        return 1;
    }
    std::cout << "Opening " << k_tx_fifo_name << " fifo\n";
    g_tx_fifo = open(k_tx_fifo_name, O_RDONLY | O_NONBLOCK);
    if (g_tx_fifo < 0)
    {
        std::cout << "Unable to open fifo " << k_tx_fifo_name << ": " << strerror(errno) << "\n";
        return 1;
    }

    std::array<uint8_t, 16> tx_buffer;

    std::cout << "Starting main loop\n";
    while (true)
    {
        ssize_t r = read(g_tx_fifo, tx_buffer.data(), tx_buffer.size());
        if (r > 0)
        {
            //std::copy(tx_buffer.begin(), tx_buffer.begin() + r, std::ostream_iterator<uint8_t>(std::cout));
            static size_t data = 0;
            data += r;
            static size_t ccc = 0;
            ccc++;
            if (ccc > 1000000)
            {
                std::cout << data << std::endl;
                ccc = 0;
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

