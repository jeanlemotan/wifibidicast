#include <array>
#include <algorithm>
#include <iterator>
#include <iostream>
#include <mutex>
#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>

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


static bool g_exit = false;

static size_t g_max_packet_size = MAX_USER_PACKET_LENGTH;

struct PCAP
{
    pcap_t* pcap = nullptr;
    size_t _80211_header_length = 0;
    int selectable_fd = 0;
    size_t tx_packet_header_length = 0;

    std::mutex tx_buffer_mutex;
    std::vector<uint8_t> tx_buffer;
    std::atomic_bool tx_data_available = { false };
} g_pcap;

struct ASIO
{
    boost::thread thread;

    boost::asio::io_service io_service;
    boost::asio::ip::udp::endpoint tx_endpoint;
    boost::asio::ip::udp::endpoint rx_endpoint;
    std::unique_ptr<boost::asio::ip::udp::socket> socket;
    std::array<uint8_t, MAX_USER_PACKET_LENGTH> rx_buffer;

    std::mutex tx_buffer_pool_mutex;
    typedef std::shared_ptr<std::vector<uint8_t>> TX_Buffer;
    std::vector<TX_Buffer> tx_buffer_pool;

    std::mutex tx_buffer_queue_mutex;
    std::vector<TX_Buffer> tx_buffer_queue; //to send

    TX_Buffer tx_buffer_in_transit;


    boost::function<void(const boost::system::error_code& error, std::size_t bytes_transferred)> tx_callback;
    boost::function<void(const boost::system::error_code& error, std::size_t bytes_transferred)> rx_callback;
} g_asio;


static bool prepare_filter()
{
    struct bpf_program program;
    std::string program_src;

    int link_encap = pcap_datalink(g_pcap.pcap);

    switch (link_encap)
    {
    case DLT_PRISM_HEADER:
        std::cout << "DLT_PRISM_HEADER Encap\n";
        g_pcap._80211_header_length = 0x20; // ieee80211 comes after this
        program_src = "radio[0x4a:4]==0x13223344";
        break;

    case DLT_IEEE802_11_RADIO:
        std::cout << "DLT_IEEE802_11_RADIO Encap\n";
        g_pcap._80211_header_length = 0x18; // ieee80211 comes after this
        program_src = "ether[0x0a:4]==0x13223344 ";
        break;

    default:
        std::cout << "!!! unknown encapsulation\n";
        return false;
    }

    if (pcap_compile(g_pcap.pcap, &program, program_src.c_str(), 1, 0) == -1)
    {
        std::cout << "Failed to compile program: " << program_src << ": " << pcap_geterr(g_pcap.pcap) << "\n";
        return false;
    }
    if (pcap_setfilter(g_pcap.pcap, &program) == -1)
    {
        pcap_freecode(&program);
        std::cout << "Failed to set program: " << program_src << ": " << pcap_geterr(g_pcap.pcap) << "\n";
        return false;
    }
    pcap_freecode(&program);

    g_pcap.selectable_fd = pcap_get_selectable_fd(g_pcap.pcap);
    return true;
}

static void asio_rx_callback(const boost::system::error_code& error, std::size_t bytes_transferred)
{
    if (error)
    {
        if (error != boost::asio::error::eof)
        {
            g_asio.socket->close();
        }
    }
    else
    {
        if (bytes_transferred > g_max_packet_size)
        {
            std::cout << "Packet too big: " << bytes_transferred << ". Clamping to max packet size: " << g_max_packet_size;
            bytes_transferred = g_max_packet_size;
        }

        std::cout << "DATAGRAM>>";
        std::copy(g_asio.rx_buffer.data(), g_asio.rx_buffer.data() + bytes_transferred, std::ostream_iterator<uint8_t>(std::cout));
        std::cout << "<<DATAGRAM";

        //copy to the pcap tx buffer
        {
            std::lock_guard<std::mutex> lg(g_pcap.tx_buffer_mutex);
            g_pcap.tx_buffer.resize(g_pcap.tx_packet_header_length + bytes_transferred);
            std::copy(g_asio.rx_buffer.data(), g_asio.rx_buffer.data() + bytes_transferred, g_pcap.tx_buffer.begin() + g_pcap.tx_packet_header_length);
            g_pcap.tx_data_available = true;
        }

        g_asio.socket->async_receive_from(boost::asio::buffer(g_asio.rx_buffer.data(), g_max_packet_size), g_asio.rx_endpoint, g_asio.rx_callback);
    }
}
static void asio_tx_callback(const boost::system::error_code& error, std::size_t bytes_transferred)
{
    assert(g_asio.tx_buffer_in_transit);

    //put it back in the pool
    if (g_asio.tx_buffer_in_transit)
    {
        std::lock_guard<std::mutex> lg(g_asio.tx_buffer_pool_mutex);
        g_asio.tx_buffer_pool.push_back(std::move(g_asio.tx_buffer_in_transit));
    }

    g_asio.tx_buffer_in_transit.reset();
}


static bool prepare_socket(uint16_t tx_port, uint16_t rx_port)
{
    g_asio.thread = boost::thread([&g_asio]()
    {
        while (!g_exit)
        {
            g_asio.io_service.run();
            g_asio.io_service.reset();
            boost::this_thread::sleep_for(boost::chrono::microseconds(500));
        }
    });

    g_asio.tx_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), tx_port);
    g_asio.rx_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), rx_port);

    g_asio.socket.reset(new boost::asio::ip::udp::socket(g_asio.io_service));
    g_asio.socket->open(boost::asio::ip::udp::v4());
    g_asio.socket->set_option(boost::asio::ip::udp::socket::reuse_address(true));
    g_asio.socket->bind(g_asio.rx_endpoint);


    g_asio.tx_callback = boost::bind(&asio_tx_callback, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred);
    g_asio.rx_callback = boost::bind(&asio_rx_callback, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred);

    g_asio.socket->async_receive_from(boost::asio::buffer(g_asio.rx_buffer.data(), g_max_packet_size), g_asio.rx_endpoint, g_asio.rx_callback);

    return true;
}

static void prepare_tx_packet_header()
{
    //prepare the buffers with headers
    g_pcap.tx_buffer.resize(sizeof(k_radiotap_header) + sizeof(k_ieee_header));
    uint8_t* pu8 = g_pcap.tx_buffer.data();

    memcpy(pu8, k_radiotap_header, sizeof(k_radiotap_header));
    pu8 += sizeof(k_radiotap_header);

    memcpy(pu8, k_ieee_header, sizeof (k_ieee_header));
    pu8 += sizeof (k_ieee_header);
}


static bool process_rx_packet()
{
    struct pcap_pkthdr* ppcapPacketHeader = nullptr;

    uint8_t payloadBuffer[MAX_PACKET_LENGTH];
    uint8_t* pu8Payload = payloadBuffer;


    int retval = pcap_next_ex(g_pcap.pcap, &ppcapPacketHeader, (const u_char**)&pu8Payload);
    if (retval < 0)
    {
        std::cout << "Socket broken: " << pcap_geterr(g_pcap.pcap) << "\n";
        return false;
    }
    if (retval != 1)
    {
        return true;
    }

    int u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));
    if (ppcapPacketHeader->len < (u16HeaderLen + g_pcap._80211_header_length))
    {
        return true;
    }

    int bytes = ppcapPacketHeader->len - (u16HeaderLen + g_pcap._80211_header_length);
    if (bytes < 0)
    {
        return true;
    }

    ieee80211_radiotap_iterator rti;
    if (ieee80211_radiotap_iterator_init(&rti, (struct ieee80211_radiotap_header *)pu8Payload, ppcapPacketHeader->len) < 0)
    {
        return true;
    }

    int n = 0;
    Penumbra_Radiotap_Header prh;
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
    pu8Payload += u16HeaderLen + g_pcap._80211_header_length;

    if (prh.radiotap_flags & IEEE80211_RADIOTAP_F_FCS)
    {
        bytes -= 4;
    }

    bool checksum_correct = (prh.radiotap_flags & 0x40) == 0;

//    block_num = seq_nr / param_retransmission_block_size;//if retr_block_size would be limited to powers of two, this could be replaced by a logical AND operation

    //printf("rec %x bytes %d crc %d\n", seq_nr, bytes, checksum_correct);

    ASIO::TX_Buffer buffer;
    {
        std::lock_guard<std::mutex> lg(g_asio.tx_buffer_pool_mutex);
        if (g_asio.tx_buffer_pool.empty())
        {
            buffer = std::make_shared<ASIO::TX_Buffer::element_type>();
        }
        else
        {
            buffer = std::move(g_asio.tx_buffer_pool.back());
            g_asio.tx_buffer_pool.pop_back();
        }
    }

    buffer->resize(bytes);
    std::copy(pu8Payload, pu8Payload + bytes, buffer->begin());
    {
        std::lock_guard<std::mutex> lg(g_asio.tx_buffer_queue_mutex);
        g_asio.tx_buffer_queue.push_back(std::move(buffer));
    }

    std::cout << "RX>>";
    std::copy(pu8Payload, pu8Payload + bytes, std::ostream_iterator<uint8_t>(std::cout));
    std::cout << "<<RX";

    return true;
}


int main(int argc, char const* argv[])
{
    namespace po = boost::program_options;

    po::options_description opt("Options");
    opt.add_options()
        ("help,h", "produce help message")
        ("interface,i", po::value<std::string>()->required(), "wlan interface in monitor mode")
        ("packet,p", po::value<size_t>(), "packet size");

    po::variables_map vm;
    try
    {
        po::store(po::command_line_parser(argc, argv).options(opt).run(), vm);
        po::notify(vm);
    }
    catch (...)
    {
        std::cout << "(c)2015 leflambeur. Based on befinitiv wifibroadcast.\n";
        std::cout << "Usage: " << argv[0] << " [options]\n";
        std::cout << opt << "\n";
    }

    if (vm.count("help"))
    {
        std::cout << "(c)2015 leflambeur. Based on befinitiv wifibroadcast.\n";
        std::cout << "Usage: " << argv[0] << " [options]\n";
        std::cout << opt << "\n";
        return 1;
    }

    std::string interface = vm["interface"].as<std::string>();
    g_max_packet_size = vm.count("packet") ? vm["packet"].as<size_t>() : MAX_USER_PACKET_LENGTH;
    if (g_max_packet_size > MAX_USER_PACKET_LENGTH)
    {
        std::cout << "Packet size is too big. Max is " << MAX_USER_PACKET_LENGTH << "\n";
        return 1;
    }

    std::cout << "Opening pcap on " << interface << "\n";

    char pcap_error[PCAP_ERRBUF_SIZE] = {0};
    g_pcap.pcap = pcap_open_live(interface.c_str(), 800, 1, -1, pcap_error);
    if (g_pcap.pcap == nullptr)
    {
        std::cout << "Unable to open interface " << interface << " in pcap: " << pcap_error << "\n";
        return (1);
    }

    std::cout << "Setting nonblocking pcap\n";
    if(pcap_setnonblock(g_pcap.pcap, 1, pcap_error) < 0)
    {
        std::cout << "Error setting " << interface << " to nonblocking mode: " << pcap_error << "\n";
        return 1;
    }

    if (!prepare_filter())
    {
        return 1;
    }

    if (!prepare_socket(8000, 8001))
    {
        return 1;
    }

    prepare_tx_packet_header();
    g_pcap.tx_packet_header_length = g_pcap.tx_buffer.size();

    std::cout << "Starting main loop\n";
    while (true)
    {
        if (g_pcap.tx_data_available)
        {
            std::lock_guard<std::mutex> lg(g_pcap.tx_buffer_mutex);
            if (g_pcap.tx_buffer.size() > g_pcap.tx_packet_header_length)
            {
//                std::cout << "TX>>";
//                std::copy(g_pcap.tx_buffer.begin(), g_pcap.tx_buffer.end(), std::ostream_iterator<uint8_t>(std::cout));
//                std::cout << "<<TX";

                int isize = static_cast<int>(g_pcap.tx_buffer.size());
                int r = pcap_inject(g_pcap.pcap, g_pcap.tx_buffer.data(), isize);
                if (r != isize)
                {
                    std::cout << "Trouble injecting packet: " << r << " / " << isize << " : " << pcap_geterr(g_pcap.pcap) << "\n";
                    return (1);
                }
                g_pcap.tx_buffer.resize(g_pcap.tx_packet_header_length);
                g_pcap.tx_data_available = false;
            }
        }


        {
            fd_set readset;
            struct timeval to;

            to.tv_sec = 0;
            to.tv_usec = 1e5;

            FD_ZERO(&readset);
            FD_SET(g_pcap.selectable_fd, &readset);

            int n = select(30, &readset, nullptr, nullptr, &to);
            if (n != 0)
            {
                if (FD_ISSET(g_pcap.selectable_fd, &readset))
                {
                    if (!process_rx_packet())
                    {
                        return 1;
                    }
                }
            }
        }

        if (!g_asio.tx_buffer_in_transit)
        {
            std::lock_guard<std::mutex> lg(g_asio.tx_buffer_queue_mutex);
            if (!g_asio.tx_buffer_queue.empty())
            {
                std::cout << "sending\n";
                g_asio.tx_buffer_in_transit = g_asio.tx_buffer_queue.front();
                g_asio.tx_buffer_queue.erase(g_asio.tx_buffer_queue.begin());
                g_asio.socket->async_send_to(boost::asio::buffer(*g_asio.tx_buffer_in_transit), g_asio.tx_endpoint, g_asio.tx_callback);
            }
        }
    }


    return 0;
}

