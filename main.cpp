#include <array>
#include <algorithm>
#include <iterator>
#include <iostream>
#include <mutex>
#include <vector>
#include <deque>
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
#include "radiotap.h"
}


static constexpr uint16_t DEFAULT_RX_PORT = 8000;
static constexpr uint16_t DEFAULT_TX_PORT = 8001;

static constexpr size_t MAX_PACKET_SIZE = 4192;
static constexpr size_t MAX_USER_PACKET_SIZE = 1470;

static constexpr size_t DEFAULT_RATE_HZ = 11000000;

// this is the template radiotap header we send packets out with
static constexpr uint8_t RADIOTAP_HEADER_original[] =
{

    0x00, //version
    0x00, //pad
    0x0c, 0x00, // <- radiotap header lengt
    0x04, 0x80, 0x00, 0x00, // <-- bitmap (RATE + TX FLAGS)
    0x22, //rate
    0x0,//padding
    0x18, 0x00
};

std::vector<uint8_t> RADIOTAP_HEADER;

#define SRC_MAC_LASTBYTE 15
#define DST_MAC_LASTBYTE 21

// Penumbra IEEE80211 header
static uint8_t IEEE_HEADER[] =
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
static bool g_loopback = false;

static size_t g_max_packet_size = MAX_USER_PACKET_SIZE;
static size_t g_rate_hz = DEFAULT_RATE_HZ;
static uint8_t g_station_id = 0;

typedef std::shared_ptr<std::vector<uint8_t>> Buffer;

struct PCAP
{
    std::mutex pcap_mutex;

    pcap_t* pcap = nullptr;
    int rx_pcap_selectable_fd = 0;

    size_t _80211_header_length = 0;
    size_t tx_packet_header_length = 0;

    std::array<uint8_t, MAX_PACKET_SIZE> loopback_buffer;
} g_pcap;

struct ASIO
{
    boost::thread thread;

    boost::asio::io_service io_service;
    boost::asio::ip::udp::endpoint tx_endpoint;
    boost::asio::ip::udp::endpoint rx_endpoint;
    std::unique_ptr<boost::asio::ip::udp::socket> socket;
    std::array<uint8_t, MAX_PACKET_SIZE> rx_buffer;

    std::mutex tx_buffer_mutex;
    std::vector<Buffer> tx_buffer_pool;
    std::deque<Buffer> tx_buffer_queue; //to send

    Buffer tx_buffer_in_transit;


    boost::function<void(const boost::system::error_code& error, std::size_t bytes_transferred)> tx_callback;
    boost::function<void(const boost::system::error_code& error, std::size_t bytes_transferred)> rx_callback;
} g_asio;


static bool prepare_filter()
{
    struct bpf_program program;
    char program_src[512];

    int link_encap = pcap_datalink(g_pcap.pcap);

    switch (link_encap)
    {
    case DLT_PRISM_HEADER:
        std::cout << "DLT_PRISM_HEADER Encap\n";
        g_pcap._80211_header_length = 0x20; // ieee80211 comes after this
        sprintf(program_src, "radio[0x4a:4]==0x13223344 && radio[0x4e:2] != 0x55%.2x", g_station_id);
        break;

    case DLT_IEEE802_11_RADIO:
        std::cout << "DLT_IEEE802_11_RADIO Encap\n";
        g_pcap._80211_header_length = 0x18; // ieee80211 comes after this
        sprintf(program_src, "ether[0x0a:4]==0x13223344 && ether[0x0e:2] != 0x55%.2x", g_station_id);
        break;

    default:
        std::cout << "!!! unknown encapsulation\n";
        return false;
    }

    if (pcap_compile(g_pcap.pcap, &program, program_src, 1, 0) == -1)
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

    g_pcap.rx_pcap_selectable_fd = pcap_get_selectable_fd(g_pcap.pcap);
    return true;
}


static void radiotap_add_u8(uint8_t*& dst, size_t& idx, uint8_t data)
{
    *dst++ = data;
    idx++;
}
static void radiotap_add_u16(uint8_t*& dst, size_t& idx, uint16_t data)
{
    if ((idx & 1) == 1) //not aligned, pad first
    {
        radiotap_add_u8(dst, idx, 0);
    }
    *reinterpret_cast<uint16_t*>(dst) = data;
    dst += 2;
    idx += 2;
}

static void prepare_radiotap_header(size_t rate_hz)
{
    RADIOTAP_HEADER.resize(1024);
    ieee80211_radiotap_header& hdr = reinterpret_cast<ieee80211_radiotap_header&>(*RADIOTAP_HEADER.data());
    hdr.it_version = 0;
    hdr.it_present = (1 << IEEE80211_RADIOTAP_RATE)
                    | (1 << IEEE80211_RADIOTAP_TX_FLAGS)
                    | (1 << IEEE80211_RADIOTAP_RTS_RETRIES)
                    | (1 << IEEE80211_RADIOTAP_DATA_RETRIES);

    auto* dst = RADIOTAP_HEADER.data() + sizeof(ieee80211_radiotap_header);
    size_t idx = dst - RADIOTAP_HEADER.data();

    //IEEE80211_RADIOTAP_RATE
    radiotap_add_u8(dst, idx, std::min(static_cast<uint8_t>(rate_hz / 500000), uint8_t(1)));
    //IEEE80211_RADIOTAP_TX_FLAGS
    radiotap_add_u16(dst, idx, 0x18);
    //IEEE80211_RADIOTAP_RTS_RETRIES
    radiotap_add_u8(dst, idx, 0x0);
    //IEEE80211_RADIOTAP_DATA_RETRIES
    radiotap_add_u8(dst, idx, 0x0);

    //finish it
    hdr.it_len = static_cast<__le16>(idx);
    RADIOTAP_HEADER.resize(idx);
}

static void prepare_tx_packet_header(uint8_t* buffer)
{
    //prepare the buffers with headers
    uint8_t* pu8 = buffer;

    memcpy(pu8, RADIOTAP_HEADER.data(), RADIOTAP_HEADER.size());
    pu8 += RADIOTAP_HEADER.size();

    memcpy(pu8, IEEE_HEADER, sizeof (IEEE_HEADER));
    pu8 += sizeof (IEEE_HEADER);
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

//        std::cout << "DATAGRAM>>";
//        std::copy(g_asio.rx_buffer.data() + g_pcap.tx_packet_header_length,
//                  g_asio.rx_buffer.data() + g_pcap.tx_packet_header_length + bytes_transferred, std::ostream_iterator<uint8_t>(std::cout));
//        std::cout << "<<DATAGRAM";

        std::lock_guard<std::mutex> lg(g_pcap.pcap_mutex);
        int isize = static_cast<int>(g_pcap.tx_packet_header_length + bytes_transferred);
        int r = pcap_inject(g_pcap.pcap, g_asio.rx_buffer.data(), isize);
        if (r <= 0)
        {
            std::cout << "Trouble injecting packet: " << r << " / " << isize << " : " << pcap_geterr(g_pcap.pcap) << "\n";
        }

        if (r > 0 && r != isize)
        {
            std::cout << "Incomplete packet sent: " << r << " / " << isize << "\n";
        }

        static int xxx_data = 0;
        static std::chrono::system_clock::time_point xxx_last_tp = std::chrono::system_clock::now();
        xxx_data += bytes_transferred;
        auto now = std::chrono::system_clock::now();
        if (now - xxx_last_tp >= std::chrono::seconds(1))
        {
            float r = std::chrono::duration<float>(now - xxx_last_tp).count();
            std::cout << "Sent: " << float(xxx_data)/r/1024.f << " KB/s\n";
            xxx_data = 0;
            xxx_last_tp = now;
        }

        g_asio.socket->async_receive_from(
                    boost::asio::buffer(g_asio.rx_buffer.data() + g_pcap.tx_packet_header_length, g_max_packet_size),
                    g_asio.rx_endpoint, g_asio.rx_callback);
    }
}
static void send_asio_packet_locked();

static void asio_tx_callback(const boost::system::error_code& error, std::size_t bytes_transferred)
{
    //put it back in the pool
    if (g_asio.tx_buffer_in_transit)
    {
        std::lock_guard<std::mutex> lg(g_asio.tx_buffer_mutex);
        g_asio.tx_buffer_pool.push_back(std::move(g_asio.tx_buffer_in_transit));

        g_asio.tx_buffer_in_transit.reset();

        //send the next one
        send_asio_packet_locked();
    }
}

static void send_asio_packet_locked()
{
    if (!g_asio.tx_buffer_queue.empty())
    {
        //std::cout << "sending\n";
        g_asio.tx_buffer_in_transit = std::move(g_asio.tx_buffer_queue.front());
        g_asio.tx_buffer_queue.pop_front();
        g_asio.socket->async_send_to(boost::asio::buffer(*g_asio.tx_buffer_in_transit), g_asio.tx_endpoint, g_asio.tx_callback);
    }
}

static void send_asio_packet()
{
    if (!g_asio.tx_buffer_in_transit)
    {
        std::lock_guard<std::mutex> lg(g_asio.tx_buffer_mutex);
        send_asio_packet_locked();
    }
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

    g_asio.socket->async_receive_from(
                boost::asio::buffer(g_asio.rx_buffer.data() + g_pcap.tx_packet_header_length, g_max_packet_size),
                g_asio.rx_endpoint, g_asio.rx_callback);

    return true;
}


static bool process_rx_packet()
{
    struct pcap_pkthdr* pcap_packet_header = nullptr;

    uint8_t payload_buffer[MAX_PACKET_SIZE];
    uint8_t* payload = payload_buffer;

    std::lock_guard<std::mutex> lg(g_pcap.pcap_mutex);

    int retval = pcap_next_ex(g_pcap.pcap, &pcap_packet_header, (const u_char**)&payload);
    if (retval < 0)
    {
        std::cout << "Socket broken: " << pcap_geterr(g_pcap.pcap) << "\n";
        return false;
    }
    if (retval != 1)
    {
        return true;
    }

    int header_len = (payload[2] + (payload[3] << 8));
    if (pcap_packet_header->len < (header_len + g_pcap._80211_header_length))
    {
        return true;
    }

    int bytes = pcap_packet_header->len - (header_len + g_pcap._80211_header_length);
    if (bytes < 0)
    {
        return true;
    }

    ieee80211_radiotap_iterator rti;
    if (ieee80211_radiotap_iterator_init(&rti, (struct ieee80211_radiotap_header *)payload, pcap_packet_header->len) < 0)
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
    payload += header_len + g_pcap._80211_header_length;

    if (prh.radiotap_flags & IEEE80211_RADIOTAP_F_FCS)
    {
        bytes -= 4;
    }

    bool checksum_correct = (prh.radiotap_flags & 0x40) == 0;

//    block_num = seq_nr / param_retransmission_block_size;//if retr_block_size would be limited to powers of two, this could be replaced by a logical AND operation

    //printf("rec %x bytes %d crc %d\n", seq_nr, bytes, checksum_correct);

    {
        std::lock_guard<std::mutex> lg(g_asio.tx_buffer_mutex);
        Buffer buffer;
        if (g_asio.tx_buffer_pool.empty())
        {
            buffer = std::make_shared<Buffer::element_type>(bytes);
        }
        else
        {
            buffer = std::move(g_asio.tx_buffer_pool.back());
            g_asio.tx_buffer_pool.pop_back();
            buffer->resize(bytes);
        }

        std::copy(payload, payload + bytes, buffer->begin());
        g_asio.tx_buffer_queue.push_back(std::move(buffer));

        send_asio_packet_locked();
    }

    if (g_loopback)
    {
        std::lock_guard<std::mutex> lg(g_pcap.pcap_mutex);
        std::copy(payload, payload + bytes, g_pcap.loopback_buffer.data() + g_pcap.tx_packet_header_length);
        int isize = static_cast<int>(g_pcap.tx_packet_header_length + bytes);
        int r = pcap_inject(g_pcap.pcap, g_pcap.loopback_buffer.data(), isize);
        if (r <= 0)
        {
            std::cout << "Trouble injecting packet: " << r << " / " << isize << " : " << pcap_geterr(g_pcap.pcap) << "\n";
        }
        if (r > 0 && r != isize)
        {
            std::cout << "Incomplete packet sent: " << r << " / " << isize << "\n";
        }
    }

//    std::cout << "RX>>";
//    std::copy(payload, payload + bytes, std::ostream_iterator<uint8_t>(std::cout));
//    std::cout << "<<RX";

    static int xxx_data = 0;
    static std::chrono::system_clock::time_point xxx_last_tp = std::chrono::system_clock::now();
    xxx_data += bytes;
    auto now = std::chrono::system_clock::now();
    if (now - xxx_last_tp >= std::chrono::seconds(1))
    {
        float r = std::chrono::duration<float>(now - xxx_last_tp).count();
        std::cout << "Received: " << float(xxx_data)/r/1024.f << " KB/s\n";
        xxx_data = 0;
        xxx_last_tp = now;
    }

    return true;
}


int main(int argc, char const* argv[])
{
    namespace po = boost::program_options;

    po::options_description opt("Options");
    opt.add_options()
        ("help,h", "produce help message")
        ("interface,i", po::value<std::string>()->required(), "wlan interface in monitor mode")
        ("packet,p", po::value<size_t>()->default_value(MAX_USER_PACKET_SIZE), "packet size")
        ("id", po::value<uint8_t>()->required(), "station id")
        ("rxport", po::value<uint16_t>()->default_value(DEFAULT_RX_PORT), "port to read data received from rfcom")
        ("txport", po::value<uint16_t>()->default_value(DEFAULT_TX_PORT), "port to write data to send through rfcom")
        ("loopback", po::value<bool>(), "relay all packets back");

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
        return 0;
    }

    if (vm.count("help"))
    {
        std::cout << "(c)2015 leflambeur. Based on befinitiv wifibroadcast.\n";
        std::cout << "Usage: " << argv[0] << " [options]\n";
        std::cout << opt << "\n";
        return 0;
    }

    std::string interface = vm["interface"].as<std::string>();
    g_max_packet_size = vm["packet"].empty() ? MAX_USER_PACKET_SIZE : vm["packet"].as<size_t>();
    if (g_max_packet_size > MAX_USER_PACKET_SIZE)
    {
        std::cout << "Packet size is too big. Max is " << MAX_USER_PACKET_SIZE << "\n";
        return 1;
    }

    g_station_id = vm["id"].as<uint8_t>();
    g_loopback = vm["loopback"].empty() ? false : vm["loopback"].as<bool>();

    uint16_t rx_port = vm["rxport"].empty() ? DEFAULT_RX_PORT : vm["rxport"].as<uint16_t>();
    uint16_t tx_port = vm["txport"].empty() ? DEFAULT_TX_PORT : vm["txport"].as<uint16_t>();

    std::cout << "\n\nInterface: " << interface << ", id: " << g_station_id << "\n";
    std::cout << "Max packet size: " << g_max_packet_size << "\n";
    std::cout << "RX Port: " << rx_port << " TX Port: " << tx_port << "\n";
    std::cout << "Loopback data: " << g_loopback << "\n";

    IEEE_HEADER[SRC_MAC_LASTBYTE] = g_station_id;
    IEEE_HEADER[DST_MAC_LASTBYTE] = g_station_id;

    char pcap_error[PCAP_ERRBUF_SIZE] = {0};

    g_pcap.pcap = pcap_open_live(interface.c_str(), 2048, 1, -1, pcap_error);
    if (g_pcap.pcap == nullptr)
    {
        std::cout << "Unable to open interface " << interface << " in pcap: " << pcap_error << "\n";
        return (1);
    }

//    std::cout << "Setting nonblocking pcap\n";
//    if(pcap_setnonblock(g_pcap.rx_pcap, 1, pcap_error) < 0)
//    {
//        std::cout << "Error setting " << interface << " to nonblocking mode: " << pcap_error << "\n";
//        return 1;
//    }

    prepare_radiotap_header(g_rate_hz);

    prepare_tx_packet_header(g_pcap.loopback_buffer.data());
    prepare_tx_packet_header(g_asio.rx_buffer.data());
    g_pcap.tx_packet_header_length = RADIOTAP_HEADER.size() + sizeof(IEEE_HEADER);

    if (!prepare_filter())
    {
        return 1;
    }

    if (!prepare_socket(rx_port, tx_port))
    {
        return 1;
    }

    std::cout << "Starting main loop\n";
    while (true)
    {
        fd_set readset;
        struct timeval to;

        to.tv_sec = 0;
        to.tv_usec = 1e3;

        FD_ZERO(&readset);
        FD_SET(g_pcap.rx_pcap_selectable_fd, &readset);

        int n = select(30, &readset, nullptr, nullptr, &to);
        if (n != 0)
        {
            if (FD_ISSET(g_pcap.rx_pcap_selectable_fd, &readset))
            {
                if (!process_rx_packet())
                {
                    return 1;
                }
            }
        }



//        {
//            std::lock_guard<std::mutex> lg(g_pcap.pcap_mutex);
//            size_t bytes_transferred = g_max_packet_size;
//            int isize = static_cast<int>(g_pcap.tx_packet_header_length + bytes_transferred);
//            int r = pcap_inject(g_pcap.pcap, g_asio.rx_buffer.data(), isize);
//            if (r <= 0)
//            {
//                std::cout << "Trouble injecting packet: " << r << " / " << isize << " : " << pcap_geterr(g_pcap.pcap) << "\n";
//            }

//            if (r > 0 && r != isize)
//            {
//                std::cout << "Incomplete packet sent: " << r << " / " << isize << "\n";
//            }

//            static int xxx_sent = 0, xxx_step = 0;
//            xxx_sent += bytes_transferred;
//            if (((xxx_step++) & 31) == 0)
//            {
//                std::cout << "Sent: " << xxx_sent << std::endl;
//            }
//        }
    }


    return 0;
}

