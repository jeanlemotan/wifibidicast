#include <array>
#include <algorithm>
//#include <iterator>
#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <deque>
#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/bind.hpp>
//#include <boost/thread.hpp>
#include <boost/program_options.hpp>

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
//#include <utime.h>
//#include <unistd.h>
//#include <getopt.h>
#include <pcap.h>
//#include <endian.h>
//#include <fcntl.h>


//#define DEBUG_PCAP
//#define DEBUG_ASIO
#define DEBUG_THROUGHPUT



static constexpr uint8_t MARKER_DATA = 0;
static constexpr uint8_t MARKER_ACK = 1;


extern "C"
{
#include "radiotap.h"
}


static constexpr uint16_t DEFAULT_PORT = 8000;

static constexpr size_t MAX_PACKET_SIZE = 4192;
static constexpr size_t MAX_USER_PACKET_SIZE = 1470;

static constexpr size_t DEFAULT_RATE_HZ = 26000000;

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

static size_t g_max_packet_size = MAX_USER_PACKET_SIZE;
static size_t g_rate_hz = DEFAULT_RATE_HZ;

static uint8_t g_local_id = 0;

static size_t g_tx_packet_header_length = 0;

static constexpr size_t MAX_INTERFACES = 32;
static size_t g_interface_count = 0;


typedef std::shared_ptr<std::vector<uint8_t>> Buffer;

struct PCAP
{
    std::mutex pcap_mutex;
    std::string interface;

    pcap_t* pcap = nullptr;
    int rx_selectable_fd = 0;

    std::array<uint8_t, MAX_PACKET_SIZE> tx_buffer;

    size_t _80211_header_length = 0;

    struct Stats
    {
        struct pcap_stat pcap;
        size_t rx_bytes = 0;
        size_t tx_bytes = 0;
        std::chrono::system_clock::time_point last_tp = std::chrono::system_clock::now();
    } stats;

} g_pcap[MAX_INTERFACES];



struct ASIO
{
    std::thread thread;

    boost::asio::io_service io_service;
    boost::asio::ip::udp::endpoint tx_endpoint;
    boost::asio::ip::udp::endpoint rx_endpoint;
    std::unique_ptr<boost::asio::ip::udp::socket> socket;

    std::array<uint8_t, MAX_USER_PACKET_SIZE> rx_buffer;

    std::mutex tx_buffer_mutex;
    std::vector<Buffer> tx_buffer_pool;
    std::deque<Buffer> tx_buffer_queue; //to send

    Buffer tx_buffer_in_transit;


    boost::function<void(const boost::system::error_code& error, std::size_t bytes_transferred)> tx_callback;
    boost::function<void(const boost::system::error_code& error, std::size_t bytes_transferred)> rx_callback;
} g_asio;


static bool prepare_filter(PCAP& pcap)
{
    struct bpf_program program;
    char program_src[512];

    int link_encap = pcap_datalink(pcap.pcap);

    switch (link_encap)
    {
    case DLT_PRISM_HEADER:
        std::cout << "DLT_PRISM_HEADER Encap\n";
        pcap._80211_header_length = 0x20; // ieee80211 comes after this
        sprintf(program_src, "radio[0x4a:4]==0x13223344 && radio[0x4e:2] != 0x55%.2x", g_local_id);
        break;

    case DLT_IEEE802_11_RADIO:
        std::cout << "DLT_IEEE802_11_RADIO Encap\n";
        pcap._80211_header_length = 0x18; // ieee80211 comes after this
        sprintf(program_src, "ether[0x0a:4]==0x13223344 && ether[0x0e:2] != 0x55%.2x", g_local_id);
        break;

    default:
        std::cout << "!!! unknown encapsulation\n";
        return false;
    }

    if (pcap_compile(pcap.pcap, &program, program_src, 1, 0) == -1)
    {
        std::cout << "Failed to compile program: " << program_src << ": " << pcap_geterr(pcap.pcap) << "\n";
        return false;
    }
    if (pcap_setfilter(pcap.pcap, &program) == -1)
    {
        pcap_freecode(&program);
        std::cout << "Failed to set program: " << program_src << ": " << pcap_geterr(pcap.pcap) << "\n";
        return false;
    }
    pcap_freecode(&program);

    pcap.rx_selectable_fd = pcap_get_selectable_fd(pcap.pcap);
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
    hdr.it_present = 0
                    | (1 << IEEE80211_RADIOTAP_RATE)
                    | (1 << IEEE80211_RADIOTAP_TX_FLAGS)
                    | (1 << IEEE80211_RADIOTAP_RTS_RETRIES)
                    | (1 << IEEE80211_RADIOTAP_DATA_RETRIES)
//                    | (1 << IEEE80211_RADIOTAP_MCS)
                    ;

    auto* dst = RADIOTAP_HEADER.data() + sizeof(ieee80211_radiotap_header);
    size_t idx = dst - RADIOTAP_HEADER.data();

    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_RATE))
    {
        radiotap_add_u8(dst, idx, std::min(static_cast<uint8_t>(rate_hz / 500000), uint8_t(1)));
    }
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_TX_FLAGS))
    {
        radiotap_add_u16(dst, idx, IEEE80211_RADIOTAP_F_TX_NOACK); //used to be 0x18
    }
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_RTS_RETRIES))
    {
        radiotap_add_u8(dst, idx, 0x0);
    }
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_DATA_RETRIES))
    {
        radiotap_add_u8(dst, idx, 0x0);
    }
    if (hdr.it_present & (1 << IEEE80211_RADIOTAP_MCS))
    {
        radiotap_add_u8(dst, idx, IEEE80211_RADIOTAP_MCS_HAVE_MCS);
        radiotap_add_u8(dst, idx, 0);
        radiotap_add_u8(dst, idx, 18);
    }

    //finish it
    hdr.it_len = static_cast<__le16>(idx);
    RADIOTAP_HEADER.resize(idx);


//    RADIOTAP_HEADER.resize(sizeof(RADIOTAP_HEADER_original));
//    memcpy(RADIOTAP_HEADER.data(), RADIOTAP_HEADER_original, sizeof(RADIOTAP_HEADER_original));
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

static void update_stats(PCAP& pcap, size_t rx_bytes, size_t tx_bytes)
{
#ifdef DEBUG_THROUGHPUT
    struct pcap_stat stats;
    pcap_stats(pcap.pcap, &stats);

    pcap.stats.pcap.ps_drop += stats.ps_drop;
    pcap.stats.pcap.ps_ifdrop += stats.ps_ifdrop;
    pcap.stats.pcap.ps_recv += stats.ps_recv;

    pcap.stats.rx_bytes += rx_bytes;
    pcap.stats.tx_bytes += tx_bytes;
    auto now = std::chrono::system_clock::now();
    if (now - pcap.stats.last_tp >= std::chrono::seconds(1))
    {
        float r = std::chrono::duration<float>(now - pcap.stats.last_tp).count();
        size_t rx_kb = size_t(float(pcap.stats.rx_bytes)/r/1024.f);
        size_t tx_kb = size_t(float(pcap.stats.tx_bytes)/r/1024.f);

        std::cout << pcap.interface << "> TX: " << tx_kb << " KB/s, RX: " << rx_kb << "KB/s" <<
                     " Drop: " << pcap.stats.pcap.ps_drop << " IFDrop: " << pcap.stats.pcap.ps_ifdrop << " RECV: " << pcap.stats.pcap.ps_recv << "\n";
        pcap.stats.tx_bytes -= tx_kb * 1024;
        pcap.stats.rx_bytes -= rx_kb * 1024;
        pcap.stats.last_tp = now;

        pcap.stats.pcap.ps_drop = 0;
        pcap.stats.pcap.ps_ifdrop = 0;
        pcap.stats.pcap.ps_recv = 0;
    }
#endif
}

static void send_asio_packet_locked();

static void send_ack()
{
    std::lock_guard<std::mutex> lg(g_asio.tx_buffer_mutex);
    Buffer buffer;
    if (g_asio.tx_buffer_pool.empty())
    {
        buffer = std::make_shared<Buffer::element_type>(1);
    }
    else
    {
        buffer = std::move(g_asio.tx_buffer_pool.back());
        g_asio.tx_buffer_pool.pop_back();
        buffer->resize(1);
    }

    buffer->front() = MARKER_ACK;
    g_asio.tx_buffer_queue.push_back(std::move(buffer));

    send_asio_packet_locked();
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
        if (bytes_transferred > 0)
        {
            if (g_asio.rx_buffer[0] == MARKER_DATA)
            {
                uint8_t* rx_buffer_ptr = g_asio.rx_buffer.data() + 1;
                bytes_transferred--;

                if (bytes_transferred > g_max_packet_size)
                {
                    std::cout << "Packet too big: " << bytes_transferred << ". Clamping to max packet size: " << g_max_packet_size;
                    bytes_transferred = g_max_packet_size;
                }

#ifdef DEBUG_ASIO
                std::cout << "ASIO RX>>";
                std::copy(rx_buffer_ptr, rx_buffer_ptr + bytes_transferred, std::ostream_iterator<uint8_t>(std::cout));
                std::cout << "<<ASIO RX";
#endif

                {
                    std::lock_guard<std::mutex> lg(g_pcap[0].pcap_mutex);
                    std::copy(rx_buffer_ptr, rx_buffer_ptr + bytes_transferred, g_pcap[0].tx_buffer.data() + g_tx_packet_header_length);
                    int isize = static_cast<int>(g_tx_packet_header_length + bytes_transferred);
                    int r = 0;
                    do
                    {
                        r = pcap_inject(g_pcap[0].pcap, g_pcap[0].tx_buffer.data(), isize);
                    } while (r < 0 && (errno == EWOULDBLOCK || errno == EAGAIN));

                    if (r <= 0)
                    {
                        std::cout << "Trouble injecting packet: " << r << " / " << isize << " : " << pcap_geterr(g_pcap[0].pcap) << "\n";
                    }

                    if (r > 0 && r != isize)
                    {
                        std::cout << "Incomplete packet sent: " << r << " / " << isize << "\n";
                    }
                }

                update_stats(g_pcap[0], 0, bytes_transferred);


                send_ack();
            }
        }

        g_asio.socket->async_receive_from(
                    boost::asio::buffer(g_asio.rx_buffer),
                    g_asio.rx_endpoint, g_asio.rx_callback);
    }
}


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
    if (!g_asio.tx_buffer_queue.empty() && !g_asio.tx_buffer_in_transit)
    {
        //std::cout << "sending\n";
        g_asio.tx_buffer_in_transit = std::move(g_asio.tx_buffer_queue.front());

#ifdef DEBUG_ASIO
        std::cout << "ASIO TX>>";
        std::copy(g_asio.tx_buffer_in_transit->begin(), g_asio.tx_buffer_in_transit->end(), std::ostream_iterator<uint8_t>(std::cout));
        std::cout << "<<ASIO TX";
#endif

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
    g_asio.thread = std::thread([&g_asio]()
    {
        while (!g_exit)
        {
            g_asio.io_service.run();
            g_asio.io_service.reset();
        }
    });

    g_asio.tx_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), tx_port);
    g_asio.rx_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), rx_port);

    g_asio.socket.reset(new boost::asio::ip::udp::socket(g_asio.io_service));
    g_asio.socket->open(boost::asio::ip::udp::v4());
    g_asio.socket->set_option(boost::asio::ip::udp::socket::reuse_address(true));
    g_asio.socket->set_option(boost::asio::socket_base::receive_buffer_size(MAX_USER_PACKET_SIZE + 200));
    g_asio.socket->set_option(boost::asio::socket_base::send_buffer_size(MAX_USER_PACKET_SIZE + 200));
    g_asio.socket->bind(g_asio.rx_endpoint);



    g_asio.tx_callback = boost::bind(&asio_tx_callback, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred);
    g_asio.rx_callback = boost::bind(&asio_rx_callback, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred);

    g_asio.socket->async_receive_from(
                boost::asio::buffer(g_asio.rx_buffer),
                g_asio.rx_endpoint, g_asio.rx_callback);

    return true;
}


static bool process_rx_packet(PCAP& pcap)
{
    struct pcap_pkthdr* pcap_packet_header = nullptr;

    uint8_t payload_buffer[MAX_PACKET_SIZE];
    uint8_t* payload = payload_buffer;

    while (true)
    {
        {
            std::lock_guard<std::mutex> lg(pcap.pcap_mutex);
            int retval = pcap_next_ex(pcap.pcap, &pcap_packet_header, (const u_char**)&payload);
            if (retval < 0)
            {
                std::cout << "Socket broken: " << pcap_geterr(pcap.pcap) << "\n";
                return false;
            }
            if (retval != 1)
            {
                //no more packets
                break;
            }
        }

        size_t header_len = (payload[2] + (payload[3] << 8));
        if (pcap_packet_header->len < (header_len + pcap._80211_header_length))
        {
            std::cout << "packet too small\n";
            return true;
        }

        size_t bytes = pcap_packet_header->len - (header_len + pcap._80211_header_length);

        ieee80211_radiotap_iterator rti;
        if (ieee80211_radiotap_iterator_init(&rti, (struct ieee80211_radiotap_header *)payload, pcap_packet_header->len) < 0)
        {
            std::cout << "iterator null\n";
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
        payload += header_len + pcap._80211_header_length;

        if (prh.radiotap_flags & IEEE80211_RADIOTAP_F_FCS)
        {
            bytes -= 4;
        }

        bool checksum_correct = (prh.radiotap_flags & 0x40) == 0;

        //    block_num = seq_nr / param_retransmission_block_size;//if retr_block_size would be limited to powers of two, this could be replaced by a logical AND operation

        //printf("rec %x bytes %d crc %d\n", seq_nr, bytes, checksum_correct);

#ifdef DEBUG_PCAP
        std::cout << "PCAP RX " << pcap.interface << ">>";
        std::copy(payload, payload + bytes, std::ostream_iterator<uint8_t>(std::cout));
        std::cout << "<<PCAP RX";
#endif

        {
            std::lock_guard<std::mutex> lg(g_asio.tx_buffer_mutex);
            Buffer buffer;
            if (g_asio.tx_buffer_pool.empty())
            {
                buffer = std::make_shared<Buffer::element_type>(bytes + 1);
            }
            else
            {
                buffer = std::move(g_asio.tx_buffer_pool.back());
                g_asio.tx_buffer_pool.pop_back();
                buffer->resize(bytes + 1);
            }

            buffer->front() = MARKER_DATA;
            std::copy(payload, payload + bytes, buffer->begin() + 1);
            g_asio.tx_buffer_queue.push_back(std::move(buffer));

            send_asio_packet_locked();
        }

        update_stats(pcap, bytes, 0);
    }

    return true;
}

// Define the function to be called when ctrl-c (SIGINT) signal is sent to process
static void signal_handler(int signum)
{
    if (g_exit)
    {
        std::cout << "Forcing an exit due to signal " << signum;
        abort();
    }
    g_exit = true;
    std::cout << "Exitting due to signal " << signum;
}


int main(int argc, char const* argv[])
{
    signal(SIGINT, signal_handler); // Trap basic signals (exit cleanly)
    signal(SIGKILL, signal_handler);
    signal(SIGUSR1, signal_handler);
//    signal(SIGQUIT, signal_handler);
//    signal(SIGABRT, signal_handler);
//    signal(SIGSTOP, signal_handler);

    namespace po = boost::program_options;

    po::options_description opt("Options");
    opt.add_options()
        ("help,h", "produce help message")
        ("interface,i", po::value<std::vector<std::string>>()->multitoken()->required(), "wlan interface in monitor mode. Use several for diversity. First one is used for transmitting.")
        ("packet,p", po::value<size_t>()->default_value(MAX_USER_PACKET_SIZE), "packet size")
        ("id", po::value<uint8_t>()->required(), "local station id")
        ("port", po::value<uint16_t>()->default_value(DEFAULT_PORT), "port to read data received from rfcom. Use port+1 to send data");

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

    g_max_packet_size = vm["packet"].empty() ? MAX_USER_PACKET_SIZE : vm["packet"].as<size_t>();
    if (g_max_packet_size > MAX_USER_PACKET_SIZE)
    {
        std::cout << "Packet size is too big. Max is " << MAX_USER_PACKET_SIZE << "\n";
        return 1;
    }

    g_local_id = vm["id"].as<uint8_t>();

    uint16_t rx_port = vm["port"].empty() ? DEFAULT_PORT : vm["port"].as<uint16_t>();
    uint16_t tx_port = rx_port + 1;

    std::cout << "\n\nLocal id: " << g_local_id << "\n";
    std::cout << "Max packet size: " << g_max_packet_size << "\n";
    std::cout << "RX Port: " << rx_port << " TX Port: " << tx_port << "\n";

    IEEE_HEADER[SRC_MAC_LASTBYTE] = g_local_id;
    IEEE_HEADER[DST_MAC_LASTBYTE] = g_local_id;

    prepare_radiotap_header(g_rate_hz);



    char pcap_error[PCAP_ERRBUF_SIZE] = {0};

    std::vector<std::string> interfaces = vm["interface"].as<std::vector<std::string>>();
    for (const auto& interface: interfaces)
    {
        PCAP& pcap = g_pcap[g_interface_count++];
        pcap.interface = interface;

        std::cout << "\n\nInterface: " << interface << ", Local id: " << g_local_id << "\n";

        pcap.pcap = pcap_create(interface.c_str(), pcap_error);
        if (pcap.pcap == nullptr)
        {
            std::cout << "Unable to open interface " << interface << " in pcap: " << pcap_error << "\n";
            return (1);
        }
        if (pcap_set_snaplen(pcap.pcap, 1800) < 0)
        {
            std::cout << "Error setting " << interface << " pcap_set_snaplen\n";
            return 1;
        }
        if (pcap_set_promisc(pcap.pcap, 1) < 0)
        {
            std::cout << "Error setting " << interface << " pcap_set_promisc\n";
            return 1;
        }
        if (pcap_set_rfmon(pcap.pcap, 1) < 0)
        {
            std::cout << "Error setting " << interface << " pcap_set_rfmon\n";
            return 1;
        }
        if (pcap_set_timeout(pcap.pcap, -1) < 0)
        {
            std::cout << "Error setting " << interface << " pcap_set_timeout\n";
            return 1;
        }
        if (pcap_set_immediate_mode(pcap.pcap, 0) < 0)
        {
            std::cout << "Error setting " << interface << " pcap_set_immediate_mode\n";
            return 1;
        }
        if (pcap_set_buffer_size(pcap.pcap, 16000000) < 0)
        {
            std::cout << "Error setting " << interface << " pcap_set_buffer_size\n";
            return 1;
        }
        if (pcap_activate(pcap.pcap) < 0)
        {
            std::cout << "Error setting " << interface << " pcap_activate\n";
            return 1;
        }
        if (pcap_setnonblock(pcap.pcap, 1, pcap_error) < 0)
        {
            std::cout << "Error setting " << interface << " to nonblocking mode: " << pcap_error << "\n";
            return 1;
        }
        if (pcap_setdirection(pcap.pcap, PCAP_D_IN) < 0)
        {
            std::cout << "Error setting " << interface << " capture direction: " << pcap_geterr(pcap.pcap);
            return 1;
        }

        prepare_tx_packet_header(pcap.tx_buffer.data());

        if (!prepare_filter(pcap))
        {
            return 1;
        }
    }

    g_tx_packet_header_length = RADIOTAP_HEADER.size() + sizeof(IEEE_HEADER);
    std::cout << "Radiocap header size: " << RADIOTAP_HEADER.size() << ", IEEE header size: " << sizeof(IEEE_HEADER) << "\n";

    //asio data will be received directly in the pcap tx buffer, just after the headers. This avoids a memcpy
    //g_asio.rx_buffer_ptr = g_pcap[0].tx_buffer.data() + g_tx_packet_header_length;


    if (!prepare_socket(rx_port, tx_port))
    {
        return 1;
    }

    std::cout << "Starting main loop\n";
    while (!g_exit)
    {
        fd_set readset;
        struct timeval to;

        to.tv_sec = 0;
        to.tv_usec = 1e3;

        FD_ZERO(&readset);
        for (size_t i = 0; i < g_interface_count; ++i)
        {
            FD_SET(g_pcap[i].rx_selectable_fd, &readset);
        }

        int n = select(30, &readset, NULL, NULL, &to);
        for (size_t i = 0; i < g_interface_count; ++i)
        {
            if (n == 0)
            {
                break;
            }

            if (FD_ISSET(g_pcap[i].rx_selectable_fd, &readset))
            {
                process_rx_packet(g_pcap[i]);
            }
        }
    }

    g_asio.io_service.stop();

    if (g_asio.thread.joinable())
    {
        g_asio.thread.join();
    }

    return 0;
}

