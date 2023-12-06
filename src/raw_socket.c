#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/filter.h>

// filter action frame packets
// Equivalent for tcp dump :
// type 0 subtype 0xd0 and wlan[24:4]=0x7f18fe34 and wlan[32]=221 and wlan[33:4]&0xffffff = 0x18fe34 and wlan[37]=0x4
// NB : There is no filter on source or destination addresses, so this code will 'receive' the action frames sent by this computer...
#define FILTER_LENGTH 20
static struct sock_filter bpfcode[FILTER_LENGTH] = {
    {0x30, 0, 0, 0x00000003},  // ldb [3]      // radiotap header length : MS byte
    {0x64, 0, 0, 0x00000008},  // lsh #8       // left shift it
    {0x7, 0, 0, 0x00000000},   // tax          // 'store' it in X register
    {0x30, 0, 0, 0x00000002},  // ldb [2]      // radiotap header length : LS byte
    {0x4c, 0, 0, 0x00000000},  // or  x        // combine A & X to get radiotap header length in A
    {0x7, 0, 0, 0x00000000},   // tax          // 'store' it in X
    {0x50, 0, 0, 0x00000000},  // ldb [x + 0]          // right after radiotap header is the type and subtype
    {0x54, 0, 0, 0x000000fc},  // and #0xfc            // mask the interesting bits, a.k.a 0b1111 1100
    {0x15, 0, 10, 0x000000d0}, // jeq #0xd0 jt 9 jf 19 // compare the types (0) and subtypes (0xd)
    {0x40, 0, 0, 0x00000018},  // Ld  [x + 24]                 // 24 bytes after radiotap header is the end of MAC header, so it is category and OUI (for action frame layer)
    {0x15, 0, 8, 0x7f18fe34},  // jeq #0x7f18fe34 jt 11 jf 19  // Compare with category = 127 (Vendor specific) and OUI 18:fe:34
    {0x50, 0, 0, 0x00000020},  // ldb [x + 32]                         // Begining of Vendor specific content + 4 ?random? bytes : element id
    {0x15, 0, 6, 0x000000dd},  // jeq #0xdd jt 13 jf 19                // element id should be 221 (according to the doc)
    {0x40, 0, 0, 0x00000021},  // Ld  [x + 33]                         // OUI (again!) on 3 LS bytes
    {0x54, 0, 0, 0x00ffffff},  // and #0xffffff                        // Mask the 3 LS bytes
    {0x15, 0, 3, 0x0018fe34},  // jeq #0x18fe34 jt 16 jf 19            // Compare with OUI 18:fe:34
    {0x50, 0, 0, 0x00000025},  // ldb [x + 37]                         // Type
    {0x15, 0, 1, 0x00000004},  // jeq #0x4 jt 18 jf 19                 // Compare type with type 0x4 (corresponding to ESP_NOW)
    {0x6, 0, 0, 0x00040000},   // ret #262144  // return 'True'
    {0x6, 0, 0, 0x00000000},   // ret #0       // return 'False'
};
static struct sock_fprog bpf = {FILTER_LENGTH, bpfcode};

static int create_raw_socket_send(const char *dev)
{
    struct sockaddr_ll s_dest_addr; // code from sender
    struct ifreq ifr;
    int fd, ifi, rb;

    bzero(&s_dest_addr, sizeof(s_dest_addr));
    bzero(&ifr, sizeof(ifr));

    memset(&s_dest_addr, 0, sizeof(s_dest_addr));

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    assert(fd != -1); // abort if error

    strncpy((char *)ifr.ifr_name, dev, IFNAMSIZ);
    ifi = ioctl(fd, SIOCGIFINDEX, &ifr);
    assert(ifi != -1); // abort if error

    s_dest_addr.sll_family = PF_PACKET;
    // we don't use a protocol above ethernet layer, just use anything here
    s_dest_addr.sll_protocol = htons(ETH_P_ALL);
    s_dest_addr.sll_ifindex = ifr.ifr_ifindex;
    s_dest_addr.sll_hatype = ARPHRD_ETHER;
    s_dest_addr.sll_pkttype = PACKET_OTHERHOST; // PACKET_OUTGOING
    s_dest_addr.sll_halen = ETH_ALEN;
    // brodcast mac
    memset(s_dest_addr.sll_addr, 0xFF, ETH_ALEN);

    rb = bind(fd, (struct sockaddr *)&s_dest_addr, sizeof(s_dest_addr));
    assert(rb != -1); // abort if error

    return fd;
}

static int create_raw_socket_recv(const char *dev)
{
    struct sockaddr_ll sll;
    struct ifreq ifr;
    int fd, ifi, rb, attach_filter;

    bzero(&sll, sizeof(sll));
    bzero(&ifr, sizeof(ifr));

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    assert(fd != -1);

    strncpy((char *)ifr.ifr_name, dev, IFNAMSIZ);
    ifi = ioctl(fd, SIOCGIFINDEX, &ifr);
    assert(ifi != -1);

    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_pkttype = PACKET_OTHERHOST;

    rb = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
    assert(rb != -1);

    attach_filter = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(struct sock_fprog));
    assert(attach_filter != -1);

    return fd;
}

void create_raw_socket(const char *dev, int *sock_fd_send, int *sock_fd_recv)
{
    uint8_t ret = 0;
    // open socket
    *sock_fd_send = create_raw_socket_send(dev);
    *sock_fd_recv = create_raw_socket_recv(dev);
    // check error
    if (*sock_fd_send == -1)
    {
        ret = 1;
    }
    if (*sock_fd_recv == -1)
    {
        ret = 1;
    }
    // close socket if error
    if (ret == 1)
    {
        if (*sock_fd_send > 0)
        {
            close(*sock_fd_send);
        }
        if (*sock_fd_recv > 0)
        {
            close(*sock_fd_recv);
        }
        *sock_fd_send = -1;
        *sock_fd_recv = -1;
    }
}

void close_raw_socket(const int sock_fd_send, const int sock_fd_recv)
{
    close(sock_fd_send);
    shutdown(sock_fd_recv, SHUT_RDWR); // wakeup recvfrom and close
}