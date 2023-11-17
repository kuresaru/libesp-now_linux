#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

typedef struct
{
    uint8_t ignored_in_this_program[4];
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint8_t broadcast_mac[6];
    uint8_t seq[2];
} ieee80211_action_header_t;

typedef struct
{
    uint8_t ignored_in_this_program[9];
    uint8_t length;
    uint8_t ignored_in_this_program_2[5];
} ieee80211_wireless_management_header_t;

const static uint8_t radiotap_header_template[] = {0x00, 0x00, 0x12, 0x00, 0x2e, 0x48, 0x00, 0x00, 0x10, 0x02, 0x76, 0x09, 0xa0, 0x00, 0xd3, 0x00, 0x00, 0x00};
const static uint8_t ieee80211_action_header_template[] = {
    0xd0, 0x00, // frame control
    0x3a, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst id
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // src id
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // BSS id
    0x00, 0x00,                         // seq
};
const static uint8_t ieee80211_wireless_management_header_template[] = {
    0x7f,             // category=vendor specific
    0x18, 0xfe, 0x34, // oui=esp
    // data (esp hdr)
    0xa2, 0x03, 0x92, 0xb0, // rand?
    0xdd,                   // fixed?
    0x00,                   // content length (this byte to data end)
    0x18, 0xfe, 0x34,       // fixed?
    0x04, 0x01,             // fixed?
};

static uint8_t sendbuf[sizeof(radiotap_header_template) + sizeof(ieee80211_action_header_template) + sizeof(ieee80211_wireless_management_header_template) + 250 + 4];
static uint8_t recvbuf[1024];
static uint16_t seq = 0;

#define RADIOTAP_HEADER_POSITION 0
#define IEEE80211_ACTION_HEADER_POSITION sizeof(radiotap_header_template)
#define IEEE80211_WIRELESS_MANAGEMENT_HEADER_POSITION (IEEE80211_ACTION_HEADER_POSITION + sizeof(ieee80211_action_header_template))
#define USERDATA_POSITION (IEEE80211_WIRELESS_MANAGEMENT_HEADER_POSITION + sizeof(ieee80211_wireless_management_header_template))

void esp_now_init(const uint8_t *my_mac)
{
    memcpy(sendbuf + RADIOTAP_HEADER_POSITION,
           radiotap_header_template,
           sizeof(radiotap_header_template));
    memcpy(sendbuf + IEEE80211_ACTION_HEADER_POSITION,
           ieee80211_action_header_template,
           sizeof(ieee80211_action_header_template));
    memcpy(sendbuf + IEEE80211_WIRELESS_MANAGEMENT_HEADER_POSITION,
           ieee80211_wireless_management_header_template,
           sizeof(ieee80211_wireless_management_header_template));
    memcpy(((ieee80211_action_header_t *)(sendbuf + IEEE80211_ACTION_HEADER_POSITION))->src_mac, my_mac, 6);
}

/**
 * send packet
 * return 0 if success
 */
uint8_t esp_now_send(int sock_fd, const uint8_t *dest_mac, const uint8_t *data, uint8_t len)
{
    // update seq
    if (++seq > 0x0FFF)
    {
        seq = 0;
    }
    // set dest mac
    memcpy(((ieee80211_action_header_t *)(sendbuf + IEEE80211_ACTION_HEADER_POSITION))->dest_mac, dest_mac, 6);
    // set seq
    ((ieee80211_action_header_t *)(sendbuf + IEEE80211_ACTION_HEADER_POSITION))->seq[0] = (seq << 4) & 0xF0;
    ((ieee80211_action_header_t *)(sendbuf + IEEE80211_ACTION_HEADER_POSITION))->seq[1] = (seq >> 4) & 0xFF;
    // set length
    ((ieee80211_wireless_management_header_t *)(sendbuf + IEEE80211_WIRELESS_MANAGEMENT_HEADER_POSITION))->length = len + 6;
    // set data
    memcpy(sendbuf + USERDATA_POSITION, data, len);
    // TODO: 4 bytes FCS
    // send
    return sendto(sock_fd, sendbuf, USERDATA_POSITION + len + 4, 0, NULL, 0) == -1;
}

void esp_now_recv(int sock_fd, uint8_t **data, uint8_t *len, uint8_t **from_mac)
{
    int recv_len = recvfrom(sock_fd, recvbuf, sizeof(recvbuf), MSG_TRUNC, NULL, 0);
    if (recv_len >= USERDATA_POSITION)
    {
        *from_mac = ((ieee80211_action_header_t *)(recvbuf + IEEE80211_ACTION_HEADER_POSITION))->src_mac;
        if (memcmp(((ieee80211_action_header_t *)(sendbuf + IEEE80211_ACTION_HEADER_POSITION))->src_mac, *from_mac, 6))
        {
            *len = ((ieee80211_wireless_management_header_t *)(recvbuf + IEEE80211_WIRELESS_MANAGEMENT_HEADER_POSITION))->length - 6;
            if (recv_len >= USERDATA_POSITION + *len)
            {
                *data = recvbuf + USERDATA_POSITION;
                return;
            }
        }
    }
    *len = 0;
}
