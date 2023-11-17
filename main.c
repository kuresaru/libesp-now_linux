#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

void create_raw_socket(const char *dev, int *sock_fd_send, int *sock_fd_recv);

void esp_now_init(const uint8_t *my_mac);
uint8_t esp_now_send(int sock_fd, const uint8_t *dest_mac, const uint8_t *data, uint8_t len);
void esp_now_recv(int sock_fd, uint8_t **data, uint8_t *len);

const uint8_t my_mac[] = {0x3c, 0x46, 0xd8, 0x4f, 0xc5, 0x5e};
const uint8_t dest_mac[] = {0xe8, 0xdb, 0x84, 0x80, 0x0b, 0x49};
int sock_fd_send = -1, sock_fd_recv = -1;

int main(int argc, char **argv)
{
    // uint8_t ret;
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <wlan_dev>", argv[0]);
        return 1;
    }
    create_raw_socket(argv[1], &sock_fd_send, &sock_fd_recv);
    if (sock_fd_send == -1)
    {
        fprintf(stderr, "Failed to create socket");
        return 1;
    }

    esp_now_init(my_mac);

    // uint8_t ctrstr[4];
    // uint8_t ctr = 0;
    uint8_t *recvbuf;
    uint8_t recvlen;
    while (1)
    {
        // ctr--;
        // sprintf((char *)ctrstr, "%03d", ctr);

        // ret = esp_now_send(sock_fd_send, dest_mac, ctrstr, 4);

        // printf("send %d %s\n", ctr, ret ? "err" : "ok");
        // usleep(500 * 1000);
        esp_now_recv(sock_fd_recv, &recvbuf, &recvlen);
        printf("recv len=%d\n", recvlen);
        for (uint8_t i = 0; i < recvlen; i++)
        {
            printf("%02X ", recvbuf[i]);
        }
        printf("\n");
    }

// LABEL_CLEAN_EXIT:
    if (sock_fd_send > 0)
    {
        close(sock_fd_send);
    }
    if (sock_fd_recv > 0)
    {
        close(sock_fd_recv);
    }

    return 0;
}
