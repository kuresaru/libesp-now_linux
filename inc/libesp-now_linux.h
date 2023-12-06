#ifndef LIBESP_NOW_LINUX_LIBESP_NOW_LINUX_H
#define LIBESP_NOW_LINUX_LIBESP_NOW_LINUX_H
#include <stdint.h>

/**
 * init protocol
 * @param my_mac
 */
void esp_now_init(const uint8_t *my_mac);

/**
 * send packet
 * @param sock_fd
 * @param dest_mac
 * @param data
 * @param len
 * @return 0 if success
 */
uint8_t esp_now_send(int sock_fd, const uint8_t *dest_mac, const uint8_t *data, uint8_t len);

/**
 * receive packet
 * @param sock_fd
 * @param data
 * @param len
 * @param from_mac
 */
void esp_now_recv(int sock_fd, uint8_t **data, uint8_t *len, uint8_t **from_mac);

/**
 * create raw socket for transport
 * @param dev
 * @param sock_fd_send
 * @param sock_fd_recv
 */
void create_raw_socket(const char *dev, int *sock_fd_send, int *sock_fd_recv);

/**
 * close raw socket
 * @param sock_fd_send
 * @param sock_fd_recv
 */
void close_raw_socket(const int sock_fd_send, const int sock_fd_recv);

#endif //LIBESP_NOW_LINUX_LIBESP_NOW_LINUX_H
