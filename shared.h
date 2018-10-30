/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * Shared data across the covert channel
 */

#ifndef SHARED_H
#define SHARED_H

//#define SERVER_IP (192 | 168 << 8 | 0 << 16 | 1 << 24)
#define SERVER_IP (127 | 0 << 8 | 0 << 16 | 1 << 24)

#define PORT 666
#define SLEEP_MS 250

#define TAG_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32

#define OVERHEAD_LEN TAG_LEN + NONCE_LEN

#define MAX_PAYLOAD 4096
#define MAX_USER_DATA MAX_PAYLOAD - OVERHEAD_LEN

#endif /* end of include guard: SHARED_H */
