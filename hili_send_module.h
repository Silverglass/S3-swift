
#include <cvmx.h>
#include <cvmx-config.h>
#include <cvmx-wqe.h>

#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN 5
#define UDP_HEADER_LEN 2
#define PACKET_OFFSET (ETHERNET_HEADER_LEN + IP_HEADER_LEN*4 + UDP_HEADER_LEN*4)

typedef struct
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t src_ip;
    uint32_t dst_ip;
} hili_send_packet_conf_t;



/** this function alloc mem from packet pool for save packet's payload
*   reserve space for L2 header(14), L3 header(20), L4 header(udp 8)
*   return: ptr point to the L4 payload
*/
void *hili_send_module_fpa_alloc();

/** this function free the fpa alloced by hili_send_module_fpa_alloc()
*   ptr: point to the L4 payload
*   so this function first move the ptr to L2 header position
*/
void hili_send_module_fpa_free(void *ptr);

/** this function first fill the  L4 header(udp 8), L3 header(20), L2 header(14)
*   then, send the packet
*   then, free the ptr alloced by hili_send_module_fpa_alloc
*   ptr: point to the L4 payload
*   len: no bigger than 1460
*   return: 0 success, other failure
*/
uint8_t hili_send_module_send_udp_packet(void *ptr, uint16_t len, hili_send_packet_conf_t *hili_send_packet_conf);

/** this function init the send module
*    set the dst mac, src mac, send port
*/
void hili_send_module_init(uint64_t dst_mac, uint8_t send_port);

