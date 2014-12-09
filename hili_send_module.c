#include <cvmx.h>
#include <cvmx-config.h>
#include <cvmx-wqe.h>
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-wqe.h"

#include "hili_send_module.h"

uint64_t SRC_MAC = 0x00dead200000;
uint64_t DST_MAC;  //0x0022196337AF (16 eth2)
uint8_t SEND_PORT;

static inline uint16_t hili_ip_calculate_ip_header_checksum(char *ip)
{
    uint64_t sum;
    uint16_t *ptr = (uint16_t*) ip;
    //uint8_t *bptr = (uint8_t*) ip;

    sum  = ptr[0];
    sum += ptr[1];
    sum += ptr[2];
    sum += ptr[3];
    sum += ptr[4];
    // Skip checksum field
    sum += ptr[6];
    sum += ptr[7];
    sum += ptr[8];
    sum += ptr[9];

    sum = (uint16_t) sum + (sum >> 16);
    sum = (uint16_t) sum + (sum >> 16);
    return ((uint16_t) (sum ^ 0xffff));
}

static void create_packet_head(char * head, uint16_t packet_length, hili_send_packet_conf_t *hili_send_packet_conf)
{
    char *ptr = head;
    uint16_t *ip_checksum_ptr;

    int i=0;
    for (i=0; i<6; i++)
    {
        *ptr++ = (DST_MAC >> (40-i*8)) &0xff; //dst mac
    }
    for (i=0; i<6; i++)
    {
        *ptr++ = (SRC_MAC >> (40-i*8)) &0xff; //src mac
    }
    *ptr++ = 0x08;                  /* Ethernet Protocol */
    *ptr++ = 0x00;
    *ptr++ = 0x4f & ( IP_HEADER_LEN | 0xf0 );                  /* IP version, ihl */
    *ptr++ = 0x00;                  /* IP TOS */
    *ptr++ = ( packet_length + IP_HEADER_LEN * 4 + UDP_HEADER_LEN * 4 ) >> 8;        /* IP length */
    *ptr++ = ( packet_length + IP_HEADER_LEN * 4 + UDP_HEADER_LEN * 4 ) & 0xff;
    *ptr++ = 0x00;                  /* IP id */     //TODO
    *ptr++ = 0x00;
    *ptr++ = 0x40;                  /* IP frag_off */ //TODO
    *ptr++ = 0x00;
    *ptr++ = 0x40;                  /* IP ttl */
    *ptr++ = 0x11;                  /* IP protocol */
    ip_checksum_ptr = (uint16_t *)ptr;    /* remember for later */
    *ptr++ = 0x00;                  /* IP check */
    *ptr++ = 0x00;
    *ptr++ = ( hili_send_packet_conf->src_ip >> 24 ) & 0xff;    /* IP src_addr */
    *ptr++ = ( hili_send_packet_conf->src_ip >> 16 ) & 0xff;
    *ptr++ = ( hili_send_packet_conf->src_ip >> 8 ) & 0xff;
    *ptr++ = ( hili_send_packet_conf->src_ip >> 0 ) & 0xff;
    *ptr++ = ( hili_send_packet_conf->dst_ip >> 24 ) & 0xff;    /* IP dst_addr */
    *ptr++ = ( hili_send_packet_conf->dst_ip >> 16 ) & 0xff;
    *ptr++ = ( hili_send_packet_conf->dst_ip >> 8 ) & 0xff;
    *ptr++ = ( hili_send_packet_conf->dst_ip >> 0 ) & 0xff;

    //*ip_checksum_ptr = ip_fast_csum(head, IP_HEAD_LENGTH);
    *ip_checksum_ptr =  hili_ip_calculate_ip_header_checksum(head+14);

    *ptr++ = hili_send_packet_conf->src_port >> 8;  /* UDP source port */
    *ptr++ = hili_send_packet_conf->src_port & 0xff;
    *ptr++ = hili_send_packet_conf->dst_port >> 8;  /* UDP destination port */
    *ptr++ = hili_send_packet_conf->dst_port & 0xff;
    *ptr++ = ( packet_length + UDP_HEADER_LEN * 4 ) >> 8;     /* UDP length */
    *ptr++ = ( packet_length + UDP_HEADER_LEN * 4 ) & 0xff;
    *ptr++ = 0x00;                  /* UDP checksum */
    *ptr++ = 0x00;
}

/** This API is called to transmitted a memory block out without work entry */
static void hili_send_memory(uint8_t *ptr, uint16_t packet_len, uint16_t port, uint8_t ipoffset)
{
    cvmx_pko_command_word0_t pko_command;
    cvmx_buf_ptr_t  packet_ptr;
    int queue;

    queue = cvmx_pko_get_base_queue(port);
    cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_CMD_QUEUE);

    pko_command.u64 = 0;
    pko_command.s.total_bytes = packet_len;
    pko_command.s.segs = 1;
    pko_command.s.ipoffp1 = ipoffset; // calculate hardware TCP/UDP checksum
    pko_command.s.dontfree = 0; // hardware free the buffer:1

    packet_ptr.u64 = 0;
    packet_ptr.s.addr = cvmx_ptr_to_phys(ptr);
    packet_ptr.s.size = packet_len;
    packet_ptr.s.pool = CVMX_FPA_PACKET_POOL;
    packet_ptr.s.size = CVMX_FPA_POOL_0_SIZE;

    int ret = cvmx_pko_send_packet_finish(port, queue, pko_command, packet_ptr, CVMX_PKO_LOCK_CMD_QUEUE);
    if (ret!=0)
    {
        printf("ERROR: Failed to send packet using cvmx_pko_send_packet ...ret=%d \n", ret);
        cvmx_fpa_free((void *)ptr, CVMX_FPA_PACKET_POOL, 0);
    }
}

void *hili_send_module_fpa_alloc()
{
    void *ptr = NULL;
    ptr = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
    if(ptr == NULL)
    {
        printf("Error: hili_send_module_fpa_alloc --- can not alloc a packet buffer! \n");
        return NULL;
    }
    ptr = (uint8_t *)ptr + PACKET_OFFSET;
    return ptr;
}

void hili_send_module_init(uint64_t dst_mac, uint8_t send_port)
{
    if(send_port<6 || send_port>15)
    {
        printf("Error: hili_send_module_init ---send_port=%d \n", send_port);
        return;        
    }
    DST_MAC = dst_mac;
    SEND_PORT = send_port;
}

void hili_send_module_fpa_free(void *ptr)
{
    if(ptr == NULL)
    {
        printf("Error: hili_send_module_fpa_free --- can not free a NULL ptr! \n");
        return;
    }
    ptr = (uint8_t *)ptr - PACKET_OFFSET;
    cvmx_fpa_free(ptr, CVMX_FPA_PACKET_POOL, 0);
}

uint8_t hili_send_module_send_udp_packet(void *ptr, uint16_t len, hili_send_packet_conf_t *hili_send_packet_conf)
{
    if(ptr == NULL)
    {
        printf("Error: hili_send_module_send_udp_packet --- ptr is NULL! \n");
        return 1;
    }
    if(len>1472)
    {
        printf("Error: hili_send_module_send_udp_packet --- len(%u) is error! \n", len);
        return 1;
    }
    
    ptr = (uint8_t *)ptr - PACKET_OFFSET;

    /** fill L2,L3,L4 header */
    create_packet_head((char *)ptr, len, hili_send_packet_conf);

    hili_send_memory((uint8_t *)ptr, len+PACKET_OFFSET, SEND_PORT, 15);

    return 0;
}
