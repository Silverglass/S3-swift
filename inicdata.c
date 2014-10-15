/***********************************************************************

  OCTEON TOOLKITS                                                         
  Copyright (c) 2007 Cavium Networks. All rights reserved.

  This file, which is part of the OCTEON TOOLKIT from Cavium Networks,
  contains proprietary and confidential information of Cavium Networks
  and in some cases its suppliers.

  Any licensed reproduction, distribution, modification, or other use of
  this file or confidential information embodied in this file is subject
  to your license agreement with Cavium Networks. The applicable license
  terms can be found by contacting Cavium Networks or the appropriate
  representative within your company.

  All other use and disclosure is prohibited.

  Contact Cavium Networks at info@caviumnetworks.com for more information.

 ************************************************************************/ 

#include <stdio.h>
#include <assert.h>
#if defined(linux) && !defined(__KERNEL)
#include <malloc.h>
#include <unistd.h>
#endif

#include "global-config.h"
#include "cvmx-config.h"

#include "cvmx.h"
#include "cvmx-sysinfo.h"
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-fau.h"
#include "cvmx-wqe.h"
#include "cvmx-pip.h"
#include "cvmx-spinlock.h"
#include "cvmx-coremask.h"
#include "cvmx-bootmem.h"
#include "cvmx-helper.h"
#include "cvmx-malloc.h"
#include "cvmx-scratch.h"
#include "cvmx-gmx.h"
#include "cvmx-ebt3000.h"

#include "cvm-common-wqe.h"
#include "cvm-common-defs.h"
#include "cvm-common-misc.h"
#include "cvm-common-fpa.h"

#include "cvm-enet.h"
#include "cvm-enet-arp.h"
#include "cvm-enet-config.h"

#include "cvm-ip-in.h"
#include "cvm-ip.h"
#include "cvm-ip-route.h"
#include "cvm-ip-sockio.h"
#include "cvm-ip-inline.h"
#include "cvm-ip-config.h"
#include "cvm-ip-if-dl.h"

#ifdef INET6
#include "cvm-in6.h"
#include "cvm-in6-var.h"
#include "cvm-ip6.h"
#include "cvm-ip6-var.h"
#include "cvm-icmp6.h"
#include "cvm-scope6-var.h"
#include "cvm-ip6-inline.h"
#include "cvm-nd6.h"
#endif

#include "cvm-tcp.h"
#include "cvm-tcp-var.h"
#include "cvm-tcp-fast.h"
#include "cvm-tcp-init.h"

#include "cvm-udp.h"
#include "cvm-udp-var.h"

#include "socketvar.h"
#include "cvm-socket.h"
#include "cvm-socket-cb.h"
#include "cvm-socket-raw.h"

#include "inic.h"
#include "hash_map.h"
#include <stdbool.h>
#include <openssl/rc4.h>

#ifdef INET6
extern void cvm_ip6_in6_ifattach __P((cvm_enet_ifnet_t *, cvm_enet_ifnet_t *));
extern void cvm_ip6_in6_ifdetach __P((cvm_enet_ifnet_t *));
#endif

uint64_t mytime = 0;

/* Core and Data masks */
extern CVMX_SHARED unsigned int coremask_app;
extern CVMX_SHARED unsigned int coremask_data;

extern int core_id;
extern CVMX_SHARED int highest_core_id;

/* idle counter (per core) */
uint64_t idle_counter = 0;


/* Ip addresses */
CVMX_SHARED cvm_ip_in_addr_t cvm_ip_address[32];
#ifdef INET6
CVMX_SHARED uint64_t cvm_ip6_address[30][2];
#endif

uint64_t cvm_debug_print_interval = 0;

#ifdef DUTY_CYCLE
uint64_t prev_conn_count = 0;

static uint64_t start_cycle = 0;
static uint64_t end_cycle = 0;
static uint64_t process_start_cycle = 0;
static uint64_t process_end_cycle = 0;
static uint64_t process_count = 0;
#endif /* DUTY_CYCLE */

#ifdef CVM_CLI_APP
CVMX_SHARED volatile uint32_t core_idle_cycles[CVMX_MAX_CORES];
#endif

#ifdef REMOTE_MANAGER
int inic_rmngr_process_request(cvm_common_wqe_t *swp);
#endif /*  REMOTE_MANAGER */

#define ANVL_RFC_793_COMPLIANCE


void S3_send_packet(cvmx_wqe_t * work)
{
		uint64_t        port;
		cvmx_buf_ptr_t  packet_ptr;
		cvmx_pko_command_word0_t pko_command;
		/* Build a PKO pointer to this packet */
		pko_command.u64 = 0;


		/* Errata PKI-100 fix. We need to fix chain pointers on segmneted
		   packets. Although the size is also wrong on a single buffer packet,
		   PKO doesn't care so we ignore it */
		if (cvmx_unlikely(work->word2.s.bufs > 1))
				cvmx_helper_fix_ipd_packet_chain(work);

		port = work->ipprt;
		if( port >= portbase + portnum)
				port = work->ipprt - portnum;
		else
				port = work->ipprt + portnum;

		int queue = cvmx_pko_get_base_queue(port);
		cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_ATOMIC_TAG);

		pko_command.s.total_bytes = work->len;
		pko_command.s.segs = work->word2.s.bufs;
		pko_command.s.ipoffp1 = 14 + 1;
		packet_ptr = work->packet_ptr;
		//cvmx_fpa_free(work, CVMX_FPA_WQE_POOL, 0);
		cvm_common_free_fpa_buffer(work, CVMX_FPA_WQE_POOL, CVMX_FPA_WQE_POOL_SIZE / CVMX_CACHE_LINE_SIZE);
		work = NULL;

		/*
		 * Send the packet and wait for the tag switch to complete before
		 * accessing the output queue. This ensures the locking required
		 * for the queue.
		 *
		 */
		if (cvmx_pko_send_packet_finish(port, queue, pko_command, packet_ptr, CVMX_PKO_LOCK_ATOMIC_TAG))
		{
				printf("Failed to send packet using cvmx_pko_send_packet_finish\
								n");
		}
}

int inic_data_global_init(void)
{
		int i,iface;
		char xname[4];

#if 0
		static uint64_t default_route_created = 0;
#endif

		CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_data_global_init\n");

		out_swp = NULL;
		out_swp_tail = NULL;

		/*
		 * Make sure we are not in NULL_NULL POW state
		 * (if we are, we can't output a packet)
		 */
		cvmx_pow_work_request_null_rd();

#ifdef WORK_QUEUE_ENTRY_SIZE_128 // {
		assert(sizeof(cvm_common_wqe_t) == 128);
		assert(CVMX_FPA_WQE_POOL_SIZE == 128);
#else
		assert(sizeof(cvm_common_wqe_t) == 256);
		assert(CVMX_FPA_WQE_POOL_SIZE == 256);
#endif // WORK_QUEUE_ENTRY_SIZE_128 }

#ifdef CVM_CLI_APP
		{
				int a = 0;

				for (a=0; a<CVMX_MAX_CORES; a++)
				{
						core_idle_cycles[a] = ((a*8) + CVM_FAU_REG_CORE_IDLE_CYCLES);
						cvmx_fau_atomic_write64(core_idle_cycles[a], 0x0);
				}
		}
#endif

		if(cvm_enet_init())
		{
				return 1;
		}

		cvm_ip_ip_init();
#ifdef INET6
		cvm_ip6_ip6_init();
#endif

		cvm_tcp_global_init();
		cvm_udp_global_init();
		cvm_raw_global_init();

#ifdef CVM_ENET_VLAN
		cvm_enet_vif_global_init();
#endif

		/* Configure the L2 interface */
		cvm_intf_autoconfig();

		for(iface=0;iface<CVM_ENET_NUM_PIFS;iface++)
		{
				if (!(activeportmask & (1 << iface))) continue;

				strcpy(xname, "em");
				xname[2] = '0' + iface/10;
				xname[3] = '0' + iface%10;
				xname[4] = 0;

				/* Adding IP address */
				cvm_enet_intf_add_ipaddr(xname, cvm_ip_address[iface], 0xffffff00);

				/* Flush packet from the output queue */
				//cvm_send_packet();

				for(i=1; i < 2; ++i){
						/* function for adding alias IP address */
						// cvm_enet_intf_add_alias_ipaddr(xname, cvm_ip_address[iface]+i);
						/* Flush packet from the output queue */
						//cvm_send_packet();
				}

#ifdef INET6
#ifdef CVM_ENET_TUNNEL
				if(iface != 16) {
#endif
						/* Auto configure link local address */
						cvm_ip6_in6_ifattach(cvm_enet_ifnet_ptr_get(iface),NULL);

						/* Configure other addresses */
						uint32_t mask_high = 0xffffffff;
						uint32_t mask_low = 0xffffffff;
						uint64_t prefixmask = ((uint64_t)(mask_high) << 32) | ((uint64_t)mask_low);
						cvm_enet_intf_add_ip6addr(xname, cvm_ip6_address[iface][0], cvm_ip6_address[iface][1], prefixmask, 0, 0xffffffff, 0xffffffff);
						cvm_send_packet();
#ifdef CVM_ENET_TUNNEL
				}
#endif
#endif
		}

#ifdef INET6
#ifdef CVM_ENET_TUNNEL
		cvm_enet_tunnel_global_init();
		cvm_enet_add_tunnel(16,2,0xc0a83001,0xc0a83064);
		cvm_ip6_add_route_for_tunnel(0x2000000000000000ULL, 0, 0xe000000000000000ULL,0, 16 ,2, 0);
		cvm_ip_tunnel_show();
#endif
#endif


#if 0
		if (!default_route_created) {
				default_route_created = 1;

				// Change gateway address according 
				// to actual network setup

				if(cvm_ip_add_default_route(0xc0a83014))
						printf("default route addition NOT successful\n");
				else
						printf("default route addition successful\n");
		}
#endif

		/* Display interface information */
		cvm_enet_intf_show();
		printf("\n");



		/* initialize the application side socket library */
		cvm_so_stack_socket_global_init();


#ifdef STACK_PERF

#ifdef INET6

#ifdef APP_ECHO_SERVER_TCP_v4_v6
		/* create a v6 listening socket */
		cvm_so_create_listening_socket_tcp6();

		/* create a v4 listening socket */
		cvm_so_create_listening_socket_tcp();

#else /* APP_ECHO_SERVER_TCP_v4_v6 */

		/* create a v6 listening socket */
		cvm_so_create_listening_socket_tcp6();

#endif /* APP_ECHO_SERVER_TCP_v4_v6 */

#else  /* INET6 */

		/* create a v4 listening socket */
		cvm_so_create_listening_socket_tcp();

#endif

		/* create a UDP listening socket */
		cvm_so_create_listening_socket_udp();

#endif /* STACK_PERF */

		return 0;
}

int inic_data_local_init(void)
{
		core_id = 0;

		CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_data_local_init\n");

		if ( (cvmx_helper_initialize_packet_io_local()) == -1)
		{
				printf("inic_data_local_init : Failed to initialize/setup input ports\n");
				return (-1);
		}

		core_id = cvmx_get_core_num();
		cvmx_wait(core_id * 500);  /* this is only for pass 1 */
		/*cvm_common_rand8_init();*/

		cvm_ip_local_init();
#ifdef INET6
		cvm_ip6_local_init();
#endif
		cvm_tcp_local_init();
		cvm_so_stack_socket_local_init();
		cvm_udp_local_init();
		cvm_raw_local_init();

		return 0;
}

typedef struct http_data_t
{
		bool is_http;
		bool login;
		bool login_done;
		bool there_is_data;//http包中纯数据部分应该从\r\n\r\n之后开始，若该数据包中含 \r\n\r\n，并且之后有数据，则there_is_data = true,并记下数据起始位置 
		bool get_content;
		bool put_content;
		bool get_done;
		bool put_done;
		uint32_t  pos;//指向需要加解密的数据的起始位置 
		uint8_t username[128];// Authorization： AWS username:XXX   2 
} http_data;

int StrFind(char * ptr, int length, char * str)
{
		int i,j;
		int len = strlen(str);
		for(i=0;i<length-len+1;i++)
		{
				for(j=0;j<len;j++)
				{
						if(ptr[i+j] != str[j])
								break;
				}
				if(j == len && ptr[i+len-1] == str[len-1])
						return i;
		}
		return -1;
}

http_data * http_parse(cvm_common_wqe_t * swp, State status)
{
		http_data * http = (http_data *) cvmx_phys_to_ptr(cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL));
		if(http == NULL)
				return http;
		memset(http, 0, sizeof(http_data));
		cvm_tcp_tcphdr_t *th;
		th = ((cvm_tcp_tcphdr_t *) & (swp->hw_wqe.packet_data[swp->l4_offset]));
		int header_len = th->th_off << 2;//length of Tcp header

		char * ptr = (char *)cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr);
		int res = -1;				
		int pos = 34 + header_len;

		//Client->Server
		if(swp->hw_wqe.ipprt < portbase + portnum)
		{
				if(StrFind(ptr+pos, 3, "GET") != -1 || StrFind(ptr+pos, 3, "PUT") != -1 || StrFind(ptr+pos, 4, "HTTP") != -1 || StrFind(ptr+pos, 4, "HEAD") != -1 || StrFind(ptr+pos, 6, "DELETE") != -1)
				{
					http->is_http = true;
				}else
					return http;
				if(status == S0)
				{
						//16 is the length of "GET / HTTP/1.1\r\n"
						res = StrFind(ptr+pos, 16, "GET / HTTP/1.1\r\n");
						if(res == -1)
								return http;
						//printf("GET / HTTP/1.1	%d\n", res);
						pos += 16;

						//cut a line to find Auth
						res = StrFind(ptr+pos, swp->hw_wqe.len-pos, "\r\n");
						//printf("/r/n  %d\n", res);
						if(res == -1)
								return http;
						pos += res+2;
						//Find Auth
						res = StrFind(ptr+pos, swp->hw_wqe.len-pos, "\r\n");
						//printf("/r/n  %d\n", res);
						if(res == -1)
								return http;
						int i = 0;
						for(i=res-1;i>=0;i--)
						{
								if(ptr[pos+i] == ':')
								{
										break;
								}					
						}
						//19 is the length of "Authorization: AWS "
						//printf("%X,		%X,		%d\n", http->username, ptr, i);
						//printf("%d\n", swp->hw_wqe.len);
						res = StrFind(ptr+pos, 19, "Authorization: AWS ");
						if(i < 0 || res == -1)
						{
								//memset(http, 0, sizeof(http_data));
								return http;
						}
						else
						{
								memcpy(http->username, ptr+pos+19, i-19);									
								http->login = true;
								return http;
						}
				}
				else if(status == S2)
				{
						res = StrFind(ptr+pos, 3, "PUT");
						if(res == -1)
								return http;
						pos += 3;
						res = StrFind(ptr+pos, swp->hw_wqe.len-pos, "HTTP/1.1\r\n");
						if(res == -1)
								return http;			
						pos += res + 10;
						res = StrFind(ptr+pos, swp->hw_wqe.len-pos, "\r\n\r\n");
						http->put_content = true;
						if(res == -1)
								return http;
						pos += 4 + res;			
						if(swp->hw_wqe.len - pos > 0)
						{
								http->there_is_data = true;
								printf("swp->hw_wqe.len: %d  pos: %d\n",swp->hw_wqe.len ,pos);
								http->pos = pos;
						}
						return http;
				}
				/*
				else if(status != S3 && status != S4)
				{
						printf("Waring:Client->Server, State is %d\n", status);
				} 
				*/
		}
		//Server->Client
		else
		{
				res = StrFind(ptr+pos, 8, "HTTP/1.1");
				if(res != -1)
					http->is_http = true;
				else 
					return http;
				if(status == S1)
				{			
						//17 is the length of "HTTP/1.1 200 OK\r\n"		
						res = StrFind(ptr+pos, 17, "HTTP/1.1 200 OK\r\n");							
						if(res == -1)
								return http;
						http->login_done = true;
						return http;							
				}
				else if(status == S2)
				{
						//17 is the length of "HTTP/1.1 200 OK\r\n"
						res = StrFind(ptr+pos, 17, "HTTP/1.1 200 OK\r\n");
						if(res == -1)
								return http;
						pos += 17;

						//cut a line to find Auth
						res = StrFind(ptr+pos, swp->hw_wqe.len-pos, "\r\n");
						if(res == -1)
								return http;
						pos += res+2;
						//Find Content-Length
						res = StrFind(ptr+pos, 16, "Content-Length: ");
						if(res == -1)
								return http;
						pos += 16;
						if(ptr[pos] == '0')
								return http;
						res = StrFind(ptr+pos, swp->hw_wqe.len-pos, "\r\n");
						if(res == -1)
								return http;
						pos += res+2;
						res = StrFind(ptr+pos, 4, "Etag");
						if(res == -1)
								return http;			
						res = StrFind(ptr+pos, swp->hw_wqe.len-pos, "\r\n\r\n");
						http->get_content = true;
						if(res == -1)
								return http;
						pos += 4 + res;			
						if(swp->hw_wqe.len - pos > 0)
						{
								http->there_is_data = true;
								http->pos = pos;
						}
						return http;			
				}
				else if(status == S3)
				{
						//17 is the length of "HTTP/1.1 200 OK\r\n"
						res = StrFind(ptr+pos, 17, "HTTP/1.1 200 OK\r\n");
						if(res == -1)
								return http;
						http->put_done = true;
						return http;	
				}
				else if(status == S4)
				{
						//8 is the length of "HTTP/1.1"
						res = StrFind(ptr+pos, 8, "HTTP/1.1");
						if(res == -1)
								return http;
						http->get_done = true;
						return http;	
				}
				/*
				else if(status != S0)
				{
						printf("Waring:Server->Clinet, State is %d\n", status);	
				}
				*/
		}
		return http;
}



void encryption(uint8_t * enc_map, cvm_common_wqe_t * swp, uint32_t pos)
{
		//return ;
		uint8_t * ptr = (uint8_t *)cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr);
		int i = 0;
		for(i=pos;i<swp->hw_wqe.len;i++)
		{
				ptr[i]=enc_map[ptr[i]];
		}
}

int process_handle(cvm_common_wqe_t * swp)
{
		if(cvmx_get_cycle() - mytime > 8000000000)
		{
				cvmx_pow_iq_com_cnt_t pow_iq_com_cnt;
				pow_iq_com_cnt.u64 = cvmx_read_csr(CVMX_POW_IQ_COM_CNT);
				printf("PAKCET:%llu,     WQE:%llu,   POW:%llu\n", cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(CVMX_FPA_PACKET_POOL)), cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(CVMX_FPA_WQE_POOL)), pow_iq_com_cnt.s.iq_cnt);
				mytime = cvmx_get_cycle();
		}
		
		
		//return 0;
		char * ptr = (char *)cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr);

		//cvm_tcp_tcphdr_t is tcp head,defined in Cvm-tcp.h
		cvm_tcp_tcphdr_t *th;
		th = ((cvm_tcp_tcphdr_t *) & (swp->hw_wqe.packet_data[swp->l4_offset]));
		int header_len = th->th_off << 2;//length of Tcp header	


		//printf("%X  print packet:\n", swp->hw_wqe.tag);
		int n = 0;
		while(n < 10)
		{
		// 	printf("%c", *(ptr+54+n));
			n++;
		}
		//printf("\n");
		int res = 1;
		list1_entry_t * list1 = list1_lookup(swp);
		if(list1 != NULL)
		{
				//printf("in list1 \n");


				//如果为拆链接数据包，则需要删除相应规则列表项
				if(th->th_flags & 0x05)// fin is 0x01; rst is 0x04
				{			
						//list2_entry_t * list2 = list2_lookup(list1);
						//list2.list1_links--;
						//if(list2.list1_links == 0)
						//{
						//没有list1_entry链接到list2_entry上，删除list2_entry 
						//cvm_common_free_fpa_buffer(list2, CVM_FPA_1024B_POOL, 8);
						//list2 = NULL;
						//}
						//删除list1_entry

						//cvm_common_free_fpa_buffer(list1, CVM_FPA_1024B_POOL, 8);
						printf("find TCP rst or fin\n");
					    list1_discard_lookup_entry(swp);	
						list1 = NULL;	
						return res;
				}

				//非拆链接数据包
				http_data * http_entry = NULL;
				http_entry = http_parse(swp, list1->status);
				//检查是否为http协议数据包
				if(http_entry->is_http)
				{
						//服务器回复登录确认，说明用户成功登录			
						if(list1->status == S1)
						{
								if(http_entry->login_done == true)
								{
										/*
										   if(list2_lookup(list1) == NULL)
										   {
										   list2_entry_t * list2 = make_list2_entry(list1);
										//TODO get_secretkey() needs to connect to keys server
										//list2->secret_key = get_secretkey(list1->username);
										hash_md5(list2->secret_key, (uint8_t*)list1->username, strlen(list1->username));

										uint8_t tmp[256];
										RC4_KEY rkey;
										int i=0;
										for(i=0;i<256;i++)
										tmp[i]=i;
										for(i=0;i<256;i++)
										{
										RC4_set_key (&rkey, 16, key);
										RC4 (&rkey, 1, tmp+i, list2->enc_map+i);						
										}	
										memcpy(list1->enc_map, list2->enc_map, 16);				
										list2->list1_links = 1;
										//TODO tag2 = md5 sum
										uint32_t * ptr = (uint32_t *)list2->secret_key;
										list2->tag2 = ptr[0] + ptr[1] + ptr[2] + ptr[3];
										list2->label = 2;
										}*/
										printf("login_done \n");
										hash_md5(list1->secret_key, (uint8_t*)list1->username, strlen(list1->username));

										uint8_t tmp[256];
										RC4_KEY rkey;
										int i=0;
										for(i=0;i<256;i++)
												tmp[i]=i;
										for(i=0;i<256;i++)
										{
												RC4_set_key (&rkey, 16, list1->secret_key);
												RC4 (&rkey, 1, tmp+i, list1->enc_map+i);						
										}					
										list1->status = S2;
								}
								cvm_common_free_fpa_buffer ((void*)http_entry, CVMX_FPA_PACKET_POOL, CVMX_FPA_PACKET_POOL_SIZE / CVMX_CACHE_LINE_SIZE);
								http_entry = NULL;
								return res;
						}

						//用户发送上传数据命令put
						if(list1->status == S2)
						{
								//Clietn->Server
								if(http_entry->put_content == true)
								{
										printf("put content \n");
										list1->status = S3;//将list1结构体的状态设置为数据上传S3
										if(http_entry->there_is_data)//如果包含数据部分，则对数据进行加密，否则直接返回
										{
												printf("put content, encrypt first packet\n");
												/*
												int i = 0;
												char * ptrp = (char *)cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr); 
												printf("http_entry->pos %d", http_entry->pos);
												while(i<100)
												{
													printf("%X", ptrp + i + http_entry->pos);
													if(i%15 == 0)
														printf("\n");
												}
												printf("\n");
												*/
												encryption(list1->enc_map, swp, http_entry->pos);
												res = 0;
										}
								}
								//Server->Client
								else if(http_entry->get_content == true)
								{
										printf("get content \n");
										list1->status = S4;
										if(http_entry->there_is_data)
										{
												printf("get content, decrypt first packet\n");
												encryption(list1->enc_map, swp, http_entry->pos);
												res = 0;
										}
								}
								cvm_common_free_fpa_buffer ((void*)http_entry, CVMX_FPA_PACKET_POOL, CVMX_FPA_PACKET_POOL_SIZE / CVMX_CACHE_LINE_SIZE);	
								http_entry = NULL;
								return res;	
						}


						//下载数据结束						//上传数据成功
						if((list1->status == S4 && http_entry->get_done == true) || (list1->status == S3 && http_entry->put_done))
						{
								printf("put or get done!\n");
								list1->status = S2;
								cvm_common_free_fpa_buffer ((void*)http_entry, CVMX_FPA_PACKET_POOL, CVMX_FPA_PACKET_POOL_SIZE / CVMX_CACHE_LINE_SIZE);	
								http_entry = NULL;
								return res;
						}
						//printf("Waring\n");			
				}
				else//在list1中，非拆链接数据包，也不带http头，应该为需要加解密的数据包，根据list1_entry.state状态机进行加解密
				{
						//数据上传过程，需要对数据进行加密	//数据下载过程，需要对数据进行解密	
						if(list1->status == S3 || list1->status == S4)
						{
								res = 0;
								//54 is the length of MAC+IP+TCP
								//printf("encryption! \n");
								encryption(list1->enc_map, swp, header_len+34);
								//printf("after encryption\n");
								cvm_common_free_fpa_buffer ((void*)http_entry, CVMX_FPA_PACKET_POOL, CVMX_FPA_PACKET_POOL_SIZE / CVMX_CACHE_LINE_SIZE);	
								http_entry = NULL;
								return res;
						}
				}
				if(http_entry != NULL)
						cvm_common_free_fpa_buffer ((void*)http_entry, CVMX_FPA_PACKET_POOL, CVMX_FPA_PACKET_POOL_SIZE / CVMX_CACHE_LINE_SIZE);
				http_entry = NULL;
				return res;
		}
		else//链接不在规则列表中
		{
				//printf("not in list1\n");
				//是否为服务器与客户端之间的新建链接
				http_data * http_entry;
				http_entry = http_parse(swp, S0);
				if(http_entry->is_http == true)
				{
						if(http_entry->login == true)//用户创建新链接时发送
						{
								printf("login\n");
								list1_entry_t * list1 = make_list1_entry(swp);
								/*
								if(list1 != NULL)
								 	printf("after make  list1 != NULL\n");
								 else
								 	printf("after make  list1 == NULL\n");




								 list1 = list1_lookup(swp);
								 if(list1 != NULL)
								 	printf("after lookup  list1 != NULL\n");
								 else
								 	printf("after lookup list1 == NULL\n");
								
								 list1_discard_lookup_entry(swp);
								 list1 = list1_lookup(swp);	
								 if(list1 != NULL)
										 printf("after discard  list1 != NULL\n");
								 else
										 printf("after discard list1 == NULL\n");

								 list1 = make_list1_entry(swp);
								 if(list1 != NULL)
										 printf("after make again list1 != NULL\n");
								 else
										 printf("after make again list1 == NULL\n");

								
								 list1 = list1_lookup(swp);
								 if(list1 != NULL)
								 	printf("after lookup again list1 != NULL\n");
								 else
								 	printf("after lookup again list1 == NULL\n");
								*/

								/*
								   填写list1结构体的数据部分 
								 */
								list1->tag1 = swp->hw_wqe.tag;
								memcpy(list1->username, http_entry->username, 128);

								//hash_md5(list1->secret_key, (uint8_t*)list1->username, strlen(list1->username));
								list1->status = S1;
								list1->inport = swp->hw_wqe.ipprt;
								if( list1->inport >= portbase + portnum)
										list1->outport = list1->inport - portnum;
								else
										list1->outport = list1->inport + portnum;
						}

				}
				cvm_common_free_fpa_buffer ((void*)http_entry, CVMX_FPA_PACKET_POOL, CVMX_FPA_PACKET_POOL_SIZE / CVMX_CACHE_LINE_SIZE);
				return res;
		}
} 







/**
 * Process incoming packets. 
 */
int inic_data_loop(void)
{
		cvm_common_wqe_t *swp = NULL;
		cvm_tcp_in_endpoints_t conn;
		cvm_tcp_tcphdr_t *th = NULL;
		cvm_ip_ip_t *ih = NULL;
		cvmx_sysinfo_t *sys_info_ptr = cvmx_sysinfo_get();
		uint64_t cpu_clock_hz = sys_info_ptr->cpu_clock_hz;
		uint64_t tick_cycle = cvmx_get_cycle();
		uint64_t tick_step;
		uint32_t idle_processing_interval_ticks = (CVM_COMMON_IDLE_PROCESSING_INTERVAL)*(1000*1000)/(CVM_COMMON_TICK_LEN_US);
		uint32_t idle_processing_last_ticks = 0;
#ifdef INET6
		struct cvm_ip6_ip6_hdr *ip6 = NULL;
#ifdef CVM_ENET_TUNNEL
		struct cvm_ip6_ip6_hdr *i6h = NULL;
#endif
#endif


#ifdef CVM_CLI_APP
		uint64_t idle_cycle_start_value;
#endif

		/* for the simulator */
		if (cpu_clock_hz == 0)
		{
				cpu_clock_hz = 333000000;
		}

		tick_step = (CVM_COMMON_TICK_LEN_US * cpu_clock_hz) / 1000000;
		cvm_debug_print_interval = cpu_clock_hz;

#ifndef REAL_HW
		/* for the simulator, set the debug interval to be 3M cycles */
		cvm_debug_print_interval = 3000000;
#endif

#ifdef DUTY_CYCLE
		start_cycle = cvmx_get_cycle();
		process_count = 0;
#endif

		if (cvmx_coremask_first_core(coremask_data)) 
		{
				/* Initiate a timer transaction for arp entry timeouts */
				//if(cvm_enet_arp_timeout_init() != CVMX_TIM_STATUS_SUCCESS)
				//{
				//		printf("Failed init of cvm_ip_arp_timeout_init\n");
				//}
		}

#if defined(CVM_COMBINED_APP_STACK)
		/* Flush the packets sent by main_global and main_local */
		/*
		printf("before cvm_send_packet () \n ");
		if (out_swp)
		{
				cvm_send_packet ();
		}
		printf("after cvm_send_packet () \n ");
		*/
		uint64_t app_timeout = cvmx_get_cycle ();
#endif




		/* start the main loop */
		while (1)
		{


#ifdef DUTY_CYCLE
				end_cycle = cvmx_get_cycle();

				/* check the wrap around case */
				if (end_cycle < start_cycle) end_cycle += cpu_clock_hz;

				if ((end_cycle - start_cycle) > cvm_debug_print_interval)
				{
						inic_do_per_second_duty_cycle_processing();
				}
#endif /* DUTY_CYCLE */

				cvmx_pow_work_request_async_nocheck(CVMX_SCR_WORK, 1);

				/* update the ticks variable */
				while (cvmx_get_cycle() - tick_cycle > tick_step)
				{
						tick_cycle += tick_step;
						cvm_tcp_ticks++;
						if (!(cvm_tcp_ticks & 0x1f)) CVM_COMMON_HISTORY_SET_CYCLE();
				}


				/* do common idle processing */
				if ( (cvm_tcp_ticks - idle_processing_last_ticks) > idle_processing_interval_ticks)
				{
						if (cvmx_coremask_first_core(coremask_data)) 
						{
								cvm_common_do_idle_processing();
						}

						idle_processing_last_ticks = cvm_tcp_ticks;
				}


#ifdef CVM_CLI_APP
				idle_cycle_start_value = cvmx_get_cycle();
#endif

				/* get work entry */
				swp = (cvm_common_wqe_t *)cvmx_pow_work_response_async(CVMX_SCR_WORK);
				if (swp == NULL)
				{
						idle_counter++;

						if(core_id == highest_core_id)
						{
								cvm_enet_check_link_status();
						}

#ifdef CVM_CLI_APP
						cvmx_fau_atomic_add64(core_idle_cycles[core_id], (cvmx_get_cycle()-idle_cycle_start_value) );
#endif
						continue;
				}

				CVM_COMMON_EXTRA_STATS_ADD64 (CVM_FAU_REG_WQE_RCVD, 1);

#ifdef WORK_QUEUE_ENTRY_SIZE_128 // {
				CVMX_PREFETCH0(swp);
#else
				/* Prefetch work-queue entry */
				CVMX_PREFETCH0(swp);
				CVMX_PREFETCH128(swp);
#endif // WORK_QUEUE_ENTRY_SIZE_128 }

				out_swp = 0;
				out_swp_tail = 0;


#ifdef DUTY_CYCLE
				/* we are about to start processing the packet - remember the cycle count */
				process_start_cycle = cvmx_get_cycle();
#endif


				/* Short cut the common case */
				if (cvmx_likely(swp->hw_wqe.unused == 0))
				{
						goto packet_from_the_wire;
				}
				printf("Get work with unused is %X\n", swp->hw_wqe.unused);

				{
						{

packet_from_the_wire:

#if CVM_PKO_DONTFREE
								swp->hw_wqe.packet_ptr.s.i = 0;
#endif

#ifdef SANITY_CHECKS
								/* we have a work queue entry - do input sanity checks */
								ret = cvm_common_input_sanity_and_buffer_count_update(swp);
#endif

								if (cvmx_unlikely(swp->hw_wqe.word2.s.rcv_error))
								{
										goto discard_swp; /* Receive error */
								}

#ifndef WORK_QUEUE_ENTRY_SIZE_128 // {
								{
										/* Make sure pre-fetch completed */
										uint64_t dp = *(volatile uint64_t*)&swp->next;
								}
#endif // WORK_QUEUE_ENTRY_SIZE_128 }

								{
										/* Initialize SW portion of the work-queue entry */
										uint64_t *dptr = (uint64_t*)(&swp->next);
										dptr[0] = 0;
										dptr[1] = 0;
										dptr[2] = 0;
										dptr[3] = 0;
								}

								if(cvmx_unlikely(swp->hw_wqe.word2.s.not_IP))
								{
										goto output;
								}

								/* Shortcut classification to avoid multiple lookups */
								if(
#ifndef INET6
												swp->hw_wqe.word2.s.is_v6 || 
#endif
												swp->hw_wqe.word2.s.is_bcast 
#ifndef INET6
												|| swp->hw_wqe.word2.s.is_mcast
#endif
								  )
								{
										goto discard_swp; /* Receive error */
								}


								/* Packet is unicast IPv4, without L2 errors */
								/* (All IP exceptions are dropped.  This currently includes
								 *  IPv4 options and IPv6 extension headers.)
								 */
								if(cvmx_unlikely(swp->hw_wqe.word2.s.IP_exc))
								{
										goto discard_swp;
								}

								/* Packet is Ipv4 (and no IP exceptions) */
								if (cvmx_unlikely(swp->hw_wqe.word2.s.is_frag || !swp->hw_wqe.word2.s.tcp_or_udp))
								{
										goto output;
								}

#ifdef ANVL_RFC_793_COMPLIANCE
								/* RFC 793 says that:
								   - We should send a RST out when we get a packet with FIN set 
								   without the ACK bit set in the flags field. 
								   - We should send a RST out when we get a packet with no flag set.
								   Hence, let TCP stack handle these conditions.
								 */
								if (cvmx_unlikely(swp->hw_wqe.word2.s.L4_error &&
														(cvmx_pip_l4_err_t)(swp->hw_wqe.word2.s.err_code != CVMX_PIP_TCP_FLG8_ERR) &&
														(cvmx_pip_l4_err_t)(swp->hw_wqe.word2.s.err_code != CVMX_PIP_TCP_FLG9_ERR)))
#else
										if (cvmx_unlikely(swp->hw_wqe.word2.s.L4_error))
#endif
										{
												cvm_tcp_handle_error(swp);
												goto discard_swp;
										}

								/* Packet is not fragmented, TCP/UDP, no IP exceptions/L4 errors */
								/* We can try an L4 lookup now, but we need all the information */
								ih = ((cvm_ip_ip_t *)&(swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));

								if (!swp->hw_wqe.word2.s.is_v6)
								{
										/* for IPv4, we must subtract CVM_COMMON_PD_ALIGN rom tcp_offset to get the offset in the mbuf */
										swp->l4_offset = ((uint16_t)(ih->ip_hl) << 2) + CVM_COMMON_PD_ALIGN;
										swp->l4_prot = ih->ip_p;
								}
#ifdef INET6
								else
								{
										ip6 = (struct cvm_ip6_ip6_hdr *) &swp->hw_wqe.packet_data[CVM_COMMON_IP6_PD_ALIGN];

										CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, 
														"%s: %d Packet trace Src: %s/%d Dest: %s/%d prot: %d len: %d\n", 
														__FUNCTION__, __LINE__, 
														cvm_ip6_ip6_sprintf (&ip6->ip6_dst), conn.ie_fport, 
														cvm_ip6_ip6_sprintf (&ip6->ip6_src), conn.ie_lport,
														swp->l4_prot, swp->hw_wqe.len);
										/* for IPv4, we must subtract CVM_COMMON_PD_ALIGN rom tcp_offset to get the offset in the mbuf */
										swp->l4_offset = CVM_IP6_IP6_HDRLEN;
										swp->l4_prot = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

								}
#endif

								th = ((cvm_tcp_tcphdr_t *)&(swp->hw_wqe.packet_data[swp->l4_offset]));

								/* check if it is a TCP packet */
								if (swp->l4_prot == CVM_IP_IPPROTO_TCP)
								{
										process_handle(swp);
#ifdef INET6
										if (!swp->hw_wqe.word2.s.is_v6)
#endif
										{
												CVM_TCP_TCP_DUMP ((void*)ih);

												/* assume IPv4 for now */
												conn.ie_laddr = ih->ip_dst.s_addr;
												conn.ie_faddr = ih->ip_src.s_addr;
												conn.ie_lport = th->th_dport;
												conn.ie_fport = th->th_sport;

										}
#ifdef INET6
										else
										{
												/* assume IPv4 for now */
												memcpy (&conn.ie6_laddr, &ip6->ip6_dst, sizeof (struct cvm_ip6_in6_addr));
												memcpy (&conn.ie6_faddr, &ip6->ip6_src, sizeof (struct cvm_ip6_in6_addr));
												conn.ie_lport = th->th_dport;
												conn.ie_fport = th->th_sport;

												/* do a TCP lookup */
												swp->tcb = cvm_tcp6_lookup (swp);

												CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, "%s: %d TCPv6 lookup Src: %s/%d Dest: %s/%d ret_tcb: 0x%llx\n", 
																__FUNCTION__, __LINE__, 
																cvm_ip6_ip6_sprintf ((cvm_ip6_in6_addr_t *) &conn.ie6_faddr), conn.ie_fport, 
																cvm_ip6_ip6_sprintf ((cvm_ip6_in6_addr_t *) &conn.ie6_laddr), conn.ie_lport, 
																CAST64(swp->tcb));
										}
#endif // INET6
								}


								goto output;
						} /* packet from wire */
				} /* switch */


output:
				CVMX_SYNCWS;

				/* Send packet out */
				if (out_swp)
				{
						cvm_send_packet();
				}

				if(swp != NULL)
				{
						S3_send_packet((cvmx_wqe_t *)swp);
						swp = NULL;
				}
#ifdef DUTY_CYCLE
				process_end_cycle = cvmx_get_cycle();
				process_count += (process_end_cycle - process_start_cycle);
#endif
		}

		return (0);


discard_swp:
		/* Free the chained buffers */
		cvm_common_packet_free(swp);

		/* Free the work queue entry */
		cvm_common_free_fpa_buffer(swp, CVMX_FPA_WQE_POOL, CVMX_FPA_WQE_POOL_SIZE / CVMX_CACHE_LINE_SIZE);
		swp = NULL;
		goto output;

} /* inic_data_loop */



#ifdef DUTY_CYCLE
inline int inic_do_per_second_duty_cycle_processing()
{
		if ( cvmx_coremask_first_core(coremask_data) )
		{
				CVM_COMMON_SIMPRINTF("cycles: %lld (%lld), idle count=%lld\n", (ll64_t)(end_cycle - start_cycle), (ll64_t)(process_count), (ll64_t)(idle_counter));
		}

		process_count = 0;
		idle_counter = 0;
		start_cycle = cvmx_get_cycle();

		if ( cvmx_coremask_first_core(coremask_data) )
		{
				int i=0;
				uint64_t fpa_hw_counters[8];
#ifndef REAL_HW
				uint64_t fpa_counters[8];

#endif


				for (i=0; i<8; i++)
				{
#ifndef REAL_HW
						fpa_counters[i] = (uint64_t)(CVM_COMMON_GET_FPA_USE_COUNT(i));
#endif
						fpa_hw_counters[i] =  CVM_COMMON_FPA_AVAIL_COUNT(i);
				}



				//CVM_COMMON_SIMPRINTF("Connection count = %lld (%lld)\n",  (ll64_t)(total_conn_count), (ll64_t)(conn_count));
				CVM_COMMON_SIMPRINTF("%6lld : %6lld : %6lld : %6lld\n", (ll64_t)(fpa_hw_counters[0]), (ll64_t)(fpa_hw_counters[1]), (ll64_t)(fpa_hw_counters[2]), (ll64_t)(fpa_hw_counters[3]));
				CVM_COMMON_SIMPRINTF("%6lld : %6lld : %6lld : %6lld\n", (ll64_t)(fpa_hw_counters[4]), (ll64_t)(fpa_hw_counters[5]), (ll64_t)(fpa_hw_counters[6]), (ll64_t)(fpa_hw_counters[7]));

#ifdef TCP_TPS_SIM
				{
						uint64_t total_conn_count = ((uint64_t)(cvmx_fau_fetch_and_add32(CVMX_FAU_REG_TCP_CONNECTION_COUNT, 0)));
						cvmx_fau_atomic_write32(CVMX_FAU_REG_TCP_CONNECTION_COUNT, 0);
						CVM_COMMON_SIMPRINTF("Total TPS count = %lu\n", total_conn_count);
				}
#endif

		}

		return (0);
}
#endif /* DUTY_CYCLES */




#ifdef CVM_CLI_APP

extern int uart_printf(int uart_index, const char *format, ...);
extern inline uint8_t uart_read_byte(int uart_index);


#define uprint(format, ...) uart_printf(0, format, ##__VA_ARGS__)
#define ugetchar() uart_read_byte(0);


/*
 * ANSCII escape sequences
 */
#define CLI_GOTO_TOP    "\033[1;1H"    /* ESC[1;1H begins output at the top of the terminal (line 1) */
#define CLI_ERASE_WIN   "\033[2J"      /* Erase the window */
#define CLI_REVERSE     "\033[7m"      /* Reverse the display */
#define CLI_NORMAL      "\033[0m"      /* Normal display */
#define CLI_CURSOR_ON   "\033[?25h"    /* Turn on cursor */
#define CLI_CURSOR_OFF  "\033[?25l"    /* Turn off cursor */
#define CLI_BOLD        "\033[1m"      /* Bold display */


void inic_top(void)
{
		int i = 0;
		int c = 0;

		static uint64_t last_core_idle_value[CVMX_MAX_CORES];
		uint64_t idle_delta[CVMX_MAX_CORES];
		int first_loop = 1;
		cvmx_sysinfo_t *sys_info_ptr = cvmx_sysinfo_get();

		uprint(CLI_CURSOR_OFF);

		while(c==0x0)
		{
				uprint(CLI_GOTO_TOP);
				uprint(CLI_ERASE_WIN);
				uprint("\n");

				if (first_loop)
				{
						for (i=0; i<CVMX_MAX_CORES; i++) last_core_idle_value[i] = cvmx_fau_fetch_and_add64(core_idle_cycles[i], 0x0);
						cvmx_wait(sys_info_ptr->cpu_clock_hz);
						first_loop = 0;
						c = ugetchar();
						continue;
				}

				for (i=0; i<CVMX_MAX_CORES; i++)
				{
						idle_delta[i] = cvmx_fau_fetch_and_add64(core_idle_cycles[i], 0x0) - last_core_idle_value[i];
						last_core_idle_value[i] = cvmx_fau_fetch_and_add64(core_idle_cycles[i], 0x0);

						if (idle_delta[i] > sys_info_ptr->cpu_clock_hz) idle_delta[i] = sys_info_ptr->cpu_clock_hz;
				}

				uprint(CLI_REVERSE);
				uprint(" Stack Cores Utilization \n");
				uprint(CLI_NORMAL);
				uprint("\n\n");

				for (i=0; i<CVMX_MAX_CORES; i++)
				{
						if ((cvmx_coremask_core(i) & coremask_data) != 0)
						{
								if (i != cvm_common_get_last_core(coremask_data))
								{
										float val = (float)((float)idle_delta[i]/(float)sys_info_ptr->cpu_clock_hz);

										val = (1.0 - val);

										uprint("    Core %2d : ", i);
										uprint(CLI_BOLD);
										uprint("%-3.1f %%\n", ((float)val*100.0));
										uprint(CLI_NORMAL);
								}
						}
				}

				uprint("\n\nPress any key to exit...\n");

				cvmx_wait(sys_info_ptr->cpu_clock_hz);
				c = ugetchar();
		}

		uprint(CLI_CURSOR_ON);
}

#endif /*  CVM_CLI_APP */
