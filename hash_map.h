#ifndef __S3_HASH_MAP__
#define __S3_HASH_MAP__
// 2014.6.9 @ shangqiuli

# include "cvm-tcp.h" 
# include "cvm-tcp-var.h" 



// hash_md5 
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "cvmx.h"
#include "cvmx-key.h"


// make_list_entry
#include "cvm-tcp-fast.h"
#include "cvm-common-fpa.h"
#include "cvm-common-misc.h"
//#include "cvm-tcp-misc.c"
#include "cvm-tcp-var.h"
#include "cvm-tcp.h" 
#include "cvmx.h"


// lookup
#include "cvm-ip.h"
#include "cvmx-asm.h"
#include "cvm-tcp-fast.h"   

#define portbase 6

#define portnum 4

/*
typedef struct cvm_tcp_lookup_entry {
  uint32_t hash_val; // bit 32 = 0: connstate; bit 31 = 1: syncache 
  uint32_t offset;
} cvm_tcp_lookup_entry_t;
 
typedef struct cvm_tcp_lookup_block {
  cvm_tcp_lookup_entry_t entry[15];
  uint32_t next_offset;
  uint8_t valid_count;
  uint8_t reserved1;
  uint16_t reserved2;
} cvm_tcp_lookup_block_t;
*/


typedef enum{
		S3_i,
		swift,
		unknown
} interface;

typedef enum {
	S0,
	S1,
	S2,
	S3,
	S4
} State;

typedef struct list1_entry{

  	uint32_t tag1; //由TCP5元组计算得到，用于索引list1_entry。
	uint8_t username[128]; //用户名，可通过解析用户发来的http数据包的Authorization位得到。
	uint8_t password[128];
	uint8_t auth_token[128];
	uint32_t tag2; //由MD5计算得到，用于索引list2_entry.
	uint16_t inport; //接收数据包的端口。
	uint16_t outport; //转发数据包的端口。
	State status; //该条TCP链接当前的状态（加密/解密/不做处理）
	interface interf;
	uint8_t secret_key[16]; //用户的密钥。//由username计算得到, example/crypto.cs
	uint8_t enc_map[256];
	uint8_t label;
	uint32_t laddr;
	uint32_t faddr;
	uint16_t lport;
	uint16_t fport;
}list1_entry_t;	

typedef struct list2_entry{
	
	uint32_t tag2; //由MD5计算得到，用于索引list2_entry.
	uint8_t secret_key[16]; //用户的密钥。
	uint8_t enc_map[256];
	uint32_t list1_links; //有多少list1_entry链接到该结构体，当值为0时，表明该用户已经退出登录，需要将该list2_entry删除。
	uint8_t label; //用于处理tag1和tag2在索引时的冲突，值为1表示tag1,值为2表示tag2.	
}list2_entry_t;



//#define CVM_TCP_NUM_LOOKUP_BUCKETS 65535
//#define CVMX_CACHE_LINE_SIZE    (128)   // In bytes





extern CVMX_SHARED uint32_t cvm_list1_lookup_hash;
extern CVMX_SHARED uint32_t cvm_list2_lookup_hash;
extern CVMX_SHARED void *cvm_tcp_connstate_base1;
extern CVMX_SHARED void *cvm_tcp_connstate_base2;
extern CVMX_SHARED void *cvm_tcp_lookup_hash_table_base1;
extern CVMX_SHARED void *cvm_tcp_lookup_hash_table_base2;
extern CVMX_SHARED void *cvm_tcp_lookup_block_base1;
extern CVMX_SHARED void *cvm_tcp_lookup_block_base2;


int init_hash();



list1_entry_t *make_list1_entry (cvm_common_wqe_t * swp);


void hash_md5(uint8_t *md5, const uint8_t *buffer, int buffer_len);


list2_entry_t *make_list2_entry (list1_entry_t *list1);

 
// list1_entry lookup, Hash CRC32
//static inline list1_entry *hash_in_listofrules(cvm_common_wqe_t * swp)
list1_entry_t *list1_lookup(cvm_common_wqe_t * swp);


list2_entry_t *list2_lookup(list1_entry_t * list1);

void list1_discard_lookup_entry(cvm_common_wqe_t *swp);
#endif
