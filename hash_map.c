
// 2014.6.9 @ shangqiuli

# include "hash_map.h" 

extern void *cvm_tcp_lookup_block_base;
extern void *cvm_tcp_syncache_base;
extern void *cvm_tcp_connstate_base;
extern cvm_tcp_lookup_block_t *cvm_tcp_lookup_block_array[CVM_TCP_MAX_NUM_LOOKUP_BLOCKS];



CVMX_SHARED uint32_t cvm_list1_lookup_hash;
 CVMX_SHARED uint32_t cvm_list2_lookup_hash;
CVMX_SHARED void *cvm_tcp_connstate_base1;
CVMX_SHARED void *cvm_tcp_connstate_base2;
CVMX_SHARED void *cvm_tcp_lookup_hash_table_base1 = NULL;
CVMX_SHARED void *cvm_tcp_lookup_hash_table_base2 = NULL;
CVMX_SHARED void *cvm_tcp_lookup_block_base1;
CVMX_SHARED void *cvm_tcp_lookup_block_base2;


int init_hash()
{
    /* setup memory for list1 lookup */
    cvm_tcp_lookup_hash_table_base1 = cvmx_bootmem_alloc(CVM_TCP_NUM_LOOKUP_BUCKETS * sizeof(cvm_tcp_lookup_block_t), CVMX_CACHE_LINE_SIZE);
    if (cvm_tcp_lookup_hash_table_base1 == NULL)
    {
        printf("Out of memory initializing lookup_hash_table.\n");       
        return (1);
    }
    memset(cvm_tcp_lookup_hash_table_base1, 0, CVM_TCP_NUM_LOOKUP_BUCKETS * sizeof(cvm_tcp_lookup_block_t));


    /* setup memory for list2 lookup */
    cvm_tcp_lookup_hash_table_base2 = cvmx_bootmem_alloc(CVM_TCP_NUM_LOOKUP_BUCKETS * sizeof(cvm_tcp_lookup_block_t), CVMX_CACHE_LINE_SIZE);
    if (cvm_tcp_lookup_hash_table_base2 == NULL)
    {
        printf("Out of memory initializing lookup_hash_table.\n");       
        return (1);
    }
    memset(cvm_tcp_lookup_hash_table_base2, 0, CVM_TCP_NUM_LOOKUP_BUCKETS * sizeof(cvm_tcp_lookup_block_t));


	// ?
	void *cvm_tcp_connstate_base1 = cvmx_phys_to_ptr(0);          /*cvmx_fpa_get_base(CVM_FPA_1024B_POOL);*/
	void *cvm_tcp_connstate_base2 = cvmx_phys_to_ptr(0);          /*cvmx_fpa_get_base(CVM_FPA_1024B_POOL);*/
}



static inline uint64_t swap64 (uint64_t v)
{
  return ((v >> 56) |
    (((v >> 48) & 0xfful) << 8) |
    (((v >> 40) & 0xfful) << 16) |
    (((v >> 32) & 0xfful) << 24) |
    (((v >> 24) & 0xfful) << 32) |
    (((v >> 16) & 0xfful) << 40) |
    (((v >> 8) & 0xfful) << 48) | (((v >> 0) & 0xfful) << 56));
}

/**
 * Calculate the MD5 hash of a block of data
 *
 * @param md5        Filled with the 16 byte MD5 hash
 * @param buffer     Input data
 * @param buffer_len Inout data length
 */
void hash_md5(uint8_t *md5, const uint8_t *buffer, int buffer_len)
{
    const uint64_t bits = swap64(buffer_len * 8); /* MD5 expects little endian */
    const uint64_t *ptr = (const uint64_t *)buffer;
    uint8_t chunk[64];

    /* Set the IV to the MD5 magic start value */
    CVMX_MT_HSH_IV(0x0123456789abcdefull, 0);
    CVMX_MT_HSH_IV(0xfedcba9876543210ull, 1);

    /* MD5 input is in the following form:
        1) User data
        2) Byte 0x80
        3) Optional zero padding
        4) Original Data length in bits as an 8 byte unsigned integer
        Zero padding is added to make the 1-4 an even multiple of 64 bytes */

    /* Iterate through 64 bytes at a time */
    while (buffer_len >= 64)
    {
        CVMX_MT_HSH_DAT(*ptr++, 0);
        CVMX_MT_HSH_DAT(*ptr++, 1);
        CVMX_MT_HSH_DAT(*ptr++, 2);
        CVMX_MT_HSH_DAT(*ptr++, 3);
        CVMX_MT_HSH_DAT(*ptr++, 4);
        CVMX_MT_HSH_DAT(*ptr++, 5);
        CVMX_MT_HSH_DAT(*ptr++, 6);
        CVMX_MT_HSH_STARTMD5(*ptr++);
        buffer_len-=64;
    }

    /* The rest of the data will need to be copied into a chunk */
    if (buffer_len > 0)
        memcpy(chunk, ptr, buffer_len);
    chunk[buffer_len] = 0x80;
    memset(chunk + buffer_len + 1, 0, 64 - buffer_len - 1);

    ptr = (const uint64_t *)chunk;
    CVMX_MT_HSH_DAT(*ptr++, 0);
    CVMX_MT_HSH_DAT(*ptr++, 1);
    CVMX_MT_HSH_DAT(*ptr++, 2);
    CVMX_MT_HSH_DAT(*ptr++, 3);
    CVMX_MT_HSH_DAT(*ptr++, 4);
    CVMX_MT_HSH_DAT(*ptr++, 5);
    CVMX_MT_HSH_DAT(*ptr++, 6);

    /* Check to see if there is room for the bit count */
    if (buffer_len < 56)
        CVMX_MT_HSH_STARTMD5(bits);
    else
    {
        CVMX_MT_HSH_STARTMD5(*ptr);
        /* Another block was needed */
        CVMX_MT_HSH_DATZ(0);
        CVMX_MT_HSH_DATZ(1);
        CVMX_MT_HSH_DATZ(2);
        CVMX_MT_HSH_DATZ(3);
        CVMX_MT_HSH_DATZ(4);
        CVMX_MT_HSH_DATZ(5);
        CVMX_MT_HSH_DATZ(6);
        CVMX_MT_HSH_STARTMD5(bits);
    }

    /* Get the final MD5 */
    CVMX_MF_HSH_IV(((uint64_t*)md5)[0], 0);
    CVMX_MF_HSH_IV(((uint64_t*)md5)[1], 1);
}




list1_entry_t *make_list1_entry (cvm_common_wqe_t * swp)
{
		cvm_ip_ip_t *ih = NULL;
		ih = ((cvm_ip_ip_t *)&(swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));
		cvm_tcp_tcphdr_t *th = NULL;
		th = ((cvm_tcp_tcphdr_t *)&(swp->hw_wqe.packet_data[swp->l4_offset]));

		

		list1_entry_t *list1 = NULL;
		list1 = (list1_entry_t *) cvm_common_alloc_fpa_buffer_sync (CVM_FPA_1024B_POOL);
		if(list1 == NULL)
		{
				printf("Can not alloc list1!\n");
				return NULL;
		}
		cvm_common_buffer_init_fast( (void*)list1,  sizeof (list1_entry_t));
		uint32_t lookup_hash, lookup_hash0, lookup_hash1;
		list1->laddr = ih->ip_dst.s_addr;
		list1->faddr = ih->ip_src.s_addr;
		list1->lport = th->th_dport;
		list1->fport = th->th_sport;

		// initialize list1_entry *list1
		uint8_t  result_md5[16];
		list1->tag1 = swp->hw_wqe.tag;
		//list1->username = "AAA"; // 如何从swp的http包里面提取 ？
		//memcpy((uint8_t *)list1->username, "AAAA", 4);
		//hash_md5(result_md5, (uint8_t*)list1->username, strlen(list1->username));
		//list1->MD5 = result_md5;
		//memcpy((uint8_t *)list1->MD5, (uint8_t *)result_md5, sizeof(result_md5));



		list1->tag2 =  result_md5[12]<<24 + result_md5[13]<<16 + result_md5[14]<<8 + result_md5[15];

		list1->inport = swp->hw_wqe.ipprt; // 如何从swp的http包里面提取 ？ 
		list1->outport = list1->inport + 4; // 如何建立port的映射关系 ？

		list1->status = 0;
		//list1->secret_key[16];
		list1->label = 0;


		int i = 0;
		int k = 0;
		cvm_tcp_lookup_block_t *block[CVM_TCP_MAX_NUM_LOOKUP_BLOCKS];
		block[0] = &(((cvm_tcp_lookup_block_t *) cvm_tcp_lookup_hash_table_base)[(swp->hw_wqe.tag) & CVM_TCP_HW_TAG_MASK]);

		CVMX_MT_CRC_POLYNOMIAL (0x1edc6f41);
		CVMX_MT_CRC_IV (0xffffffff);
		CVMX_MT_CRC_WORD (list1->laddr);
		CVMX_MT_CRC_HALF (list1->lport);
		CVMX_MF_CRC_IV (lookup_hash0);
		CVMX_MT_CRC_IV (0xffffffff);
		CVMX_MT_CRC_WORD (list1->faddr);
		CVMX_MT_CRC_HALF (list1->fport);
		CVMX_MF_CRC_IV (lookup_hash1);
		lookup_hash = lookup_hash0 ^ lookup_hash1;

		while (block[k]->next_offset != 0)
		{
				k++;
				block[k] = (cvm_tcp_lookup_block_t *)(cvm_tcp_lookup_block_base 
								+ (((uint64_t)(block[k - 1]->next_offset)) << CVM_TCP_LOOKUP_BLOCK_SHIFT) );
		}
		if (block[k]->valid_count < 15)
		{
				i =  block[k]->valid_count;
		}
		else
		{
				/* alloc 5-tuple lookup block from FPA */
				k++;
				block[k] = (cvm_tcp_lookup_block_t *)cvm_common_alloc_fpa_buffer_sync(CVM_FPA_128B_POOL);
				if (block[k] == 0)
				{
						printf("tcp_insert_lookup_entry: allocation failure for 128B pool\n");
						return (CVM_COMMON_ENOMEM);
				}

				block[k - 1]->next_offset = (uint32_t) (( (CAST64(block[k])) 
										-  (CAST64(cvm_tcp_lookup_block_base))) >> CVM_TCP_LOOKUP_BLOCK_SHIFT);
				block[k]->next_offset = 0;
				i = 0;
		}

		block[k]->entry[i].hash_val = lookup_hash;
		block[k]->entry[i].offset = (uint32_t)(( (CAST64(list1)) 
								-  (CAST64(cvm_tcp_connstate_base))) >> CVM_TCP_TCPCB_SHIFT);
		block[k]->valid_count++;

		//printf("block:%X,	hash:%X,	off:%X\n", block[k], block[k]->entry[i].hash_val, block[k]->entry[i].offset);
		cvm_tcp_move_lookup_entry_to_front(block, k, i);
		CVMX_SYNCWS;

		return list1;
}

list2_entry_t *make_list2_entry (list1_entry_t *list1)
{

		//cvm_tcp_tcphdr_t *th;
		//cvm_tcp_syncache_t *sc = NULL;
		cvm_tcp_lookup_block_t **block;
		int i, k;

		//cvm_tcp_tcpcb_t *list2 = NULL;
		//cvm_tcp_tcpcb_t *head;
		list2_entry_t *list2 = NULL;
		list2_entry_t *head;

		block = cvm_tcp_lookup_block_array;


		// alloc list2_entry
		list2 = (list2_entry_t *) cvm_common_alloc_fpa_buffer_sync (CVM_FPA_1024B_POOL);
		if (list2 == 0)
		{
				CVM_COMMON_TRACE_P2 (CVM_COMMON_TRACE_EXIT, CVM_COMMON_TRACE_FNPTR, cvm_tcp_create_connstate, swp, swp->tcb);
				return (NULL);
		}

		cvm_common_buffer_init_fast( (void*)list2,  sizeof (list2_entry_t));

		// initialize list2_entry *list2
		//list2->secret_key[16] = {0};
		list2->list1_links = 1;
		list2->label = 0;
		list2->tag2 = list1->tag2;


		// build hash_table for list1_entry
		k = cvm_tcp_lookup_block_num;
		i = cvm_tcp_lookup_entry_num;
		block = cvm_tcp_lookup_block_array;

		/* swap matching entry with first entry if needed */
		/* may need to be rewritten in order to get better addr gen code from compiler */
		cvm_tcp_move_lookup_entry_to_front(block, k, i);

		/* place conn state ptr into lookup entry (now in 1st position) */
		(((cvm_tcp_lookup_block_t *) cvm_tcp_lookup_hash_table_base2)[list1->tag2 & CVM_TCP_HW_TAG_MASK]).entry[0].offset = (uint64_t)( (CAST64(list2)) - (CAST64(cvm_tcp_connstate_base2))) >> CVM_TCP_TCPCB_SHIFT;

		return list2;
}	








// list1_entry lookup, Hash CRC32
//static inline list1_entry *hash_in_listofrules(cvm_common_wqe_t * swp)
list1_entry_t *list1_lookup(cvm_common_wqe_t * swp)
{
		uint32_t tag = swp->hw_wqe.tag;

		cvm_ip_ip_t *ih = NULL;
		ih = ((cvm_ip_ip_t *)&(swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));
		cvm_tcp_tcphdr_t *th = NULL;
		th = ((cvm_tcp_tcphdr_t *)&(swp->hw_wqe.packet_data[swp->l4_offset]));
		uint32_t lookup_hash, lookup_hash0, lookup_hash1;
		uint32_t laddr = ih->ip_dst.s_addr;
		uint32_t faddr = ih->ip_src.s_addr;
		uint16_t lport = th->th_dport;
		uint16_t fport = th->th_sport;

		cvm_tcp_lookup_block_t *block[CVM_TCP_MAX_NUM_LOOKUP_BLOCKS];
		int start;
		list1_entry_t *connstate = NULL;
		int i, k;

		/* start code to implement 5-tuple exact-match lookup */
		k = 0;
		block[0] = &(((cvm_tcp_lookup_block_t *)cvm_tcp_lookup_hash_table_base)[tag & CVM_TCP_HW_TAG_MASK]);
		CVMX_PREFETCH(block[0], 0);

		/* calc secondary hash (crc-32c) */
		//lookup_hash = crc_calc32(laddr, faddr, lport, fport);
		CVMX_MT_CRC_POLYNOMIAL(0x1edc6f41);
		CVMX_MT_CRC_IV(0xffffffff);
		CVMX_MT_CRC_WORD(laddr);
		CVMX_MT_CRC_HALF(lport);
		CVMX_MF_CRC_IV(lookup_hash0);
		CVMX_MT_CRC_IV(0xffffffff);
		CVMX_MT_CRC_WORD(faddr);
		CVMX_MT_CRC_HALF(fport);
		CVMX_MF_CRC_IV(lookup_hash1);
		lookup_hash = lookup_hash0 ^ lookup_hash1;

		//printf("list1_lookup lookup_hash = %X  tag = %X\n", lookup_hash, tag);

		start = 0;

		/* search */
keep_looking:
		do
		{
				CVMX_PREFETCH((cvm_tcp_lookup_block_t *)(cvm_tcp_lookup_block_base 
										+ ((uint64_t)(block[k]->next_offset) << CVM_TCP_LOOKUP_BLOCK_SHIFT)), 0);
				//printf("%X,		%d\n", block[k], block[k]->valid_count);
				for (i=start; i<block[k]->valid_count; i++)
				{
						//printf("%X,		%X\n", block[k]->entry[i], block[k]->entry[i].hash_val);
						if (block[k]->entry[i].hash_val == lookup_hash)
								goto match;
				}
				start = 0;
				k++;
				block[k] = (cvm_tcp_lookup_block_t *)(cvm_tcp_lookup_block_base 
								+ ((uint64_t)(block[k - 1]->next_offset) << CVM_TCP_LOOKUP_BLOCK_SHIFT));
		} while (block[k - 1]->next_offset != 0);

		CVM_COMMON_TRACE_P1 (CVM_COMMON_TRACE_EXIT, CVM_COMMON_TRACE_FNPTR, cvm_tcp_is_lookup_entry_present, tag);
		return NULL;

match:
		if ((block[k]->entry[i].offset & 0x80000000) != 0)
		{
				printf("Wrong base to search!\n");
				connstate = (list1_entry_t *)(cvm_tcp_syncache_base 
								+ (((uint64_t)(block[k]->entry[i].offset & CVM_TCP_SYNCACHE_OFFSET_MASK)) << CVM_TCP_SYNCACHE_SHIFT));
		}
		else
		{
				connstate = (list1_entry_t *)(cvm_tcp_connstate_base 
								+ ((uint64_t)(block[k]->entry[i].offset) << CVM_TCP_TCPCB_SHIFT));

		}
		start = i + 1;
		//Client->Server
		if (swp->hw_wqe.ipprt < portbase + portnum  && ((laddr != connstate->laddr)
						|| (faddr != connstate->faddr)
						|| (lport != connstate->lport)
						|| (fport != connstate->fport)))
		{
				goto keep_looking;
		}
		//Server->Client
		if (swp->hw_wqe.ipprt >= portbase + portnum  && ((faddr != connstate->laddr)
								|| (laddr != connstate->faddr)
								|| (fport != connstate->lport)
								|| (lport != connstate->fport)))
		{
				goto keep_looking;
		}

		CVM_COMMON_TRACE_P1 (CVM_COMMON_TRACE_EXIT, CVM_COMMON_TRACE_FNPTR, cvm_tcp_is_lookup_entry_present, tag);
		return connstate;
}



list2_entry_t *list2_lookup(list1_entry_t * list1)
{
		uint32_t lookup_hash0, lookup_hash1;
		cvm_tcp_lookup_block_t **block;
		int start;

		list2_entry_t *ret_val = NULL;

		// 
		uint32_t tag2 = list1->tag2;
		uint32_t *MD5_map = list1->secret_key;

		//cvm_ip_ip_t *ih = ((cvm_ip_ip_t *)&(swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));
		//cvm_tcp_tcphdr_t *th = ((cvm_tcp_tcphdr_t *)&(swp->hw_wqe.packet_data[swp->l4_offset]));

		// 仿照原来的方式 
		uint32_t laddr = MD5_map[0];
		uint32_t faddr = MD5_map[1];
		//uint16_t lport = th->th_dport;
		//uint16_t fport = th->th_sport;
		uint32_t lport = MD5_map[2];
		uint32_t fport = MD5_map[3];


		int i, k;


		//swp->control.sc = 0;
		block = cvm_tcp_lookup_block_array;

		/* start code to implement 5-tuple exact-match lookup */
		k = 0;
		//block[0] = &(((cvm_tcp_lookup_block_t *) cvm_tcp_lookup_hash_table_base)[(swp->hw_wqe.tag) & CVM_TCP_HW_TAG_MASK]);
		block[0] = &(((cvm_tcp_lookup_block_t *) cvm_tcp_lookup_hash_table_base2)[(tag2) & CVM_TCP_HW_TAG_MASK]);
		CVMX_PREFETCH (block[0], 0);

#if defined(__KERNEL__) && defined(linux)
		set_c0_status(ST0_CU2);
#endif
		/* calc secondary hash (crc-32c) */
		CVMX_MT_CRC_POLYNOMIAL (0x1edc6f41);
		CVMX_MT_CRC_IV (0xffffffff);
		CVMX_MT_CRC_WORD (laddr);
		//CVMX_MT_CRC_HALF (lport);
		CVMX_MT_CRC_WORD (laddr);
		CVMX_MF_CRC_IV (lookup_hash0);

		CVMX_MT_CRC_IV (0xffffffff);
		CVMX_MT_CRC_WORD (faddr);
		//CVMX_MT_CRC_HALF (fport);
		CVMX_MT_CRC_WORD (laddr);
		CVMX_MF_CRC_IV (lookup_hash1);
		cvm_list2_lookup_hash = lookup_hash0 ^ lookup_hash1;

		start = 0;
		cvm_tcp_oldest = 0;			/* points to oldest syncache entry */
		cvm_tcp_nb = 0;			/* number of entries */

		k = 0;
		//block[0] = &(((cvm_tcp_lookup_block_t *) cvm_tcp_lookup_hash_table_base)[(swp->hw_wqe.tag) & CVM_TCP_HW_TAG_MASK]);
		block[0] = &(((cvm_tcp_lookup_block_t *) cvm_tcp_lookup_hash_table_base2)[(tag2) & CVM_TCP_HW_TAG_MASK]);
		if (block[0]->valid_count == 0)
		{
				cvm_tcp_last = 0;
				cvm_tcp_oldest = (cvm_tcp_lookup_entry_t *) block[0];
				goto lookup_end;
		}

		/* search */
keep_looking:
		do
		{
				for (i = start; i < block[k]->valid_count; i++)
				{
						if (block[k]->entry[i].offset & 0x80000000)
						{
								/* increment number of syncache entries in this bucket */
								cvm_tcp_nb++;
								if(!cvm_tcp_oldest) 
										cvm_tcp_oldest = &(block[k]->entry[i]);
						}

						if (block[k]->entry[i].hash_val == cvm_list2_lookup_hash)
								goto match;
				}

				start = 0;
				k++;
				block[k] = (cvm_tcp_lookup_block_t *)cvmx_phys_to_ptr( CAST64(cvm_tcp_lookup_block_base2) + ((uint64_t)(block[k - 1]->next_offset) << CVM_TCP_LOOKUP_BLOCK_SHIFT));

		}while (block[k - 1]->next_offset != 0);

		cvm_tcp_last = &(block[k - 1]->entry[i - 1]);
		cvm_tcp_lookup_block_num = k-1;
		cvm_tcp_lookup_entry_num = i-1;
		//swp->control.sc = 0;

		goto lookup_end;



		// 找到了，怎么处理？ 
match:

		if (block[k]->entry[i].offset & 0x80000000)
		{
				//swp->control.sc = 1;
				ret_val = (cvm_tcp_tcpcb_t *)cvmx_phys_to_ptr( CAST64(cvm_tcp_syncache_base) +
								((((uint64_t)(block[k]->entry[i].offset & CVM_TCP_SYNCACHE_OFFSET_MASK))) << CVM_TCP_SYNCACHE_SHIFT));
		}
		else
		{
				//swp->control.sc = 0;
				ret_val = (list1_entry_t *)cvmx_phys_to_ptr( CAST64(cvm_tcp_connstate_base2) + (((uint64_t)(block[k]->entry[i].offset)) << CVM_TCP_TCPCB_SHIFT));
		}



		start = i + 1;

		// ?
		//if ((laddr != ret_val->conn.ie_laddr) || (faddr != ret_val->conn.ie_faddr) || (lport != ret_val->conn.ie_lport) || (fport != ret_val->conn.ie_fport))
		if ((tag2 != ret_val->tag2))
		{
				ret_val = NULL;
				goto keep_looking;
		}


		cvm_tcp_lookup_block_num = k;
		cvm_tcp_lookup_entry_num = i;

		CVMX_PREFETCH(ret_val, 0);
		CVMX_PREFETCH128(ret_val);

		//if (swp->control.sc == 0)
		//  {
		/* swap matching entry with first entry if needed */
		/* may need to be rewritten in order to get better addr gen code from compiler */
		//cvm_tcp_move_lookup_entry_to_front(block, k, i);
		//}

lookup_end:

		CVM_TCP_SET_ACTIVE_TCPCB(ret_val);
		CVM_COMMON_TRACE_P2 (CVM_COMMON_TRACE_EXIT, CVM_COMMON_TRACE_FNPTR, cvm_tcp_lookup, swp, ret_val);

		return ret_val;
		/* end code to implement 5-tuple exact-match lookup */	
}


/*
 * block no = block number (should be 0 based)
 * entry no = entry offset within the block (0-14)
 */

int list1_remove_lookup_entry (cvm_tcp_lookup_block_t *block_list[], int block_no, int entry_no, cvm_common_wqe_t *swp)
{
		int i = entry_no;
		int j = 0;
		int k = block_no;

		CVM_COMMON_TRACE (CVM_COMMON_TRACE_ENTER, CVM_COMMON_TRACE_FNPTR, cvm_tcp_remove_lookup_entry);

		while (1)
		{
				for (j=i+1; j<block_list[k]->valid_count; j++)
				{
						*((uint64_t *)&(block_list[k]->entry[j - 1])) = *((uint64_t *)&(block_list[k]->entry[j]));
				}

				if (block_list[k]->next_offset != 0)
				{
						k++;
						block_list[k] = (cvm_tcp_lookup_block_t *)(cvm_tcp_lookup_block_base 
										+ ((uint64_t)(block_list[k - 1]->next_offset) << CVM_TCP_LOOKUP_BLOCK_SHIFT));
						*((uint64_t *)&(block_list[k - 1]->entry[14])) = *((uint64_t *)&(block_list[k]->entry[0]));
						i = 0;
				}
				else
				{
						break;
				}
		}

		block_list[k]->valid_count--;
		if ((k != 0) && (block_list[k]->valid_count == 0))
		{
				/* free lookup block */
				cvm_common_free_fpa_buffer(block_list[k], CVM_FPA_128B_POOL, 1);
				block_list[k - 1]->next_offset = 0;
		}

		CVMX_SYNCWS;

		CVM_COMMON_TRACE (CVM_COMMON_TRACE_EXIT, CVM_COMMON_TRACE_FNPTR, cvm_tcp_remove_lookup_entry);
		return (0);
}


void list1_discard_lookup_entry(cvm_common_wqe_t *swp)
{
		uint32_t tag = swp->hw_wqe.tag;

		cvm_ip_ip_t *ih = NULL;
		ih = ((cvm_ip_ip_t *)&(swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));
		cvm_tcp_tcphdr_t *th = NULL;
		th = ((cvm_tcp_tcphdr_t *)&(swp->hw_wqe.packet_data[swp->l4_offset]));
		uint32_t lookup_hash, lookup_hash0, lookup_hash1;
		uint32_t laddr = ih->ip_dst.s_addr;
		uint32_t faddr = ih->ip_src.s_addr;
		uint16_t lport = th->th_dport;
		uint16_t fport = th->th_sport;

		cvm_tcp_lookup_block_t *block[CVM_TCP_MAX_NUM_LOOKUP_BLOCKS];
		int start;
		list1_entry_t *connstate = NULL;
		int i, k;

		/* start code to implement 5-tuple exact-match lookup */
		k = 0;
		block[0] = &(((cvm_tcp_lookup_block_t *)cvm_tcp_lookup_hash_table_base)[tag & CVM_TCP_HW_TAG_MASK]);
		CVMX_PREFETCH(block[0], 0);

		/* calc secondary hash (crc-32c) */
		//lookup_hash = crc_calc32(laddr, faddr, lport, fport);
		CVMX_MT_CRC_POLYNOMIAL(0x1edc6f41);
		CVMX_MT_CRC_IV(0xffffffff);
		CVMX_MT_CRC_WORD(laddr);
		CVMX_MT_CRC_HALF(lport);
		CVMX_MF_CRC_IV(lookup_hash0);
		CVMX_MT_CRC_IV(0xffffffff);
		CVMX_MT_CRC_WORD(faddr);
		CVMX_MT_CRC_HALF(fport);
		CVMX_MF_CRC_IV(lookup_hash1);
		lookup_hash = lookup_hash0 ^ lookup_hash1;

		//printf("list1_lookup lookup_hash = %X  tag = %X\n", lookup_hash, tag);

		start = 0;

		/* search */
keep_looking:
		do
		{
				CVMX_PREFETCH((cvm_tcp_lookup_block_t *)(cvm_tcp_lookup_block_base 
										+ ((uint64_t)(block[k]->next_offset) << CVM_TCP_LOOKUP_BLOCK_SHIFT)), 0);
				//printf("%X,		%d\n", block[k], block[k]->valid_count);
				for (i=start; i<block[k]->valid_count; i++)
				{
						//printf("%X,		%X\n", block[k]->entry[i], block[k]->entry[i].hash_val);
						if (block[k]->entry[i].hash_val == lookup_hash)
								goto match;
				}
				start = 0;
				k++;
				block[k] = (cvm_tcp_lookup_block_t *)(cvm_tcp_lookup_block_base 
								+ ((uint64_t)(block[k - 1]->next_offset) << CVM_TCP_LOOKUP_BLOCK_SHIFT));
		} while (block[k - 1]->next_offset != 0);

		CVM_COMMON_TRACE_P1 (CVM_COMMON_TRACE_EXIT, CVM_COMMON_TRACE_FNPTR, cvm_tcp_is_lookup_entry_present, tag);
		printf("Can not find the hash to delete!\n");
		return ;

match:
		if ((block[k]->entry[i].offset & 0x80000000) != 0)
		{
				printf("Wrong base to search!\n");
				connstate = (list1_entry_t *)(cvm_tcp_syncache_base 
								+ (((uint64_t)(block[k]->entry[i].offset & CVM_TCP_SYNCACHE_OFFSET_MASK)) << CVM_TCP_SYNCACHE_SHIFT));
		}
		else
		{
				connstate = (list1_entry_t *)(cvm_tcp_connstate_base 
								+ ((uint64_t)(block[k]->entry[i].offset) << CVM_TCP_TCPCB_SHIFT));

		}
		start = i + 1;
		//Client->Server
		if (swp->hw_wqe.ipprt < portbase + portnum  && ((laddr != connstate->laddr)
						|| (faddr != connstate->faddr)
						|| (lport != connstate->lport)
						|| (fport != connstate->fport)))
		{
				goto keep_looking;
		}
		//Server->Client
		if (swp->hw_wqe.ipprt >= portbase + portnum  && ((faddr != connstate->laddr)
								|| (laddr != connstate->faddr)
								|| (fport != connstate->lport)
								|| (lport != connstate->fport)))
		{
				goto keep_looking;
		}

		printf("Find the hash to delete!\n");
		if(connstate == NULL)
			printf("list1 is NULL\n");
		else
			cvm_common_free_fpa_buffer(connstate, CVM_FPA_1024B_POOL, 0);
		list1_remove_lookup_entry (block, k, i, swp);
		CVM_COMMON_TRACE_P1 (CVM_COMMON_TRACE_EXIT, CVM_COMMON_TRACE_FNPTR, cvm_tcp_is_lookup_entry_present, tag);
		return ;
}
