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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cvmx-config.h"
#include "global-config.h"

#include "cvmx.h"
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-fau.h"
#include "cvmx-wqe.h"
#include "cvmx-spinlock.h"
#include "cvmx-helper.h"
#include "cvmx-malloc.h"

#include "socket.h"
#include "cvm-ip-in.h"
#include "cvm-ip.h"
#include "cvm-ip-if-var.h"


#ifdef INET6
#include "cvm-in6.h"
#include "cvm-in6-var.h"
#include "cvm-ip6.h"
#endif

#include "inic.h"
#include "socketvar.h"

#include "cvm-tcp-var.h"

#include "cvm-socket.h"
#ifdef ANVL_OCTEON_PORT
#include "mntcpapp.h"
#endif

#define RAND_VAL   0x53

int inic_app_local_init(void)
{
    int core_id = -1;

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_app_local_init\n");

    core_id = cvmx_get_core_num();

    /* 
     * for each core running the application, seed
     * the random number generator
     */

    srand((core_id+1) * RAND_VAL);

    if ( (cvmx_helper_initialize_packet_io_local()) == -1)
    {
        printf("inic_app_local_init : Failed to initialize/setup input ports\n");
        return (-1);
    }

    cvm_so_app_socket_local_init();

    return (0);
}


int inic_app_global_init(void)
{

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_app_global_init\n");

    cvm_so_app_socket_global_init();

    CVMX_SYNCWS;

    return (0);
}


/* inic application loop */
int inic_app_loop()
{
	
    return 0;
}
