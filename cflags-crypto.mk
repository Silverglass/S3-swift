
# 
# OCTEON SDK
# 
# Copyright (c) 2007 Cavium Networks. All rights reserved.
# 
# This file, which is part of the OCTEON SDK which also includes the
# OCTEON SDK Package from Cavium Networks, contains proprietary and
# confidential information of Cavium Networks and in some cases its
# suppliers. 
# 
# Any licensed reproduction, distribution, modification, or other use of
# this file or the confidential information or patented inventions
# embodied in this file is subject to your license agreement with Cavium
# Networks. Unless you and Cavium Networks have agreed otherwise in
# writing, the applicable license terms can be found at:
# licenses/cavium-license-type2.txt
# 
# All other use and disclosure is prohibited.
# 
# Contact Cavium Networks at info#caviumnetworks.com for more information.
# 


CFLAGS_GLOBAL += -DCVMX_LLM_NUM_PORTS=1

CFLAGS_LOCAL =
# Enable this flag to get crypto api's performance numbers in cpu cycles
# CFLAGS_LOCAL += -DTEST_CPU_CYCLES
