README for Octeon TCP/IP stack
Release v1.5.0 Build 62
Dated: 4/03/2008




1. WHAT IS IN THIS RELEASE?
2. DEPENDENCIES
3. HOW TO INSTALL	
4. HOW TO BUILD
	4.1. STACK-PERF
	4.2. APP-ECHO-SERVER	
	4.3. APP-ECHO-SERVER-CB
	4.4. APP-CLIENT
	4.5. APP-CLIENT-CB
	4.6. UDP APPLICATION
	4.7. RAW SOCKET APPLICATION
5. VARIOUS TCP SETTINGS
6. IP SETTINGS
	6.1. HOW TO MODIFY IPv4 ADDRESSES
	6.2. HOW TO MODIFY IPv6 ADDRESSES
7. IP STACK FEATURES
8. TCP STACK FEATURES
9. CHANGES FROM RELEASE 1.40
        9.1. IP STACK BUG FIXES
        9.2. TCP/UDP STACK BUG FIXES
        9.3  KNOWN ISSUES
10. CHANGES FROM RELEASE 1.33
        10.1. IP STACK BUG FIXES
        10.2. TCP/UDP STACK BUG FIXES
        10.3  RAW STACK BUG FIXES
11. CHANGES FROM RELEASE 1.32
        11.1. IP STACK BUG FIXES
        11.2. TCP STACK BUG FIXES
12. CHANGES FROM RELEASE 1.31
	12.1. IP STACK BUG FIXES
	12.2. TCP STACK BUG FIXES
13. CHANGES FROM RELEASE 1.30
	13.1. NEW IP STACK FEATURES
	13.2. TCP STACK BUG FIXES
14. CHANGES FROM RELEASE 1.20
	14.1. NEW IP STACK FEATURES
	14.2. TCP STACK BUG FIXES
15. CHANGES FROM RELEASE 1.15
	15.1. NEW TCP STACK FEATURES
	15.2. TCP BUG FIXES	
16. CHANGES FROM RELEASE 1.1
17. CHANGES FROM RELEASE 1.0



NOTE: The instructions in this document assume that the SDK is installed under 
/usr/local/Cavium_Networks/
If you have installed the SDK at some other location then use that path
instead of /usr/local/Cavium_Networks.


1 What is in this release?
--------------------------
This release contains the source code for the Octeon TCP/IP stack and related 
applications.

Note: All tests were done on Octeon EBT3000 PASS2 Evaluation boards.


2 Dependencies
--------------
The release requires OCTEON-SDK-1.7.1-240 or greater already installed on the 
system.


3 How to Install
----------------
Octeon SDK is usually installed under /usr/local/Cavium_Networks folder.

Please install components-common rpm

# rpm -i OCTEON-COMPONENTS-COMMON-1.5.0-45.i386.rpm

After the COMMON installation, install the IP rpm:

# rpm -i OCTEON-IP-1.5.0-62.i386.rpm

After the IP installation, install the TCP rpm:

# rpm -i OCTEON-TCP-1.5.0-62.i386.rpm


This will create the following directory structure in the OCTEON-SDK folder:

OCTEON-SDK
	applications
	    iNIC

	components
            common
	    socket
	    tcp
	    enet
	    ip
            ip6
	    udp


The 'iNIC' folder  contains the source code for app-echo-server, app-client ,
app-echo-server-cb and main loop of the TCP/IP stack.

The 'common' folder contains various macros and routines used by tcp and ip.

The 'socket' folder contains the source code for BSD compatible socket library 
and cavium socket enhancements.

The 'tcp' folder contains source code for the TCP stack.

The 'ip' folder contains the source code for the 'IP stack.

The 'ip6' folder contains the source code for the 'IP6 stack.

The 'enet' folder contains source code for ethernet functions.


4 How to Build
--------------
Before building, make sure that Octeon SDK environment is setup correctly. 

Note: This release supports SDK versions 1.7 and greater.

Please run the "env-setup <OCTEON_MODEL>" script in the OCTEON-SDK folder:
# cd /usr/local/Cavium_Networks/OCTEON-SDK
# source ./env-setup OCTEON_CN38XX 

Make sure to run the correct script based on the target board. 


To build TCP/IP stack, there are six modes:
1. stack-perf (default mode)
2. app-echo-server (stack and app on separate cores)
3. app-echo-server-cb (stack and app on same core)
4. app-client (stack and app on separate cores)
5. app-client-cb (stack and app on same core)
5. app-server-raw (stack and app on separate core)
6. UDP Application
7. RAW SOCKET Application


Note: TCP/IP stack can be built for either n64 or n32 mode.
      
      For building n64 mode, do the following:
  
          # make clean
          # make


      For building n32 mode, do the following:

          # make OCTEON_TARGET=cvmx_n32 clean  
          # make OCTEON_TARGET=cvmx_n32


      All the sections below build the TCP/IP stack for n64 mode.
      For building the TCP/IP stack for n32 mode, please use
      the make command accordingly.


Both n32 and n64 modes support IPv6. By default, the IPv6 support
is disabled. In order to enable this feature, please do the
following:

      # make clean
      # make CVM_IP6=1 


This enables the IPv6 support for n64 mode. For n32 and IPv6 support,
do the following:

      # make CVM_IP6=1 OCTEON_TARGET=cvmx_n32 clean
      # make CVM_IP6=1 OCTEON_TARGET=cvmx_n32


Note that when compiled for IPv6, the code supports both
IPv4 and IPv6.


This release includes VLAN support. Please refer to 
/usr/local/Cavium_Networks/OCTEON-SDK/components/enet/README.vlan for
more information.

The release also has IPv6-over-IPv4 (RFC 4213) support. Please refer to
/usr/local/Cavium_Networks/OCTEON-SDK/components/ip/README.tunnel for
additional information.


4.1 stack-perf
--------------
The default Makefile and configuration settings builds the TCP/IP stack in this 
mode. This is most suitable for testing the TCP/IP stack performance using 
industry standard performance-measuring tool IXLOAD from Ixia. In this mode, 
the TCP/IP stack runs in server mode, accepting new connections on TCP port 80. 
It echoes back the received data after connection establishment. The remote 
client closes the connection. The release contains the document to setup IXLOAD 
for TCP/IP performance measurement. 

The global-config.h file under OCTEON-SDK/applications/iNIC/config folder has 
compile-time flags to control different modes. The default mode is stack-perf 
and is enabled by the following flag:


#define STACK_PERF

This flags is already defined as the default configuration.
To build, please do the following:

# cd /usr/local/Cavium_Networks/OCTEON-SDK/applications/iNIC
# make clean
# make

This will create 'tcpinicmain' executable in the iNIC folder that can be loaded 
and executed on the Octeon board.

To change the behavior of the stack-perf mode, there is an additional flag in 
the global-config.h file which is disabled by default. 

#define IXIA_THRUPUT_TEST : If this flag is used, it enables the
TCP/IP stack to respond with a HTTP packet for every GET request from the 
client. The client can specify the HTTP response size from the Octeon in 
the GET request. For example if client sends GET /512.html, Octeon will 
send back a 512 byte HTTP response. This flag should be used along with 
STACK_PERF flag.


4.2 app-echo-server
-------------------
This mode behaves in the similar fashion as the stack-perf mode. The only 
difference is that it executes a server socket application, which listens for 
incoming connections on TCP port 80, and echoes back the received data after 
connection establishment. 

The server uses the BSD style socket interface.

The global-config.h file under OCTEON-SDK/applications/iNIC/config folder has 
compile-time flags to control different modes. The following flag enables the 
app-echo-server mode:

/* #define STACK_PERF */ : Make sure to comment out this flag.

#define APP_ECHO_SERVER

app-echo-server application runs on a separate core than the TCP/IP stack. The
Makefile controls the number of cores that execute the application. Make sure 
that the Makefile has following line:

NUM_APP_PROCESSORS=1

Where "1" specfies how many cores to be used for the server application.

To build, please do the following:

# cd /usr/local/Cavium_Networks/OCTEON-SDK/applications/iNIC
# make clean
# make

This will create 'tcpinicmain' executable in the iNIC folder that can be
loaded and executed on the Octeon board.

When compiled for IPv6, the flag "APP_ECHO_SERVER_TCP_v4_v6" enables the
echo server to listen on both V4 and V6 sockets. This flag can be defined 
in OCTEON-SDK/applications/iNIC/config/global-config.h file.

If this flag is not defined and the code is compiled for IPv6, only V6
listening socket is created in the echo server application.


4.3 app-echo-server-cb
----------------------
This mode is similar to the app-echo-server mode, but the application runs on 
the same core running the stack. The server application uses the Direct Network 
Interface (DNI) to communicate to the stack. It listens for incoming 
connections on TCP port 80 and echoes back the received data after connection 
establishment. 

The global-config.h file under OCTEON-SDK/applications/iNIC/config folder has 
the compile-time flags to control this mode. The following flag enables the 
app-echo-server-cb mode:

/* #define STACK_PERF */ : Make sure to comment out this flag.

#define CVM_COMBINED_APP_STACK

To build, please do the following:

# cd /usr/local/Cavium_Networks/OCTEON-SDK/applications/iNIC
# make clean
# make

This will create 'tcpinicmain' executable in the iNIC folder that can be loaded 
and executed on the Octeon board.


4.4 app-client
--------------
This mode behaves like a TCP client, which opens 1000 TCP connections serially. It 
establishes each connection to a remote server with IP address: 192.168.48.150 
port 1500. Modifying the code in app-client.c file in the iNIC folder can 
change these settings.
For each connection it sends 512 bytes of arbitrary data and expects the server 
to echo back the same data. It compares the received data with the sent data 
and prints error message if they don't compare. It then closes that TCP 
connection.


The global-config.h file under OCTEON-SDK/applications/iNIC/config folder has 
compile-time flags to control different modes. The following flag enables the 
app-client mode:

/* #define STACK_PERF */ : Make sure to comment out this flag.

/* #define APP_ECHO_SERVER */ " Make sure to comment out this flag.

#define APP_CLIENT

app-client application runs on a separate core than the TCP/IP stack. The
Makefile controls the number of cores that execute the application. Make sure
that the Makefile has following line:

NUM_APP_PROCESSORS=1


To build, please do the following:

# cd /usr/local/Cavium_Networks/OCTEON-SDK/applications/iNIC
# make clean
# make

This will create 'tcpinicmain' executable in the iNIC folder that can be loaded 
and executed on the Octeon board.


4.5 app-client-cb
-----------------
This mode is similar to the app-echo-client mode, but the application runs on 
the same core running the stack. The client application uses the Direct Network 
Interface (DNI) to communicate to the stack. 

In this mode, the client opens 1000 TCP connections serially. It establishes 
each connection to a remote server with IP address: 192.168.48.150 port 1500. 
Modifying the code in app-client-cb.c file in the iNIC folder can change this 
setting.
For each connection the client sends 512 bytes of arbitrary data and expects 
the server to echo back the same data. It compares the received data with the 
sent data and prints error message if they don't compare. It then closes that 
TCP connection.

The global-config.h file under OCTEON-SDK/applications/iNIC/config folder has 
compile-time flags to control different modes. The following flag enables the 
app-client-cb mode:

/* #define STACK_PERF */ : Make sure to comment out this flag.

/* #define APP_ECHO_SERVER */ " Make sure to comment out this flag.

/* #define APP_CLIENT */

#define CVM_COMBINED_APP_STACK

#define DNI_APP_CLIENT


To build, please do the following:

# cd /usr/local/Cavium_Networks/OCTEON-SDK/applications/iNIC
# make clean
# make

This will create 'tcpinicmain' executable in the iNIC folder that can be loaded 
and executed on the Octeon board.


4.6 UDP Application
-------------------
The release contains a sample UDP echo test program for Octeon. To run the UDP 
echo program, following flags are used:

/* #define STACK_PERF */ : Make sure to comment out this flag.

/* Either define */
#define APP_ECHO_SERVER 
/* OR */
#define CVM_COMBINED_APP_STACK

/* #define APP_CLIENT */   : Make sure to comment out this flag. 
/* #define DNI_APP_CLIENT */   : Make sure to comment out this flag. 


#define CVM_UDP_ECHO_SERVER  : This flag should be defined */

Note: The "APP_ECHO_SERVER" will run the UDP application on a seprate core from
stack, while defining "CVM_COMBINED_APP_STACK" will run the udp application
on the smae core as the stack.

The UDP application listens on port 8888 and echoes the data it receives back 
to the sender.

If compiled for IPv6, the UDP application also creates an additional V6 socket
which listens on port 9999 and echoes back the incoming data.


4.7 RAW SOCKET Application
--------------------------
This release contains a sample raw server test program for Octeon. 

4.7.1 Application and Stack on separate cores (non-DNI mode)

Make the following changes in OCTEON-SDK/applications/iNIC/config/global-config.h file

- comment the STACK_PERF flag
/* #define STACK_PERF */     : Make sure to comment out this flag.

- define the APP_SERVER_RAW flag
#define APP_SERVER_RAW

- Following flags need to be defined in addition to the above flags for
  Raw Socket-TCP support:
#define CVM_RAW_TCP_SUPPORT

- Code compiled for IPv6
If the code is compiled for IPv6, the application creates a V6 socket
and only handles IPv6 packets.

For details regarding the application, please refer to the file
OCTEON-SDK/applications/iNIC/app-server-raw.c


4.7.2 Application and Stack on the same core (DNI mode)

Make the following changes in OCTEON-SDK/applications/iNIC/config/global-config.h file

- Comment the STACK_PERF flag
/* #define STACK_PERF */     : Make sure to comment out this flag.

- define CVM_COMBINED_APP_STACK flag
#define CVM_COMBINED_APP_STACK

- define CVM_COMBINED_APP_STACK_ECHO_SERVER_RAW flag
#define CVM_COMBINED_APP_STACK_ECHO_SERVER_RAW_FLAG

- Code compiled for IPv6
If the code is compiled for IPv6, the application creates a V6 socket
and only handles IPv6 packets.

For details regarding the application, please refer to the file 
OCTEON-SDK/applications/iNIC/app-echo-server-raw-cb.c

In both the above cases, the raw socket application receives data from
the sender and sends the received data back to the sender (after 
removing the IP header from the received data)


5 Various TCP settings
----------------------
Various flags in 
/usr/local/Cavium_Networks/OCTEON-SDK/applications/iNIC/config/global-config.h 
control the behavior of the TCP stack. These flags are:

 5.1	TCP_DO_TS_OPT: 
      When set to 1, it enables the TCP timestamp option.
      By default this flag is set to 0.

 5.2	TCP_DO_SACK_OPT:
      When set to 1, it enables the TCP selective ACK option.
      By default this flag is set to 0.

 5.3	TCP_DO_WS_OPT:
      When set to 1, it enables the TCP window scaling option.
      By default this flag is set to 0.
    
 5.4	TCP_DISABLE_DACK:
      When set to 1, it disables the TCP delayed ACK mechanism.
      By default this flag is set to 1.

 5.5	TCP_DISABLE_RETRANSMIT_TIMER:
      When set to 1, it disables the TCP retransmission timer.
      By default this flag is set to 0.

 5.6	TCP_DISABLE_TIME_WAIT_TIMER:
      When set to 1, it disables the TCP time-wait timer.
      By default this flag is set to 0.

 5.7	TCP_DISABLE_KEEPALIVE_TIMER:
      When set to 1, it disables the TCP keep-alive timer.
      By default this flag is set to 0.

 5.8	TCP_DISABLE_DELAYED_ACK_TIMER:
      When set to 1, it disables the TCP delayed ACK timer.
      By default this flag is set to 0.

 5.9	TCP_DISABLE_PERSIST_TIMER:
      When set to 1, it disables the TCP persist timer.
      By default this flag is set to 0.

 5.10	TCP_DISABLE_LISTEN_CLOSE_TIMER:
      When set to 1, it disables the TCP listen-close timer.
      By default this flag is set to 0.

 5.11	TCP_DISABLE_SYNCACHE_TIMER:
      When set to 1, it disables the TCP syncache retransmission timer. 
By default this flag is set to 0.


6 IP Settings
-------------
The default IP address setting is as under. Please note that the Octeon board 
can be optionally used with a SPI daughter board which has 10 ports.

IPv4 addresses:

Interface 0 (SPI):
Port 0:  IP: 192.168. 32.1 Netmask: 0xffffff00
Port 1:  IP: 192.168. 33.1 Netmask: 0xffffff00
Port 2:  IP: 192.168. 34.1 Netmask: 0xffffff00
Port 3:  IP: 192.168. 35.1 Netmask: 0xffffff00
Port 4:  IP: 192.168. 36.1 Netmask: 0xffffff00
Port 5:  IP: 192.168. 37.1 Netmask: 0xffffff00
Port 6:  IP: 192.168. 38.1 Netmask: 0xffffff00
Port 7:  IP: 192.168. 39.1 Netmask: 0xffffff00
Port 8:  IP: 192.168. 40.1 Netmask: 0xffffff00
Port 9:  IP: 192.168. 41.1 Netmask: 0xffffff00

Interface 1 (RGMII):
Port16:  IP: 192.168. 48.1 Netmask: 0xffffff00
Port17:  IP: 192.168. 49.1 Netmask: 0xffffff00
Port18:  IP: 192.168. 50.1 Netmask: 0xffffff00
Port19:  IP: 192.168. 51.1 Netmask: 0xffffff00


IPv6 addresses:

Interface 0 (SPI):
Port 0:  IPv6: 2233:4455:6677:8899:1234:5678:abcd:ef32/64
Port 1:  IPv6: 2233:4455:6677:889a:1234:5678:abcd:ef32/64
Port 2:  IPv6: 2233:4455:6677:889b:1234:5678:abcd:ef32/64
Port 3:  IPv6: 2233:4455:6677:889c:1234:5678:abcd:ef32/64
Port 4:  IPv6: 2233:4455:6677:889d:1234:5678:abcd:ef32/64
Port 5:  IPv6: 2233:4455:6677:889e:1234:5678:abcd:ef32/64
Port 6:  IPv6: 2233:4455:6677:889f:1234:5678:abcd:ef32/64
Port 7:  IPv6: 2233:4455:6677:88a0:1234:5678:abcd:ef32/64
Port 8:  IPv6: 2233:4455:6677:88a1:1234:5678:abcd:ef32/64
Port 9:  IPv6: 2233:4455:6677:88a2:1234:5678:abcd:ef32/64

Interface 1 (RGMII):
Port 16: IPv6: 2233:4455:6677:88a9:1234:5678:abcd:ef32/64
Port 17: IPv6: 2233:4455:6677:88aa:1234:5678:abcd:ef32/64
Port 18: IPv6: 2233:4455:6677:88ab:1234:5678:abcd:ef32/64
Port 19: IPv6: 2233:4455:6677:88ac:1234:5678:abcd:ef32/64



6.1 How to Modify IPv4 Addresses
--------------------------------
The IP addresses can be changed from the command line with '-p' option. For 
example -p6=12.12.12.12 configures the IP address for port 6 to 12.12.12.12 
with a netmask based on the netclass.
Please note that '-p' command line option does not have any spaces '=' or '.'


6.2 How to Modify IPv6 Addresses
--------------------------------
The IPv6 addresses can be changed from the command line with '-6p' option.
For example 'bootoct 0x100000 coremask=0x1 -6p0=3ffe:0501:ffff:0100:020f:b7ff:fe10:1fe2
-6p3=3ffe:0501:ffff:0101:020f:b7ff:fe10:1fe2' configures the IP6 address for
port0 to 3ffe:0501:ffff:0100:020f:b7ff:fe10:1fe2 and
port3 to 3ffe:0501:ffff:0101:020f:b7ff:fe10:1fe2
Please note that '-6p' command line option does not have any spaces '=' or '.'


7 IP Stack Features
-------------------

7.1 The following IPv4 stack features are supported in this release:

	IPv4 header checksum 
	IPv4 header validation
	IPv4 header generation
	Fast path receive
	Fast path transmit
	ICMP Echo Reply
	ARP Request
	ARP Reply
	ARP Table
	Boot time configurable Routing Table
	Command Line Interface
	Retrieving and displaying L2 addresses
	Setting/retrieving interface flags and mtu.
	Adding and deleting IPv4 addresses.
	Adding and deleting routing table entries.
	Retrieving and displaying routing table information.


7.2 The following IPv6 stack features are supported in this release:

	IPv6 header validation
	Fast path receive
	Fast path transmit
	ICMPv6 Echo Reply
	Neighbor Discovery (Neighbor Solicitation/Advertisement, Router Solicitation/Advertisement)
	IPv6 Stateless Address Configuration
	Boot time configurable Routing Table
	Command Line Interface
	Retrieving and displaying L2 addresses
	Setting/retrieving interface flags and mtu.
	Adding and deleting IPv6 addresses.
	Adding and deleting routing table entries.
	Retrieving and displaying routing table information.


8 TCP Stack Features
--------------------

The following TCP stack and socket features are supported in this release:

	BSD Compliant TCP Socket API
		socket()
		bind()
		listen()
		accept()
		accept_multi()
		connect()
		close()
		setsockopt()
		getsockopt()
		send()
		recv()
		read_zc()
		write_zc()
		read()
		write()
		poll()
		fcntl()
		ioctl()
		shutdown()
		sendto()
		recvfrom()

	Simultaneous Open
	Connection Reset
	Delayed Ack.
	Sliding Window Protocol
	TCP Header Checksum 
	TCP MSS Option
        TCP Selective ACK Option
        TCP Time Stamps Option
        TCP PAWS (Protection Against Wrapped Sequence numbers)
        TCP Window Scaling Option (scaling of 1 is currently supported)
	TCP Timers
	TCP Reassembly
	TCP stats collection
	UDP Support
	RAW Sockets Support


9. Changes from release 1.40
----------------------------
+ IPv6-over-IPv4 (RFC 4213: Configured Tunneling) support
+ IPv6 Path MTU Discovery (RFC 1981)
+ Host based VLAN support
+ Loopback interface support


9.1 IP Bug Fixes:
-----------------

Bug 1385: Buffer leak due to IP/IPSec reassembly garbage collector bitmask not cleared correctly
Bug 1388: Crash in reassembly under load conditions due to reassembly data structure not initialized properly
Bug 1391: Buffer leak due to fragment descriptors not getting freed under certain circumstances
Bug 1438: The 'i' bit in the work queue for IP fragmentation entry is hardcoded
Bug 1441: Next packet pointer is not preserved when L2 header is added
Bug 1452: Buffer size not adjusted for multibuffer packets in the IPFwd application
Bug 1453: TCP checksum is not calculated correctly in software
Bug 1460: Back field is not set during fragmentation
Bug 1461: Crash in cvm_common_dump_packet_gth
Bug 1474: Crash observed during ARP
Bug 1495: Crash in reassembly under load conditions with mtu=3300 
Bug 1511: Missing CVMX_SYNCWS in reassembly code. 
Bug 1512: Last Fragment received more than once for the same flow is not handles properly. 
Bug 1513: End of the 'last fragment' is less than the last byte seen for a flow not handles properly.
Bug 1514: Back value of the reassembled packet might be incorrect. 
Bug 1515: Multiple Buffer overlap not handled for merge behind case. 
Bug 1516: Last buffer size was not being adjusted properly for a regular fragment merge. 
Bug 1525: Potential Buffer leak in IP reassembly


9.2 TCP/UDP Stack bug fixes:
----------------------------

Bug 1359: Processing SYN in SYN-RCVD state
Bug 1420: Double free of work queue entry in DNI UDP send case
Bug 1465: TCP Timers for v6 traffic
Bug 1469: UDP with IPv6: close may not remove bind entry from the lookup table
Bug 1479: Un-initialized WQE field in connect() causes V4 packets to be treared as V6
Bug 1481: Corrupted data is returned when running TCP stack in STACK_PERF mode with IPv6 traffic
Bug 1509: Data corruption while processing overlapping packets
Bug 1521: Incorrect seqnum in FIN retransmission


9.3 Known Issues:
----------------

Bug 1522: Memory leak when a UDP socket is closed
Bug 1523: Memory leak when UDP packets are received but there is no listening socket



10 Changes from release 1.33
----------------------------
+ IPv6 support
+ TCP and UDP support for IPv6

10.1 IP Bug Fixes:
------------------
 
Bug 1174: API missing for changing L2 address
Bug 1311: The control can stuck in an infinite loop in function cvm_ip_ifa_ifwithaddr()
Bug 1351: TCP checksum incorrectly calculated for forwarded IP fragments
Bug 1352: Crash observed during TCP checksum calculation for host initiated packets requiring ip fragmentation
Bug 1353: ICMP error messages should include as many bytes of the original packet as possible without leading to ip fragmentation
Bug 1358: Bogus ARP generated during system initialization for n32 dual mode (IPv4/IPv6) stack
Bug 1360: IPv6 address addition/deletion and route addition/deletion functions are not working for n32 mode

10.2 TCP/UDP Stack bug fixes:
-----------------------------

Bug 1343: UDP may not setup the IPv4 header properly if the code is compiled only for IPv4

10.3 RAW Stack Bug Fixes:
------------------------
Following bugs are fixed for the RAW stack:

Bug 1333: Raw socket connected to foreign address = 0
Bug 1341: Data corruption in RAW sockets


11 Changes from release 1.32
----------------------------
+ Raw sockets support
+ TCP protocol support for Raw sockets
+ N32 mode support

11.1 IP Bug Fixes:
-----------------
Following bugs are fixed for the IP stack:

Bug 1171: IP Reassembly drops UDP packets with checksum field=0 
Bug 1173: Data corruption and system crash for out-of-order multi buffer fragment reassembly 
Bug 1188: Hardware MTU is not set when calling enet ioctl for setting MTU 
Bug 1190: IP reassembly fails when MTU=64 for 128-byte packet sent in 4 fragments 
Bug 1198: ARP Table head pointer is not global

11.2 TCP Bug Fixes:
------------------
Following bugs are fixed for the TCP stack release:

Bug 1199: soconnect: accessing work-queue entry after free
Bug 1203: Booting octeon tcp with 1G Memory configuration
Bug 1205: UDP stack traps when sending UDP packets in STACK_PERF mode
Bug 1206: Invalid no of apps cores defined in Makefile doesnt generate any error
Bug 1195: README document fixes
Bug 1213: TCP Conngestion control doesn't work
Bug 1232: cvm_so_get_recv_data() can double free fpa pointer for UDP linked buffer case


12 Changes from release 1.31
---------------------------

12.1 IP Stack Bug Fixes
----------------------
Following Bugs are fixed for the IP stack:

Bug 1083: IP address deletion api missing.
Bug 1084: Crash seen with ping of data size >= 2953 Bytes 
Bug 1085: Pool 0 depletion seen for packets with size > MTU.
Bug 1092: System hangs with overlapped fragments during IP reassembly.
Bug 1096: Pool 0 depletion seen for packets with size > MTU (Netem: Duplicate 10%) 
Bug 1099: Pool 0 depletion seen with Netem: Drop 10% (For fragmented data only)
Bug 1104: Routing tree entry deletion api not working for indirect routes.


12.2 TCP Stack Bug Fixes
-----------------------
Following Bugs are fixed for the TCP stack:

Bug 942:  TCP control block being accessed in cvm_so_tcp_close() after 
signature mismatch
Bug 943:  128B pool out of buffer condition is not being handled correctly in 
create_syncache()
Bug 947:  zero copy: cleanup if alloc() fails
Bug 952:  socket core timeout leading to memory corruption
Bug 956:  "TCP retransmission timer: incorrect ""slop"""
Bug 963:  Reassembly: Processing zero-len control packets
Bug 971:  Accept queue full condition is not being handled correctly
Bug 977:  UDP: cvm_so_recvfrom functionality broken
Bug 979:  Updating tcp state while closing session
Bug 992:  Memory leak on WQE Pool #1
Bug 996:  App core sending more window updates to stack core than required
Bug 1025: TCP Timer: FPA memory corruption leading to double-free/alloc
Bug 1026: IXIA thruput drop from 100MB to 10kB
Bug 1027: Non-blocking connect() doesn't work
Bug 1031: Memory leak in slow path FIN processing
Bug 1034: TTL value in a re-transmitted SYN-ACK is zero
Bug 1041: Missing Segment
Bug 1042: Invalid value returned by cvm_tcp_usr_soshutdown()
Bug 1050: Socket file descriptor corruption
Bug 1051: Memory corruption in pool #4 (256B)
Bug 1052: Memory leak in Packet pool #0 (2048B)
Bug 1053: Proxy Sessions stalling
Bug 1054: TCP reassembly corner cases
Bug 1055: Crash due to un-initialized time-wait state
Bug 1056: TCP-Reassembly: Double accounting of input segment results in acking for un-received data
Bug 1057: Incorrect FIN processing in case of missing received packets
Bug 1061: connect() timeout doesn't return an event in DNI mode
Bug 1062: Incorrect timeout values for sending SYN retries
Bug 1067: Invalid Free to Pool #3 (128B)
Bug 1068: Pool #1 corruption (stack core gets UDP pkt!)
Bug 1069: Ethernet crash in enet_ether_output
Bug 1070: Corruption in Pool #3 (invalid/double free)
Bug 1071: Crash due to mismatch between WQE data and packet pointer
Bug 1072: so_send() returning incorrent bytes to app when memory alloc fails
Bug 1073: TCP Reassembly problem
Bug 1074: Memory leak when sosend fails to alloc WQE
Bug 1075: Memory leak in 128B Pool
Bug 1076: memory corruption problem in pool #3 after 13 hrs
Bug 1077: Memory corruption in pool #4 (256B)
Bug 1078: Proxy Sessions stalling
Bug 1079: Socket file descritor corruption (bad fd)
Bug 1080: Crash due to un-initialized time-wait timer state variable
Bug 1081: TCP Reassembly issues
Bug 1106: bind() to an invalid local address does not return error
Bug 1114: UDP Sendto() call ignores an earlier bind()
Bug 1115: Invalid seq# calculation when out of order data is received
Bug 1117: udp_output return value not being propagated back to the application
Bug 1119: memcpy parameters in cvm-tcp-fast.h are incorrect (linked buffer case)
Bug 1124: DOS attack: adding packet pool threshold for TCP Reassembly
Bug 1161: SYN-ACK from Octeon TCP stack doesn't have MSS option  
Bug 1172: UDP sendto() to a local IP address results is a crash  



13 Changes from release 1.30
----------------------------

13.1 New IP stack Features
--------------------------
Following new features were added to the IP stack:

+ Retrieving and displaying L2 addresses
+ Setting/retrieving interface flags and mtu.
+ Adding and deleting IP addresses.
+ Adding and deleting routing table entries.
+ Retrieving and displaying routing table information.

13.2 TCP Stack Bug Fixes
------------------------
Following Bugs are fixed.
  Bug 853: TCP: TSEGQ: Incrementing null pointer buffer.
  Bug 927: IP: Segment ptr corruption during IP reassembly
  Bug 928: IP: Buffer not freed during IP fragmentation using gather array
  Bug 929: IP: Ethernet header included as part of payload during IP fragmentation
  Bug #853 TSEGQ: Incrementing null pointer buffer  
  Bug #941 Socket APIs: synchronization issues between socket and tcp 
           Cores.

14 Changes from release 1.20
----------------------------

14.1 New IP Stack Features
--------------------------
1. Added default route support in IP. A default gateway can be added by calling 
the function: cvm_ip_add_default_route(gateway_address);

Note: There can only be one default route.

2 Added support to collect TCP stats remotely. The following flags should be 
defined in global-config.h to enable this feature:

#define TCP_STATS
#define REMOTE_STATS_REPORTING

The file applications/iNIC/inicrmngr.h defines opcodes and corresponding data 
structures for the request and response.

A remote host creates a UDP packet with a request and sends it to the Octeon 
using UDP port number 8749. Upon receipt of this request, Octeon creates a UDP 
reply packet containing all the requested information, and sends it back to the 
remote host.

14.2 TCP Stack Bug Fixes
------------------------
The following bugs are fixed:
   
Bug #450	SO_LINGER with non-zero linger timer doesn't work
Bug #575	Inaccuracy in persist timer
Bug #719	tcp_output fast path: Handling len<0 condition 
Bug #721	Default gateway or added gateways do not work in TCP/UDP case 
Bug #722	Handling invalid ACK pkts 
Bug #741	Listen on same address and port by multiple app cores 
Bug #762	Connect notification is not received in TCP stack 1.2 for DNI mode
Bug #763	TCP core crashes on SSL application
Bug #813	Tag value not stored for DNI connect() case
Bug #820	ICMP Error: double free of swp (WQE pool)
Bug #821	Incorrect received packet length for certain UDP packets
Bug #836	A few retransmit timeout calculations may be incorrect

  
15 Changes from release 1.15
----------------------------

15.1 New TCP Stack Features
---------------------------
1 Selective ACK(SACK) functionality has been added

2 Time Stamp and Window Scaling options are added (scaling of 1 is currently 
supported)

3 PAWS (Protection Against Wrapped Sequence numbers) has been added

4 Watermark socket option is now supported.

5 Default TCP Receive Window size has changed from 32k to 64k.
12.2 TCP Bug Fixes
The following bugs are fixed:

Bug #440	TCP Output failures when sending 1 byte pkt
Bug #538	App core goes into indefinite loop when send-q is full
Bug #548	Blocking send() API and SND_TIMEO
Bug #627	tsegq: corner case in head_delete function
Bug #634 	corrupted swp crashes tcp in tseq tail add function
Bug #637 	dupack processing: snd_nxt incremented to huge value
Bug #638 	connect: Missing TCP MSS option in SYN pkt
Bug #639 	Reassembly: tcp doesn't recover even if the expected seqnum is recvd
Bug #640 	Reassembly: inconsistency in tsegqes
Bug #641 	Reassembly: App doesn't get data even when tcp has done reaasembly
Bug #643 	Reassembly: error in trim_front scenario
Bug #644 	Reassembly: tsegqe merging issues
Bug #645 	Delayed ACK timer functionality doesn't work
Bug #656 	Reassembly: adding new tsegqe between existing tsegqe 
Bug #658 	connect( doesn't work
Bug #659 	connect() on Non Blocking socket doesn't work
Bug #670 	TCP Keepalive timer doesn't work in fast path
Bug #682 	Reassembly: corruption in tsegqe 
Bug #685 	Reassembly: Incorrect tsegq_len leading to app trap
Bug #689 	Reassembly: inserting seqnum between existing entries
Bug #693 	TCP Passive Open: ACK with data in SYN_RCVD state
Bug #694 	Reassembly: Handling out of sequence FIN (no data) pkt
Bug #703 	Timestamp option: session resets after a couple of minutes
Bug #726 	ZC app: handing TCP send_q_full condition



16 Changes from release 1.1
---------------------------
This release contains test programs to demonstrate UDP functionality.


17 Changes from release 1.0
---------------------------
1. select() mechanism has been replaced with poll()

2. Limit on maximum number of descriptors has been removed 

3.  MSS options is now controlled through a flag in global-config.h file. By 
default, it is disabled. To enable the MSS options, un-comment the line:
    
#define TCP_USE_MSS

4. TCP stats collection mechanism is added. By default, it is disabled. It can 
be enabled by un-commenting the following line in global-config.h file: 

#define TCP_STATS
      
NOTE: In order to verify ANVL Advanced tests, TCP_USE_MSS must be defined.

5. shutdown() API has been added

6. Direct Network Interface support has been added

7. Changes in cvm_so_send() and cvm_so_write_zc() status reporting:
   If send queue is full and we can't send any data, the errno is set to  
   EAGAIN for Non-Blocking sockets and ENOMEM for Blocking sockets.

8. accept(): 
   ECONNABORTED is not supported
 
9 bind()/connect(): 
  Don't check if the address specified is a valid one. 

10. connect(): 
If an invalid family type is passed, it returns EINVAL instead of EAFNOSUPPORT
 
11. poll():
    If timeout value is NULL, it returns immediately. 
 

