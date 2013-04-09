#include <stdio.h>
#include <WinSock2.h>

// ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN 6

// ethernet headers are 14 bytes
#define ETHER_SIZE 14

// ethernet header
typedef struct ethernet_header {
	// destination host address
	u_char dhost[ETHER_ADDR_LEN];

	// source host address
	u_char shost[ETHER_ADDR_LEN];

	// type (IP, ARP, etc)
	u_short type;
} ethernet_header;

typedef struct ip_header {
	// version (4 bits) + header length (4 bits)
	u_char ver_ihl;
	
	// type of service
	u_char tos;
	
	// total length
	u_short tlen;
	
	// identification
	u_short identification;
	
	// flags (3 bits) + fragment offset (13 bits)
	u_short flags_fo;
	
	// time to live
	u_char ttl;
	
	// protocol
	u_char proto;
	
	// checksum
	u_short crc;

	struct {
		// source address
		in_addr ip_src;

		// destination address
		in_addr ip_dst;
	};

	// options + padding
	u_int op_pad;
} ip_header;

// tcp header
typedef struct tcp_header {
	// source port
	u_short sport;

	// destination port
	u_short dport;

	// sequence number
	u_long seq;

	// acknowledgement number
	u_long ack;

	// data-offset
	u_char off;

	// flags
	u_char flags;

	// window
	u_short win;

	// checksum
	u_short crc;

	// urgent
	u_short urg;
} tcp_header;

// udp header
typedef struct udp_header {
	// source port
	u_short sport;

	// destination port
	u_short dport;

	// datagram length
	u_short len;

	// checksum
	u_short crc;
} udp_header;
