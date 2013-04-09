#include <stdio.h>
#include <pcap.h>

// columns for a single row in each "block" (hex & ascii are "individual" blocks)
#define LINE_LENGTH 16

pcap_t *open_file(char *);

void read_packet(const struct pcap_pkthdr *, const u_char *);

const char *timestamp(struct timeval);