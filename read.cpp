#include <stdio.h>
#include <pcap.h>
#include "read.h"
#include "packet.h"


int main(int argc, char **argv) {
	if (argc != 2) {
		printf("usage: %s file.pcap", argv[0]);
		return -1;
	}

	// open the capture-file
	pcap_t *fp = open_file(argv[1]);
	if (fp == NULL) return -1;

	// read through all of the packets in the file
	int packet_count = 0;
	const unsigned char *packet;
	struct pcap_pkthdr header;
	while ((packet = pcap_next(fp, &header)) != NULL) {
		read_packet(&header, packet);
		packet_count++;
	}
	printf("Total Packets: %d", packet_count);

	// close the file
	pcap_close(fp);
	return 0;
}

pcap_t *open_file(char *filename) {
	pcap_t *fp;
	char errorBuffer[PCAP_ERRBUF_SIZE];

	if ((fp = pcap_open_offline(filename, errorBuffer)) == NULL) {
		fprintf(stderr, "\nUnable to open the capture file %s.\n", filename);
		return NULL;
	}
	return fp;
}

void read_packet(const struct pcap_pkthdr *header, const u_char *packet) {
	// print packet info
	printf("Packet: %s (length: %ld bytes)\n", timestamp(header->ts), header->len);

	// print the packet
	int i = 0, eol = LINE_LENGTH - 1;
	for (; i < header->caplen; i++) {
		printf("%.2x ", packet[i]);

		if ((i % LINE_LENGTH) == eol) {
			// do an ascii-dump of the data too
			printf("   ");
			for (int j = (i - eol); j <= i; j++) printf("%.2c ", isprint(packet[j]) ? packet[j] : '.');
			printf("\n");
		}
	}
	// if the packet doesn't end on an interval of LINE_LENGTH, don't forget to print the rest of the ascii-data
	if ((i % LINE_LENGTH) != 0) {
		printf("%*s" "%s", (LINE_LENGTH - (i % LINE_LENGTH)) * 3, " ", "   ");
		for (int j = (i - eol); j <= i; j++) printf("%.2c ", isprint(packet[j]) ? packet[j] : '.');
	}
	printf("\n\n");	
}

const char *timestamp(struct timeval tv) {
	static char timestamp_buffer[64], full_buffer[64];

	// the .tv_sec is the timestamp portion; convert that to local-time and make printable
	time_t time = tv.tv_sec;
	struct tm *timeTm = localtime(&time);
	strftime(timestamp_buffer, sizeof(timestamp_buffer), "%Y-%m-%d %H:%M:%S", timeTm);

	// add the milliseconds (.tv_usec) and return
	_snprintf(full_buffer, sizeof(full_buffer), "%s.%03d", timestamp_buffer, (tv.tv_usec / 1000) + 1);
	return full_buffer;
}