#include <stdio.h>
#include <pcap.h>

pcap_t *open_file(char *);
void read_loop(u_char *, const struct pcap_pkthdr  *, const u_char *);

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("usage: %s file.pcap", argv[0]);
		return -1;
	}

	// open the capture-file
	pcap_t *fp = open_file(argv[1]);
	if (fp == NULL) return -1;

	// call the pcap-loop-dispatcher to loop through the input file to read each packet
	pcap_loop(fp, 0, read_loop, NULL);

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

void read_loop(u_char *unused, const struct pcap_pkthdr *header, const u_char *packet_data) {
	// print initial packet info
	printf("Packet: %ld:%ld (len: %ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
}