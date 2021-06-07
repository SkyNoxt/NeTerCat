
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>

void handler(unsigned char* object, const struct pcap_pkthdr* header, const unsigned char* data)
{
	fwrite(header, sizeof(struct pcap_pkthdr), 1, stdout);
	fwrite(data, header->caplen, 1, stdout);

	fflush(stdout);
}

void* capture(void* handle)
{
	pcap_loop(handle, 0, handler, 0);
	return 0;
}

void* inject(void* handle)
{
	struct pcap_pkthdr header;
	void* data;

	fread(&header, sizeof(struct pcap_pkthdr), 1, stdin);
	while(!feof(stdin))
	{
		data = malloc(header.caplen);
		fread(data, header.caplen, 1, stdin);

		pcap_inject(handle, data, header.caplen);
		free(data);

		fread(&header, sizeof(struct pcap_pkthdr), 1, stdin);
	}
	return 0;
}

int main(int argc, char** argv)
{
	fprintf(stderr, "Network Interface Concatenation Tool.\n");
	fprintf(stderr, "\n");

	if(argc != 2)
	{
		fprintf(stderr, "\tUsage:\n");
		fprintf(stderr, "\t\t %s <interface>\n", argv[0]);
		fprintf(stderr, "\n");

		return 0;
	}

	char buffer[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, buffer);
	if(!handle)
	{
		fprintf(stderr, "%s\n", buffer);
		return -1;
	}

	pthread_t captureThread, injectThread;
	pthread_create(&captureThread, NULL, capture, handle);
	pthread_create(&injectThread, NULL, inject, handle);

	pthread_join(injectThread, 0);

	pcap_breakloop(handle);
	pcap_close(handle);

	pthread_join(captureThread, 0);

	fprintf(stderr, "\n");
	fflush(stdout);

	return 0;
}

