
#include <stdlib.h>
#include <threads.h>

#include <pcap.h>

void handler(unsigned char* object, const struct pcap_pkthdr* header, const unsigned char* data)
{
	fwrite(header, sizeof(struct pcap_pkthdr), 1, stdout);
	fwrite(data, header->caplen, 1, stdout);

	fflush(stdout);
}

int capture(void* handle)
{
	pcap_loop(handle, 0, handler, 0);
	return 0;
}

int inject(void* handle)
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
	fprintf(stderr, "Network Interface Concatenation Tool.\n\n");

	char buffer[PCAP_ERRBUF_SIZE];

	if(argc != 2)
	{
		fprintf(stderr, "\tUsage:\n");
		fprintf(stderr, "\t\t %s <interface>\n", argv[0]);
		fprintf(stderr, "\n\tInterfaces:\n");

		pcap_if_t *devices = 0, *device = 0;
		if(pcap_findalldevs(&devices, buffer))
		{
			fprintf(stderr, "\t\t%s\n", buffer);
			return -1;
		}

		device = devices;
		while(device)
			fprintf(stderr, "\t\t%-50s - %s\n", device->name, device->description), device = device->next;
		pcap_freealldevs(devices);

		return 0;
	}

	pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, buffer);
	if(!handle)
	{
		fprintf(stderr, "%s\n", buffer);
		return -1;
	}

	thrd_t captureThread, injectThread;
	thrd_create(&captureThread, capture, handle);
	thrd_create(&injectThread, inject, handle);

	thrd_join(injectThread, 0);

	pcap_breakloop(handle);
	pcap_close(handle);

	thrd_join(captureThread, 0);

	fprintf(stderr, "\n");
	fflush(stdout);

	return 0;
}
