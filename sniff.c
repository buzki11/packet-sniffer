#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <net/ethernet.h>

#define IP 0x0800
#define ARP 0x806
#define RARP 0x035
#define VLAN 0x8100
#define IPV6 0x86dd

void print_ethertype(struct ether_header eth_hdr);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet);

int main() {
	system("clear");
   	pcap_if_t *devs;
    	pcap_if_t *d;
    	char errbuf[PCAP_ERRBUF_SIZE];
	char ip[13];
	char subnet_mask[13];
	bpf_u_int32 ip_raw; /* IP address as an integer */
	bpf_u_int32 subnet_raw; /* Subnet mask as integer */
	int lookup_return_code;
	struct in_addr address; /*Used for IP and Subnet */
	const u_char *packet;
	int timeout_limit = 10000; /* In milliseconds */
	struct pcap_pkthdr packet_header;
    // Get all available devices
    	if (pcap_findalldevs(&devs, errbuf) == -1) {
        	fprintf(stderr, "Error finding devices: %s\n", errbuf);
        	return 1;
    	}
	printf("#####################################\n\n");
    // Print the list of devices
    	printf("Available network devices:\n");
    	for (d = devs; d != NULL; d = d->next) {
        	printf("\t%s - %s\n", d->name, d->description ? d->description : "No description available");
    	}
	printf("\n######################################\n\n");
    // If you want to use the first device, select the first one in the list
    	if (devs != NULL) {
        	pcap_t *handle = pcap_open_live(devs->name, BUFSIZ, 1, 1000, errbuf);
        	if (handle == NULL) {
            		fprintf(stderr, "Error opening device: %s\n", errbuf);
            		pcap_freealldevs(devs);
            		return 1;
        	}
        	printf("Capturing on device: %s\n", devs->name);
		lookup_return_code = pcap_lookupnet(devs->name,
						    &ip_raw,
						    &subnet_raw,
						    errbuf);
		if (lookup_return_code ==-1){
			printf("%s\n", errbuf);
			return 1;
		}
		address.s_addr=ip_raw;
		strcpy(ip, inet_ntoa(address));
		if(ip==NULL){
			perror("inet_ntoa 1");
			return 1;
		}
		address.s_addr=subnet_raw;
		strcpy(subnet_mask, inet_ntoa(address));
		if(subnet_mask==NULL){
			perror("inet_ntoa 2");
			return 1;
		}
		printf("IP address: %s\n", ip);
		printf("Subnet Mask: %s\n", subnet_mask);
        	pcap_close(handle);
    	} else {
        	fprintf(stderr, "No devices found\n");
        	return 1;
    	}

	/* Packet Sniffing Code here...*/

	printf("\n*******************\n\n");
	pcap_t *handle=pcap_open_live(devs->name, BUFSIZ, 0, timeout_limit, errbuf);
	if(handle==NULL){
		fprintf(stderr, "Could not open device %s: %s\n", devs->name, errbuf);
		return 2;
	}
	pcap_loop(handle, 0, my_packet_handler, NULL);

    // Clean up and free device list
    	pcap_freealldevs(devs);

    	return 0;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet){
	struct ether_header *eth_hdr;
	eth_hdr=(struct ether_header *) packet;
	print_ethertype(*eth_hdr);
	print_packet_info(packet, *packet_header);
	return;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header){
	printf("Packet capture length: %d\n", packet_header.caplen);
	printf("Packet total length %d\n", packet_header.len);
	printf("----------------------------\n\n");
}

void print_ethertype(struct ether_header eth_hdr){
	printf("Type: ");
	switch(ntohs(eth_hdr.ether_type)){
	  case IP:
	    printf("IP\n");
	    break;
	  case ARP:
	    printf("ARP\n");
	    break;
	  case IPV6:
	    printf("IPV6\n");
	    break;
	  case RARP:
	    printf("RARP\n");
	    break;
	}
}
