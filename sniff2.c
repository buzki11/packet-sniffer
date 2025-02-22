#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

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
    // Get all available devices
    	if (pcap_findalldevs(&devs, errbuf) == -1) {
        	fprintf(stderr, "Error finding devices: %s\n", errbuf);
        	return 1;
    	}

    // Print the list of devices
    	printf("Available network devices:\n");
    	for (d = devs; d != NULL; d = d->next) {
        	printf("%s - %s\n", d->name, d->description ? d->description : "No description available");
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
        // Your capture code here...

        	pcap_close(handle);
    	} else {
        	fprintf(stderr, "No devices found\n");
        	return 1;
    	}

    // Clean up and free device list
    	pcap_freealldevs(devs);

    	return 0;
}

