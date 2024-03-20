#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		printf("\n");
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet+sizeof(*eth_hdr));
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet+sizeof(*eth_hdr)+sizeof(ip_hdr));
		const u_int8_t* payload = (u_int8_t*)(packet+sizeof(*eth_hdr)+sizeof(*ip_hdr)+sizeof(*tcp_hdr));
		int data_count = header->caplen-(sizeof(*eth_hdr)+sizeof(*ip_hdr)+sizeof(*tcp_hdr)); //전체 크기 - 헤더 = payload
		if(ntohs(eth_hdr->ether_type)==ETHERTYPE_IP){
			if(ip_hdr->ip_p != 6){ //protocol이 6일 때 TCP
				printf("ethernet -> Yes / ipv4 -> Yes / TCP -> No!\n");
				continue;
			}
			printf("Ethernet header's src mac: ");
			for(int i=0; i<6; i++)
			{
				if(i<5) printf("%02x:",eth_hdr->ether_shost[i]);
				else printf("%02x\n",eth_hdr->ether_shost[i]);
				
			}

			printf("Ethernet header's dst mac: ");
			for(int i=0; i<6; i++)
			{
				if(i<5) printf("%02x:",eth_hdr->ether_dhost[i]);
				else printf("%02x\n",eth_hdr->ether_dhost[i]);
				
			}
			printf("\n");

			printf("IP Headers's src ip: ");
			for(int i=0; i<4; i++)
			{
				if(i<3)	printf("%d.",(ip_hdr->ip_src.s_addr>>8*i)&0xff);
				else printf("%d\n",(ip_hdr->ip_src.s_addr>>8*i)&0xff);
			}

			printf("IP Headers's dst ip: ");
			for(int i=0; i<4; i++)
			{
				if(i<3)	printf("%d.",(ip_hdr->ip_dst.s_addr>>8*i)&0xff);
				else printf("%d\n",(ip_hdr->ip_dst.s_addr>>8*i)&0xff);
				
			}
			printf("\n");
			
			printf("TCP Header's src port: %d\n", ntohs(tcp_hdr->th_sport));
			printf("TCP Header's dst port: %d\n", ntohs(tcp_hdr->th_dport));
			printf("\n");

			printf("Payload(Data, MAX 20bytes): ");
			if(data_count <= 0) continue;
			else if(data_count < 20)
			{
				for(int i=0; i<data_count; i++)
				{
					printf("%02x ",*(payload+i));
				}	
				printf("\n");
			}
			else
			{
				for(int i=0; i<20; i++)
				{
					printf("%02x ",*(payload+i));
				}	
				printf("\n");
			}
			printf("\n");


		}


	}

	pcap_close(pcap);
}
