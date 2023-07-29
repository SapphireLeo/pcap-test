#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define ETHER_ADDR_LEN 14
#define ONLY_TCP true // debug option: whether program captures only tcp packet.
#define PAYLOAD_SIZE 10

/* define characters */ 
#define BLANK ' '
#define VLINE '|'
#define HLINE '-'

/* define block size of display(print) */
#define TYPE_BLOCK_SIZE 13
#define SRC_BLOCK_SIZE 19
#define DEST_BLOCK_SIZE 19
#define PAYLOAD_BLOCK_SIZE 39

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

/* ethernet header structure */
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

/* ip header structure (Little Endian) */
struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    u_int8_t ip_tos;
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/* tcp header structure (Litle Endian) */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

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

/* function prototype */

/* basic display function  */
void print_line();
void print_double_line();
void print_block();
int get_left_padding(int block_size, int string_size);
int get_right_padding(int block_size, int string_size);

/* packet parsing function */
void parse_mac_address();
void parse_ip_address();

/* advanced display function */
void print_all_blocks();
void print_program_header();
void print_ethernet(struct libnet_ethernet_hdr* eth_hdr);
void print_ip(struct libnet_ipv4_hdr* ip_hdr);
void print_tcp(struct libnet_tcp_hdr* tcp_hdr);
void print_payload();


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
		
		/* parse every header information and packet header */
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*) packet;
		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*) (packet + ETHER_ADDR_LEN);
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*) (packet + ETHER_ADDR_LEN + (ip_hdr -> ip_hl) * 4);

		/* get packet payload.
		 * data offset can be derived from ip header length and tcp header length.
		 * data size can be computed by substract ip header length + tcp header length from ip total packet length. */
		const u_char* payload = packet + ETHER_ADDR_LEN + (ip_hdr -> ip_hl) * 4 + (tcp_hdr -> th_off) * 4;
		int payload_length = ntohs(ip_hdr -> ip_len) - (ip_hdr -> ip_hl) * 4 - (tcp_hdr -> th_off) * 4;

#if (ONLY_TCP)
		/* drop packet if it is not tcp packet. */
		if(ip_hdr -> ip_p != 0x06){
			continue;
		}
#endif		
		/* display captured bytes */
		print_double_line();
		printf(" %u bytes captured (TCP packet)\n", header->caplen);
		
		/* display packet analysis in a form of table */
		print_program_header();			
		print_ethernet(eth_hdr);
		print_ip(ip_hdr);
		print_tcp(tcp_hdr);
		print_payload(payload, payload_length);

		printf("\n");
	}

	pcap_close(pcap);
}

/* display chacracter as many as input number */
void print_character(char character, int num){
	for(int i=0; i<num; i++){
		printf("%c", character);
	}
}

/* display header of packet analysis table */
void print_program_header(){
	print_line();
        print_character(VLINE, 1);
	
	print_block(TYPE_BLOCK_SIZE, "TYPE");	
	print_character(VLINE, 1);
	
	print_block(SRC_BLOCK_SIZE, "SOURCE");
	print_character(VLINE, 1);
	
	print_block(DEST_BLOCK_SIZE, "DESTINATION");
	print_character(VLINE, 1);
	
	printf("\n");
	print_double_line();
}

/* get size of display padding(left)  from table block size and string size. */
int get_left_padding(int block_size, int string_size){
	return (block_size - string_size) / 2;
}

/* get size of display padding(right) from table block size and string size. */
int get_right_padding(int block_size, int string_size){
	return (block_size - string_size) / 2 + (block_size - string_size) % 2;
}

/* display block according to block size and string. */
void print_block(int block_size, const char* string){
	print_character(BLANK, get_left_padding(block_size, strlen(string)));
	printf("%s", string);	
	print_character(BLANK, get_right_padding(block_size, strlen(string)));
}

/* display a line and make a new line. */
void print_line(){
	print_character(HLINE, TYPE_BLOCK_SIZE + SRC_BLOCK_SIZE + DEST_BLOCK_SIZE + 4);
	printf("\n");
}

/* display double line and make a new line. */
void print_double_line(){
	print_character('=', TYPE_BLOCK_SIZE + SRC_BLOCK_SIZE + DEST_BLOCK_SIZE + 4);
	printf("\n");
}

/* parse MAC address from 1byte integer array. */
void parse_mac_address(char* buffer, u_int8_t* m){
        sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* parse IP address from 4byte integer in network byte order. */
void parse_ip_address(char* buffer, u_int32_t ip){
	ip = ntohl(ip);
	sprintf(buffer, "%d.%d.%d.%d", ip >> 24, ip << 8 >> 24, ip << 16 >> 24, ip << 24 >> 24);
}

/* parse TCP port number from 2byte integer in network byte order. */
void parse_tcp_address(char* buffer, u_int16_t port){
	sprintf(buffer, "%d", ntohs(port));
}

/* display a row of packet analysis table. */
/* the row displayes data type, source address(port) and destination address(port) */
void print_all_blocks(const char* type, const char* src, const char* dest){
	print_character(VLINE, 1);

        print_block(TYPE_BLOCK_SIZE, type);
	print_character(VLINE, 1);

	print_block(SRC_BLOCK_SIZE, src);
	print_character(VLINE, 1);

	print_block(DEST_BLOCK_SIZE, dest);
	print_character(VLINE, 1);

        printf("\n");
	print_line();
}

/* display ethernet row of packet analysis table. */
void print_ethernet(struct libnet_ethernet_hdr* eth_hdr){
	char type[TYPE_BLOCK_SIZE] = "MAC address";
	char src[SRC_BLOCK_SIZE];
	char dest[DEST_BLOCK_SIZE];

	parse_mac_address(src, eth_hdr -> ether_shost);
	parse_mac_address(dest, eth_hdr -> ether_dhost);
	
	print_all_blocks(type, src, dest);
}

/* display IP row of packet analysis table. */
void print_ip(struct libnet_ipv4_hdr* ip_hdr){
	char type[TYPE_BLOCK_SIZE] = "IP address";
	char src[SRC_BLOCK_SIZE];
	char dest[DEST_BLOCK_SIZE];

	parse_ip_address(src, ip_hdr -> ip_src.s_addr);
	parse_ip_address(dest, ip_hdr -> ip_dst.s_addr);
	
	print_all_blocks(type, src, dest);
}

/* display TCP row of packet analysis table. */
void print_tcp(struct libnet_tcp_hdr* tcp_hdr){
	char type[TYPE_BLOCK_SIZE] = "TCP port";
	char src[SRC_BLOCK_SIZE];
	char dest[DEST_BLOCK_SIZE];

	parse_tcp_address(src, tcp_hdr -> th_sport);
	parse_tcp_address(dest, tcp_hdr -> th_dport);
	
	print_all_blocks(type, src, dest);
}

/* display payload row of packet analysis table. */
void print_payload(const u_char* payload, int payload_length){
	char payload_string[PAYLOAD_SIZE * 2 + 1] = "";

	for (int i = 0; i < PAYLOAD_SIZE + 1 && i < payload_length; i++){
		sprintf(payload_string + i * 2, "%02x", payload[i]);
	}

	if (payload_length == 0){
		strcpy(payload_string, "No Data");
	}

	/* payload row has only two columns(cells). */
	print_character(VLINE, 1);
	print_block(TYPE_BLOCK_SIZE, "Payload");
	print_character(VLINE, 1);

	print_block(PAYLOAD_BLOCK_SIZE, payload_string);
	print_character(VLINE, 1);
	printf("\n");
	print_line();
}	
