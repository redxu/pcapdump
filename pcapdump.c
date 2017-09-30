#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include "qqlog.h"


typedef struct pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;    
	uint32_t sigfigs;   
	uint32_t snaplen;   
	uint32_t linktype;  
} pcap_file_header;


typedef struct timestamp{  
    uint32_t tv_sec;  
    uint32_t tv_usec;  
} timestamp;  
   
typedef struct pcap_pkthdr{  
    timestamp ts;  
    uint32_t capture_len;  
    uint32_t len;
} pcap_pkthdr;

//数据帧头  
typedef struct frame_header  
{ 
	uint8_t  dstmac[6]; 	//目的MAC地址  
	uint8_t  srcmac[6]; 	//源MAC地址  
	uint16_t frame_type;    //帧类型  
} frame_header; 

/* 4 bytes IP address */
typedef struct ip_address
{
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;
} ip_address;

/* IPv4 header */
typedef struct ip_header
{
	uint8_t	 ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	uint8_t	 tos;			// Type of service 
	uint16_t tlen;			// Total length 
	uint16_t identification; // Identification
	uint16_t flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	uint8_t	 ttl;			// Time to live
	uint8_t	 proto;			// Protocol
	uint16_t crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	uint32_t	op_pad;			// Option + Padding
} ip_header;


typedef struct tcp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t doff:4,hlen:4,fin:1,syn:1,rst:1,psh:1,ack:1,urg:1,ece:1,cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} tcp_header;


void showUsage(char** argv) {
	printf("Usage: %s pcappath localip\n", argv[0]);
}


uint32_t ip2long(const char* ip) {
	uint32_t a, b, c, d; 
	sscanf(ip, "%u.%u.%u.%u", &d, &c, &b, &a); 
	return ((a << 24) | (b << 16) | (c << 8) | d);
}


void long2ip(uint32_t ip, char buf[]){ 
	int i = 0; 
	uint8_t tmp[4] = {0}; 

	for(i = 0; i < 4; i++){ 
		tmp[i] = ip & 0xff; 
		ip = ip >> 8; 
	} 
	sprintf(buf, "%u.%u.%u.%u", tmp[0], tmp[1], tmp[2], tmp[3]); 
}


int main(int argc, char** argv) {
	FILE* file;
	pcap_file_header pfh;
	pcap_pkthdr      pktheader;
	frame_header     frameheader;
	ip_header        ipheader;
	tcp_header		 tcpheader;
	uint8_t buffer[8196];
	int size, pkt_size, pkt_idx;
	long fpos;
	uint16_t sport, dport;
	struct tm *ltime;
	char timestr[16];
	uint32_t targetip;

	if(argc != 3) {
		showUsage(argv);
		return -1;
	}

	file = fopen(argv[1], "rb");
	if(file == NULL) {
		printf("file %s not exit!\n", argv[1]);
		return -1;
	}

	targetip = ip2long(argv[2]);

	size = fread(&pfh, 1, sizeof(pfh), file);
	if(size != sizeof(pfh)) {
		printf("read pfh failed! %d\n", size);
		return -1;
	}

	//unlink("./qqpacket.txt");
	pkt_idx = 0;
	while(1) {
		memset(&pktheader, 0, sizeof(pktheader));
		memset(&frameheader, 0, sizeof(frameheader));
		memset(&ipheader, 0, sizeof(ipheader));
		memset(&tcpheader, 0, sizeof(tcpheader));
		memset(&buffer, 0, sizeof(buffer));

		if(feof(file)) {
			break;
		}

		pkt_idx++;

		//报头
		size = fread(&pktheader, 1, sizeof(pktheader), file);
		if(size != sizeof(pktheader)) {
			printf("read pkt_header failed!\n");
			break;
		}

		fpos = ftell(file) + pktheader.capture_len;

		//帧头
		size = fread(&frameheader, 1, sizeof(frameheader), file);
		if(size != sizeof(frameheader)) {
			printf("read frame_header failed!\n");
			break;
		}
		//IPV4 only
		if(frameheader.frame_type != 8) {
			fseek(file, fpos, SEEK_SET);
			continue;
		}

		//ip头
		size = fread(&ipheader, 1, sizeof(ipheader), file);
		if(size != sizeof(ipheader)) {
			printf("read ip_header failed!\n");
			break;
		}
		//ip头修正
		fseek(file, (ipheader.ver_ihl & 0xf) * 4 - size, SEEK_CUR);

		if(ipheader.proto != 6) {
			fseek(file, fpos, SEEK_SET);
			continue;
		}

		//判断协议过滤tcp

		//tcp头
		size = fread(&tcpheader, 1, sizeof(tcpheader), file);
		if(size != sizeof(tcpheader)) {
			printf("read tcp_header failed!\n");
			break;
		}
		//tcp头修正
		fseek(file, tcpheader.hlen*4 - size, SEEK_CUR);

		//计算pkt_len
		pkt_size = fpos - ftell(file);
		size = fread(buffer, 1, pkt_size, file);
		if(size != pkt_size) {
			printf("read tcp_body failed! size=%d pkt_size=%d\n", size, pkt_size);
			break;
		}

		if(pkt_size == 0)
			continue;

		//过滤规则,在这修改
		//端口规则
		sport = ntohs(tcpheader.src_port);
		dport = ntohs(tcpheader.dst_port);
		//IP规则183.36.108.161 0xB7246ca1
		uint32_t sip = *(uint32_t *)&ipheader.saddr;
		uint32_t dip = *(uint32_t *)&ipheader.daddr;
		if(sip != targetip && dip != targetip) {
			continue;
		}
		

		uint32_t local_tv_sec = pktheader.ts.tv_sec;
		ltime = localtime((time_t *)&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		char filename[1024];
		if(sip == targetip) {
			long2ip(dip, filename);
		}
		else {
			long2ip(sip, filename);
		}
		strcat(filename, ".txt");

		qq_log(filename, "[%d]%s %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
			pkt_idx,
			timestr,
			ipheader.saddr.byte1,
			ipheader.saddr.byte2,
			ipheader.saddr.byte3,
			ipheader.saddr.byte4,
			sport,
			ipheader.daddr.byte1,
			ipheader.daddr.byte2,
			ipheader.daddr.byte3,
			ipheader.daddr.byte4,
			dport
		);
		
		qq_log_buf(filename, buffer, pkt_size, "");
	}


	fclose(file);
	return 0;
}

