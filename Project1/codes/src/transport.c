#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

void swap(uint32_t *a, uint32_t *b) {
	uint32_t temp = *a;
	*a = *b;
	*b = temp;
}

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    
    // Calculate the TCP pseudo-header checksum
    uint32_t sum = 0;
    sum += (iphdr.saddr >> 16) & 0xFFFF; 
    sum += iphdr.saddr & 0xFFFF;         
    sum += (iphdr.daddr >> 16) & 0xFFFF; 
    sum += iphdr.daddr & 0xFFFF;         
    sum += htons(IPPROTO_TCP);
    uint16_t tcphdr_len = tcphdr.th_off * 4;
    uint16_t tcp_len = tcphdr_len + plen;
    sum += htons(tcp_len);

    // Create a buffer to store the TCP header and payload
    // Then calculate them together in the buffer
    uint8_t *buf = (uint8_t *)malloc((tcphdr_len + plen) * sizeof(uint8_t)); 
    memcpy(buf, &tcphdr, tcphdr_len); 
    memcpy(buf + tcphdr_len, pl, plen);
    uint16_t *pl_ptr = (uint16_t *)buf;
    while (tcp_len > 1) {
        sum += *pl_ptr++;
        tcp_len -= 2;
    }

    // Deal with odd header len
    if (tcp_len) {
	    sum += (*pl_ptr) & htons(0xFF00);
    }

    while (sum >> 16) {
	    sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the one's complement of the sum to get the final checksum
    return ~sum; 
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP

    // Check the validity of the function arguments
    if (!net || !self || !segm) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    // Check if the segment length is valid
    if (segm_len < sizeof(struct tcphdr)) {
        fprintf(stderr, "Invalid TCP segment length.\n");
        return NULL;
    }
    
    // Copy TCP header from the segment
    memcpy(&self->thdr, segm, sizeof(struct tcphdr));
    
    // Calculate TCP header length
    self->hdrlen = self->thdr.doff * 4;
    if (self->hdrlen < sizeof(struct tcphdr)) {
        fprintf(stderr, "Invalid TCP header length (%d).\n", self->hdrlen);
        return NULL;
    }

    // Calculate the length of TCP payload
    self->plen = segm_len - self->hdrlen;
    if (self->plen < 0) {
        fprintf(stderr, "Invalid TCP payload length.\n");
        return NULL;
    }

    // Copy TCP payload from the segment
    self->pl = (uint8_t *)malloc(self->plen * sizeof(uint8_t));
    memcpy(self->pl, segm + self->hdrlen, self->plen);
    
    // Fill up expect value which will be used in fmt_tcp_rep
    if (strcmp(net->dst_ip, net->x_src_ip) == 0 && self->plen != 0) {
        self->x_tx_seq = ntohl(self->thdr.th_ack);
        self->x_tx_ack = ntohl(self->thdr.th_seq) + self->plen;
        self->x_src_port = ntohs(self->thdr.th_dport);
        self->x_dst_port = ntohs(self->thdr.th_sport);
    }

    // Return TCP payload
    return self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
    
    // Hint 2
    // Fill up the TCP header
    self->thdr.th_seq = htonl(self->x_tx_seq);
    self->thdr.th_ack = htonl(self->x_tx_ack);
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);

    if (dlen == 0) {
        self->thdr.psh = 0;
    }
    
    // Copy data to TCP payload
    memcpy(self->pl, data, dlen);

    // Calculate the TCP header checksum
    self->thdr.check = 0;
    self->thdr.check = cal_tcp_cksm(iphdr, self->thdr, self->pl, dlen);

    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

