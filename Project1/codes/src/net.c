#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    struct iphdr *temp_ptr = &iphdr;
    uint16_t *iphdr_ptr = (uint16_t *)temp_ptr;
    size_t hdr_len = iphdr.ihl * 4;
    uint32_t sum = 0;

    // Calculate the chcksum for the IP header
    while (hdr_len > 1) {
        sum += *iphdr_ptr++;
        hdr_len -= 2;
    }

    // Deal with odd header len
    if (hdr_len) {
	    sum += (*iphdr_ptr) & htons(0xFF00);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer

    // Check the validity of the function arguments
    if (!self || !pkt) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }
    
    // Check if packet length is greater than or equal to the size of am IP header
    if (pkt_len < sizeof(struct iphdr)) {
        fprintf(stderr, "Packet too short for IP header\n");
        return NULL;
    }

    // Cast the packet as an IP header struct
    struct iphdr *iph = (struct iphdr *)pkt;
    // Copy IPV4 header to self->ip4hdr
    memcpy(&self->ip4hdr, pkt, sizeof(struct iphdr));

    // Set the IP source and destination address
    // x_dst_ip and x_src_ip will be the value been store in the header in fmt_net_rep
    inet_ntop(AF_INET, &(iph->saddr), self->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->saddr), self->x_dst_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), self->dst_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), self->x_src_ip, INET_ADDRSTRLEN);

    // Set the protocol number and payload length
    self->pro = (Proto)iph->protocol;
    self->hdrlen = iph->ihl * 4;
    self->plen = ntohs(iph->tot_len) - self->hdrlen;

    // Return a pointer to the payload
    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send
    
    // Check the validity of the function arguments
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }
    
    // Set the source and destination IP addresses in the IP header
    if (inet_pton(AF_INET, self->x_src_ip, &(self->ip4hdr.saddr)) != 1) {
        fprintf(stderr, "Invalid source IP address.\n");
        return NULL;
    }
    
    if (inet_pton(AF_INET, self->x_dst_ip, &(self->ip4hdr.daddr)) != 1) {
        fprintf(stderr, "Invalid destination IP address.\n");
        return NULL;
    }
    
    // Hint 2
    // Set the total length of the IP packet
    self->ip4hdr.tot_len = htons(self->plen + self->hdrlen);
    
    // Calculate the IP header checksum
    self->ip4hdr.check = 0;
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);
    
    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
