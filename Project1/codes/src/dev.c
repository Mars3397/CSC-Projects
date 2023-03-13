#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "replay.h"
#include "transport.h"

inline static int get_ifr_mtu(struct ifreq *ifr)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return ifr->ifr_mtu;
}

inline static struct sockaddr_ll init_addr(char *name)
{
    struct sockaddr_ll addr;
    bzero(&addr, sizeof(addr));

    // [TODO]: Fill up struct sockaddr_ll addr which will be used to bind in func set_sock_fd

    /*struct sockaddr_ll {
        unsigned short sll_family;   // Always AF_PACKET
        unsigned short sll_protocol; // Physical-layer protocol
        int            sll_ifindex;  // Interface number
        unsigned short sll_hatype;   // ARP hardware type
        unsigned char  sll_pkttype;  // Packet type
        unsigned char  sll_halen;    // Length of address
        unsigned char  sll_addr[8];  // Physical-layer address
    };*/

    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);       // htons(ETH_P_ALL) -> all protocols are received
    addr.sll_ifindex = if_nametoindex(name);    // if_nametoindex() map ifname to the index of the network interface

    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    return addr;
}

inline static int set_sock_fd(struct sockaddr_ll dev)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    bind(fd, (struct sockaddr *)&dev, sizeof(dev));

    return fd;
}

void fmt_frame(Dev *self, Net net, Esp esp, Txp txp)
{
    // [TODO]: store the whole frame into self->frame
    // and store the length of the frame into self->framelen

    // Declare a 8 bit pointer point to the memory location of self->frame
    uint8_t *frame_ptr = self->frame;

    // copy memory content to frame according to the order of trasport mode
    size_t offset = 0;
    memcpy(frame_ptr + offset, self->linkhdr, LINKHDRLEN);      offset += LINKHDRLEN;
    memcpy(frame_ptr + offset, &net.ip4hdr, net.hdrlen);        offset += net.hdrlen;
    memcpy(frame_ptr + offset, &esp.hdr, sizeof(EspHeader));    offset += sizeof(EspHeader);
    memcpy(frame_ptr + offset, &txp.thdr, txp.hdrlen);          offset += txp.hdrlen;
    memcpy(frame_ptr + offset, txp.pl, txp.plen);              offset += txp.plen;
    memcpy(frame_ptr + offset, &esp.pad, esp.tlr.pad_len);	offset += esp.tlr.pad_len;
    memcpy(frame_ptr + offset, &esp.tlr, sizeof(EspTrailer));   offset += sizeof(EspTrailer);
    memcpy(frame_ptr + offset, esp.auth, esp.authlen);         offset += esp.authlen;

    // Set framelen
    self->framelen = offset;
}

ssize_t tx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = sendto(self->fd, self->frame, self->framelen,
                0, (struct sockaddr *)&self->addr, addrlen);

    if (nb <= 0) perror("sendto()");

    return nb;
}

ssize_t rx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = recvfrom(self->fd, self->frame, self->mtu,
                  0, (struct sockaddr *)&self->addr, &addrlen);
    if (nb <= 0)
        perror("recvfrom()");

    return nb;
}

void init_dev(Dev *self, char *dev_name)
{
    if (!self || !dev_name || strlen(dev_name) + 1 > IF_NAMESIZE) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    self->mtu = get_ifr_mtu(&ifr);

    self->addr = init_addr(dev_name);
    self->fd = set_sock_fd(self->addr);

    self->frame = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    self->framelen = 0;

    self->fmt_frame = fmt_frame;
    self->tx_frame = tx_frame;
    self->rx_frame = rx_frame;

    self->linkhdr = (uint8_t *)malloc(LINKHDRLEN);
}
