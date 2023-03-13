#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
    
    // Declare sock_fd and sadb_msg for SADB_DUMP
    int sock_fd;
    struct sadb_msg msg = {
        .sadb_msg_version = PF_KEY_V2,
        .sadb_msg_type = SADB_DUMP,
        .sadb_msg_errno = 0,
        .sadb_msg_satype = type,
        .sadb_msg_len = sizeof(struct sadb_msg) / sizeof(uint64_t),
        .sadb_msg_reserved = 0,
        .sadb_msg_seq = 0,
        .sadb_msg_pid = getpid(),
    };

    // Create a PF_KEY socket
    sock_fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    if (sock_fd < 0) {
        perror("socket");
        return;
    }

    // Send the SADB_DUMP message to the kernel
    size_t l = write(sock_fd, &msg, sizeof(struct sadb_msg)); 
    if (l < 0) {
        perror("write");
        close(sock_fd);
        return;
    }

    // Receive the SADB_DUMP message response from the kernel
    char buf[1024];
    ssize_t len = read(sock_fd, &buf, 1024);
    if (len < 0) {
        perror("read");
        close(sock_fd);
        return;
    }

    // Parse the SADB_DUMP response to retrieve the authentication key
    struct sadb_ext *ext = (struct sadb_ext *)(buf + 16);
    while ((char *)ext < buf + 216) {
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            struct sadb_key *key_ext = (struct sadb_key *)ext;
            memcpy(key, (char *)key_ext + sizeof(struct sadb_key), key_ext->sadb_key_bits / 8);
            break;
        }
        ext += ext->sadb_ext_len * 2;
    }

    close(sock_fd);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    if (!self) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }
    
    // Calculate the length of the padding needed and store in ESP trailer
    self->tlr.pad_len = (4 - (self->plen + sizeof(EspTrailer)) % 4);

    // Allocate memory for the padding and set it with 0102...0n
    uint8_t pad_ptr[self->tlr.pad_len];
    for (int i = 1; i <= self->tlr.pad_len; i++) {
	    memset(&pad_ptr[i - 1], (uint8_t)(i), 1);
    }
    memcpy(&self->pad, pad_ptr, self->tlr.pad_len);

    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb
    memcpy(buff, &self->hdr, sizeof(EspHeader));        nb += sizeof(EspHeader);
    memcpy(buff + nb, self->pl, self->plen);            nb += self->plen;
    memcpy(buff + nb, &self->pad, self->tlr.pad_len);   nb += self->tlr.pad_len;
    memcpy(buff + nb, &self->tlr, sizeof(EspTrailer));  nb += sizeof(EspTrailer);
    
    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }
	
    self->authlen = ret;

    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP

    // Check the validity of the function arguments
    if (!self || !esp_pkt) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    // Check if the packet length is valid
    if (esp_len < sizeof(EspHeader) + sizeof(EspTrailer)) {
        fprintf(stderr, "Invalid ESP packet length.\n");
        return NULL;
    }

    // Copy ESP header from the packet
    memcpy(&self->hdr, esp_pkt, sizeof(EspHeader));
    esp_pkt += sizeof(EspHeader);
    esp_len -= sizeof(EspHeader);

    // Copy ESP trailer from the packet
    memcpy(&self->tlr, esp_pkt + esp_len - sizeof(EspTrailer) - HMAC96AUTHLEN, sizeof(EspTrailer));

    // Copy ESP padding from the packet
    memcpy(self->pad, esp_pkt + esp_len - HMAC96AUTHLEN - sizeof(EspTrailer) - self->tlr.pad_len, self->tlr.pad_len);
    
    // Get ESP payload length from the padding length field in the trailer
    self->plen = esp_len - HMAC96AUTHLEN - sizeof(EspTrailer) - self->tlr.pad_len;
    // Copy ESP payload from the packet
    memcpy(self->pl, esp_pkt, self->plen);

    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)

    // The value of "next" in the ESP trailer indicates the protocol that 
    // should follow the ESP protocol (eg. ICMP, TCP)
    self->tlr.nxt = p;

    // Header
    // -------------------------
    self->hdr.seq = htonl(esp_hdr_rec.seq + 1);
    esp_hdr_rec.seq += 1;
    self->hdr.spi = esp_hdr_rec.spi;

    return self;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
