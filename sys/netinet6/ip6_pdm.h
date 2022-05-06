/*-
 * Copyright (c) 2017 Inside Products, Inc.
 * All rights reserved.
 *
 * Portions of this software were developed by Patrick Kelsey while working
 * for Inside Products, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _NETINET6_IP6_PDM_H_
#define _NETINET6_IP6_PDM_H_

/* PDM Destination Option */
struct ip6_opt_pdm {
	uint8_t ip6op_type;
	uint8_t ip6op_len;
	uint8_t ip6op_scale_dtlr;
	uint8_t ip6op_scale_dtls;
	uint16_t ip6op_psntp;
	uint16_t ip6op_psnlr;
	uint16_t ip6op_dtlr;
	uint16_t ip6op_dtls;
} __packed;
#define IP6OPT_PDM	0x0F

#ifdef _KERNEL

struct ip6_pdm_tag {
	struct m_tag mtag;
	uint16_t rx_seq; /* network byte order */
};

struct ip6_pdm_entry {
	TAILQ_ENTRY(ip6_pdm_entry) ipe_link;
#define IP6_PDM_KEY_QUADS	5
	/*
	 * Key format (all components in network byte order):
	 *   16 bytes foreign IP address
	 *   16 bytes local IP address
	 *    3 bytes of zeroes -----------+ MSByte
	 *    1 byte protocol number       |  Packed into 
	 *    2 bytes foreign port number  |  64-bit word
	 *    2 bytes local port number ---+ LSByte
	 */
	uint64_t key[IP6_PDM_KEY_QUADS];
	struct bintime last_rx_time; /* time of last receive on this flow */
	struct bintime last_tx_time; /* time of last transmit on this flow */
	uint16_t last_rx_seq; /* last rx seq no on this flow, network byte order */
	uint16_t next_tx_seq; /* next tx seq no on this flow */
	/* dtls and scale_dtls are the encoded difference between the time
	 * the last packet was received on this flow and the time the last
	 * packet was transmitted on this flow when the last received packet
	 * arrived (that is, the value of last_tx_time when that last
	 * received packet was being processed )
	 */
	uint16_t dtls; /* network byte order */
	uint8_t scale_dtls;
	uint8_t flags;
#define IP6_PDM_FLAG_RX_TIME_VALID	0x01
#define IP6_PDM_FLAG_TX_TIME_VALID	0x02
};

struct ip6_pdm_bucket {
	struct mtx	ipb_mtx;
	TAILQ_HEAD(bucket_entries, ip6_pdm_entry) ipb_entries;
	struct callout	ipb_timer;
	int		ipb_num_entries;
	struct ip6_pdm_state *ipb_state;
};

struct ip6_pdm_state {
	uma_zone_t 	zone;
	uma_zone_t 	tag_zone;
	struct ip6_pdm_bucket *hash_base;
	unsigned int	enabled;
	unsigned int 	hash_bucket_limit;
	unsigned int 	hash_buckets;
	unsigned int 	hash_mask;
	uint32_t 	hash_secret;
};

struct in_conninfo;

void ip6_pdm_init(void);
void ip6_pdm_destroy(void);
void ip6_pdm_input(struct mbuf *, int, int);
unsigned int ip6_pdm_size(struct ip6_dest *, unsigned int *, uint8_t *,
    uint8_t *);
int ip6_pdm_output(struct mbuf *, struct mbuf **, unsigned int);
void ip6_pdm_add_tag(struct mbuf *, struct ip6_opt_pdm *);
unsigned int ip6_pdm_filter_conninfo(unsigned int, struct in_conninfo *);

#endif /* _KERNEL */

#endif /* !_NETINET6_IP6_PDM_H_ */
