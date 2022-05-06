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
 */

/*
 * This is an implementation of the IPv6 Performance and Diagnostic Metrics
 * (PDM) Destination Option [draft-ietf-ippm-6man-pdm-option-12].
 *
 * This implementation is currently considered to be experimental and is not
 * included in kernel builds by default.  To include this code, add the
 * following line to your kernel config:
 *
 * options INET6_PDM
 *
 *
 * The following PDM-specific sysctls are defined:
 *
 * net.inet6.ip6.pdm.enabled (RW, default 0)
 *     When zero, no PDM options in inbound packets are processed and no PDM
 *     options are inserted into outbound packets.  On the transition from
 *     enabled to disabled, the PDM state table is cleared.
 *
 * net.inet6.ip6.pdm.hash_bucket_limit (RWTUN, default IP6_PDM_HASH_BUCKET_LIMIT_DEFAULT)
 *     The maximum number of records in a state table hash bucket.  If the
 *     limit is reduced, all buckets will be trimmed to the new limit.
 *
 * net.inet6.ip6.pdm.hash_buckets (RDTUN, default IP6_PDM_HASH_BUCKETS_DEFAULT)
 *     The number of state table hash buckets.  This must be a power of 2.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/hash.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_pdm.h>

static void ip6_pdm_tag_free(struct m_tag *t);
static unsigned int ip6_pdm_filter_mbuf(struct mbuf *m, int nopdm);
static void ip6_pdm_timestamp(struct bintime *bt);
static void ip6_pdm_delta_time(struct bintime *t1, struct bintime *t2,
    uint16_t *delta, uint8_t *scale);
static struct ip6_pdm_entry *ip6_pdm_lookup(uint64_t *key,
    struct ip6_pdm_bucket **ipbp);
static struct ip6_pdm_entry *ip6_pdm_create(struct ip6_pdm_bucket *ipb,
    uint64_t *key);
static void ip6_pdm_bucket_trim(struct ip6_pdm_bucket *ipb, unsigned int limit);
static void ip6_pdm_entry_drop(struct ip6_pdm_entry *ipe,
    struct ip6_pdm_bucket *ipb);

#define IP6_PDM_HASH_BUCKET_LIMIT_DEFAULT	16
#define IP6_PDM_HASH_BUCKETS_DEFAULT		2048 /* must be power of 2 */

static VNET_DEFINE(struct ip6_pdm_state, ip6_pdm_state);
#define	V_ip6_pdm_state		VNET(ip6_pdm_state)

static SYSCTL_NODE(_net_inet6_ip6, OID_AUTO, pdm, CTLFLAG_RW, 0,
    "IPv6 PDM option");

VNET_DEFINE(unsigned int, ip6_pdm_enabled) = 0;
static int sysctl_net_inet6_ip6_pdm_enabled(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_net_inet6_ip6_pdm, OID_AUTO, enabled,
    CTLFLAG_VNET | CTLTYPE_UINT | CTLFLAG_RWTUN, NULL, 0,
    &sysctl_net_inet6_ip6_pdm_enabled, "IU",
    "Enable/disable IPv6 PDM option processing");

static int sysctl_net_inet6_ip6_pdm_hash_bucket_limit(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_net_inet6_ip6_pdm, OID_AUTO, hash_bucket_limit,
    CTLFLAG_VNET | CTLTYPE_UINT | CTLFLAG_RWTUN, NULL, 0,
    &sysctl_net_inet6_ip6_pdm_hash_bucket_limit, "IU",
    "PDM state table max records per bucket");

static VNET_DEFINE(unsigned int, ip6_pdm_hash_buckets) =
    IP6_PDM_HASH_BUCKETS_DEFAULT;
#define	V_ip6_pdm_hash_buckets	VNET(ip6_pdm_hash_buckets)
SYSCTL_UINT(_net_inet6_ip6_pdm, OID_AUTO, hash_buckets,
    CTLFLAG_VNET | CTLFLAG_RDTUN, &VNET_NAME(ip6_pdm_hash_buckets), 0,
    "PDM state table number of buckets (power of 2)");

static MALLOC_DEFINE(M_IP6_PDM, "ip6_pdm", "IPv6 PDM buckets");

#define	IPB_LOCK(ipb)		mtx_lock(&(ipb)->ipb_mtx)
#define	IPB_UNLOCK(ipb)		mtx_unlock(&(ipb)->ipb_mtx)
#define	IPB_LOCK_ASSERT(ipb)	mtx_assert(&(ipb)->ipb_mtx, MA_OWNED)

void
ip6_pdm_init(void)
{
	unsigned int i;
	
	/* May already be non-zero if kernel tunable was set */
	if (V_ip6_pdm_state.hash_bucket_limit == 0)
		V_ip6_pdm_state.hash_bucket_limit =
		    IP6_PDM_HASH_BUCKET_LIMIT_DEFAULT;

	/* May already be non-zero if kernel tunable was set */
	if ((V_ip6_pdm_state.hash_buckets == 0) ||
	    !powerof2(V_ip6_pdm_state.hash_buckets))
		V_ip6_pdm_state.hash_buckets = IP6_PDM_HASH_BUCKETS_DEFAULT;

	V_ip6_pdm_state.hash_mask = V_ip6_pdm_state.hash_buckets - 1;
	V_ip6_pdm_state.hash_secret = arc4random();

	V_ip6_pdm_state.hash_base = malloc(V_ip6_pdm_state.hash_buckets *
	    sizeof(struct ip6_pdm_bucket), M_IP6_PDM, M_WAITOK | M_ZERO);

	for (i = 0; i < V_ip6_pdm_state.hash_buckets; i++) {
		TAILQ_INIT(&V_ip6_pdm_state.hash_base[i].ipb_entries);
		mtx_init(&V_ip6_pdm_state.hash_base[i].ipb_mtx, "ip6_pdm_bucket",
			 NULL, MTX_DEF);
		callout_init_mtx(&V_ip6_pdm_state.hash_base[i].ipb_timer,
			 &V_ip6_pdm_state.hash_base[i].ipb_mtx, 0);
		V_ip6_pdm_state.hash_base[i].ipb_num_entries = 0;
		V_ip6_pdm_state.hash_base[i].ipb_state = &V_ip6_pdm_state;
	}

	/*
	 * Note that while the total number of entries in the PDM state
	 * table is limited by the table management logic to
	 * V_ip6_pdm_state.hash_buckets * V_ip6_pdm_state.hash_bucket_limit,
	 * the total number of items in this zone can exceed that amount by
	 * the number of CPUs in the system times the maximum number of
	 * unallocated items that can be present in each UMA per-CPU cache
	 * for this zone.
	 */
	V_ip6_pdm_state.zone = uma_zcreate("ip6_pdm_entries",
	    sizeof(struct ip6_pdm_entry), NULL, NULL, NULL, NULL, UMA_ALIGN_CACHE,
	    0);

	V_ip6_pdm_state.tag_zone = uma_zcreate("ip6_pdm_tags",
	    sizeof(struct ip6_pdm_tag), NULL, NULL, NULL, NULL, UMA_ALIGN_CACHE,
	    0);
}

void
ip6_pdm_destroy(void)
{
	struct ip6_pdm_bucket *ipb;
	unsigned int i;

	for (i = 0; i < V_ip6_pdm_state.hash_buckets; i++) {		
		ipb = &V_ip6_pdm_state.hash_base[i];
		ip6_pdm_bucket_trim(ipb, 0);
		mtx_destroy(&ipb->ipb_mtx);
	}

	KASSERT(uma_zone_get_cur(V_ip6_pdm_state.zone) == 0,
	    ("%s: PDM state zone allocation count not 0", __func__));
	uma_zdestroy(V_ip6_pdm_state.zone);
	KASSERT(uma_zone_get_cur(V_ip6_pdm_state.tag_zone) == 0,
	    ("%s: PDM tag zone allocation count not 0", __func__));
	uma_zdestroy(V_ip6_pdm_state.tag_zone);
	free(V_ip6_pdm_state.hash_base, M_IP6_PDM);
}

static unsigned int
ip6_pdm_supported_proto(int proto)
{
	switch (proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
	case IPPROTO_ICMPV6:
		return (1);
	default:
		return (0);
	}
}

void
ip6_pdm_input(struct mbuf *m, int proto, int ulp_off)
{
	struct ip6_pdm_tag *tag;
	struct ip6_hdr *ip6;
	uint8_t *p;
	struct ip6_pdm_bucket *ipb;
	struct ip6_pdm_entry *entry;
	uint64_t hash_key[IP6_PDM_KEY_QUADS];
	uint16_t delta;
	uint8_t scale;
	
	/*
	 * If PDM is enabled, the header that is about to be processed is
	 * the ULP header, and there is a PDM tag present, perform PDM
	 * input processing.
	 */
	if (!V_ip6_pdm_state.enabled || !ip6_pdm_supported_proto(proto))
		return;

	tag = (struct ip6_pdm_tag *)m_tag_locate(m, MTAG_ABI_IPV6, IPV6_TAG_PDM,
	    NULL);
	if (tag == NULL)
		return;

	ip6 = mtod(m, struct ip6_hdr *);
	memcpy(&hash_key[0], &ip6->ip6_src, 32);
	switch (proto) {
	case IPPROTO_SCTP:
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		p = mtod(m, uint8_t *) + ulp_off;
		hash_key[4] =
		    (p[0] << 24) |
		    (p[1] << 16) |
		    (p[2] << 8)  |
		     p[3];
		break;
	default:
		hash_key[4] = 0;
		break;
	}
	hash_key[4] |= (uint64_t)proto << 32;
	
	entry = ip6_pdm_lookup(hash_key, &ipb);
	/* IPB_LOCK is now held */
	if (entry == NULL) {
		entry = ip6_pdm_create(ipb, hash_key);
		if (entry == NULL)
			goto out;

		bintime_clear(&entry->last_tx_time);
		entry->next_tx_seq = arc4random();
	}

	entry->last_rx_seq = tag->rx_seq;
	/*
	 * Taking tx/rx timestamps while the ipb lock is held ensures that
	 * the last tx time can't advance beyond the current rx timestamp,
	 * and thus that the DTLS computed below will always be
	 * non-negative.
	 */
	ip6_pdm_timestamp(&entry->last_rx_time);
	entry->flags |= IP6_PDM_FLAG_RX_TIME_VALID;
	if (entry->flags & IP6_PDM_FLAG_TX_TIME_VALID)
		ip6_pdm_delta_time(&entry->last_rx_time, &entry->last_tx_time,
		    &delta, &scale);
	else
		delta = scale = 0;
	entry->dtls = htons(delta);
	entry->scale_dtls = scale;
	
out:
	IPB_UNLOCK(ipb);
}

unsigned int
ip6_pdm_size(struct ip6_dest *dest, unsigned int *base_size, uint8_t *pad_before,
    uint8_t *pad_after)
{
	unsigned int base;
	uint8_t pad1, pad2, pdm_size;
	
	if (dest)
		base = (dest->ip6d_len + 1) << 3;
	else
		base = sizeof(struct ip6_dest);

	/*
	 * PDM option must start a multiple of 2 bytes from the
	 * beginning of the extension header.
	 */
	pad1 = base & 0x1;
	pdm_size = pad1 + sizeof(struct ip6_opt_pdm);
	/*
	 * Extension header must be a multiple of 8 bytes.
	 */
	pad2 = (8 - ((base + pdm_size) & 0x7)) & 0x7;
	pdm_size += pad2;

	if (base_size)
		*base_size = base;
	if (pad_before)
		*pad_before = pad1;
	if (pad_after)
		*pad_after = pad2;
	
	return (pdm_size);
}

int
ip6_pdm_output(struct mbuf *m, struct mbuf **m_destp, unsigned int nopdm)
{
	struct ip6_hdr *ip6;
	uint8_t *p;
	struct ip6_pdm_bucket *ipb;
	struct ip6_pdm_entry *entry;
	struct ip6_opt_pdm *pdm;
	struct mbuf *m_dest;
	struct mbuf *m_pdm;
	uint64_t hash_key[IP6_PDM_KEY_QUADS];
	struct bintime last_rx_time;
	struct bintime now;
	unsigned int i;
	unsigned int base_size, pdm_size, size;
	int error = 0;
	uint16_t tx_seq;
	uint16_t rx_seq;
	uint16_t delta, dtls;
	uint8_t scale, scale_dtls;
	uint8_t flags;
	uint8_t proto;
	uint8_t pad_before, pad_after;
	
	if (ip6_pdm_filter_mbuf(m, nopdm)) {
		ip6 = mtod(m, struct ip6_hdr *);
		proto = ip6->ip6_nxt;
		memcpy(&hash_key[0], &ip6->ip6_dst, 16);
		memcpy(&hash_key[2], &ip6->ip6_src, 16);
		switch (proto) {
		case IPPROTO_SCTP:
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			p = mtod(m, uint8_t *) + sizeof(struct ip6_hdr);
			hash_key[4] =
			    (p[2] << 24) |
			    (p[3] << 16) |
			    (p[0] << 8)  |
			    p[1];
			break;
		default:
			hash_key[4] = 0;
			break;
		}
		hash_key[4] |= (uint64_t)proto << 32;

		entry = ip6_pdm_lookup(hash_key, &ipb);
		/* IPB_LOCK is now held */
		if (entry == NULL) {
			entry = ip6_pdm_create(ipb, hash_key);
			if (entry == NULL) {
				IPB_UNLOCK(ipb);
				return (ENOMEM);
			}
			
			bintime_clear(&entry->last_rx_time);
			entry->next_tx_seq = arc4random();
			entry->last_rx_seq = 0;
		}

		/*
		 * Taking tx/rx timestamps while the ipb lock is held
		 * ensures that the last rx time can't advance beyond the
		 * current tx timestamp, and thus that the DTLR computed
		 * below will always be non-negative.
		 */
		flags = entry->flags;
		ip6_pdm_timestamp(&now);
		last_rx_time = entry->last_rx_time;
		entry->last_tx_time = now;
		entry->flags |= IP6_PDM_FLAG_TX_TIME_VALID;
		rx_seq = entry->last_rx_seq;
		tx_seq = entry->next_tx_seq;
		entry->next_tx_seq++;
		dtls = entry->dtls;
		scale_dtls = entry->scale_dtls;

		IPB_UNLOCK(ipb);

		m_dest = *m_destp;
		pdm_size =
		    ip6_pdm_size(m_dest ? mtod(m_dest, struct ip6_dest *) : NULL,
			&base_size, &pad_before, &pad_after);

		size = base_size + pdm_size;
		if (!m_dest || (M_TRAILINGSPACE(m_dest) < pdm_size)) {
			m_pdm = NULL;
			if (size <= MLEN)
				m_pdm = m_get(M_NOWAIT, MT_DATA);
			else if (size <= MCLBYTES)
				m_pdm = m_getcl(M_NOWAIT, MT_DATA, 0);
			if (m_pdm == NULL)
				return(ENOBUFS);
			if (m_dest) {
				memcpy(mtod(m_pdm, caddr_t),
				    mtod(m_dest, caddr_t), base_size);
				m_freem(m_dest);
			}
			*m_destp = m_pdm;
		} else
			m_pdm = m_dest;
	
		m_pdm->m_len = size;
		p = mtod(m_pdm, uint8_t *);
		/* p[0] is nxt field, which is set later by the caller */
		p[1] = (size >> 3) - 1;  /* p[1] is len field */
		p += base_size;
		if (pad_before)
			*p++ = IP6OPT_PAD1;
		pdm = (struct ip6_opt_pdm *)p;
		pdm->ip6op_type = IP6OPT_PDM;
		pdm->ip6op_len = sizeof(struct ip6_opt_pdm) - 2;
		pdm->ip6op_psntp = htons(tx_seq);
		pdm->ip6op_psnlr = rx_seq;  /* already in network byte order */
		if (flags & IP6_PDM_FLAG_RX_TIME_VALID)
			ip6_pdm_delta_time(&now, &last_rx_time, &delta, &scale);
		else
			delta = scale = 0;
		pdm->ip6op_dtlr = htons(delta);
		pdm->ip6op_scale_dtlr = scale;
		pdm->ip6op_dtls = dtls; /* already in network byte order */
		pdm->ip6op_scale_dtls = scale_dtls;
		p += sizeof(struct ip6_opt_pdm);
		if (pad_after) {
			if (pad_after == 1)
				*p++ = IP6OPT_PAD1;
			else {
				*p++ = IP6OPT_PADN;
				*p++ = pad_after - 2;
				for (i = 0; i < pad_after - 2; i++)
					*p++ = 0;
			}
		}
	}
	
	return (error);
}

void
ip6_pdm_add_tag(struct mbuf *m, struct ip6_opt_pdm *pdm)
{
	struct ip6_pdm_tag *tag;

	tag = uma_zalloc(V_ip6_pdm_state.tag_zone, M_NOWAIT);
	if (tag == NULL)
		return;

	m_tag_setup(&tag->mtag, MTAG_ABI_IPV6, IPV6_TAG_PDM,
	    sizeof(struct ip6_pdm_tag) - sizeof(struct m_tag));
	tag->mtag.m_tag_free = ip6_pdm_tag_free;
	tag->rx_seq = pdm->ip6op_psntp;
	
	m_tag_prepend(m, &tag->mtag);
}

static void
ip6_pdm_tag_free(struct m_tag *t)
{
	uma_zfree(V_ip6_pdm_state.tag_zone, t);	
}

static unsigned int
ip6_pdm_filter_mbuf(struct mbuf *m, int nopdm)
{
	/* XXX later the user-filter logic will be applied here */
	if (!nopdm && V_ip6_pdm_state.enabled)
		return (1);

	return (0);
}

unsigned int
ip6_pdm_filter_conninfo(unsigned int proto, struct in_conninfo *inc)
{
	/* XXX later the user-filter logic will be applied here */
	if (V_ip6_pdm_state.enabled)
		return (1);

	return (0);
}

static void
ip6_pdm_timestamp(struct bintime *bt)
{
	/* XXX provide knob for fast-and-loose bintime */
	binuptime(bt);
}

static void
ip6_pdm_delta_time(struct bintime *t1, struct bintime *t2, uint16_t *delta,
    uint8_t *scale)
{
	struct bintime bin_delta;
	uint64_t val1, val2;
	uint64_t product;
	int8_t scale1, scale2;
	int8_t product_scale;
	int8_t bitno;
	uint8_t adj;

	/*
	 * The overall approach used here is to convert the bintime delta to
	 * attoseconds using 32 significant binary digits for both the delta
	 * time value and the 10^18 constant.  Effectively, the computation
	 * is being done using floating point multiplication with a 32-bit
	 * mantissa.  The result is then adjusted to 16 significant binary
	 * digits and a corresponding exponent.
	 */
	
	bin_delta = *t1;
	bintime_sub(&bin_delta, t2);

	/*
	 * struct bintime is a 128-bit quantity representing time in units
	 * of 2^-64 seconds.  The sec member has bits 127 to 64 and the frac
	 * member has bits 63 to 0.  We want to extract the 32 MSBs of the
	 * delta value (starting with the most significant bit set) and keep
	 * track of the exponent corresponding to units of seconds.
	 */
	if (bin_delta.sec == 0) {
		if (bin_delta.frac == 0) {
			*delta = *scale = 0;
			return;
		}
		/* flsll() labels the LSB as bit 1 */
		bitno = flsll(bin_delta.frac) - 1;
		scale1 = bitno - 64;
		if (bitno < 31) {
			/*
			 * 32-bit window contains (bitno + 1) bits from frac
			 * and (31- bitno) zeroes shifted in from the right.
			 */
			adj = 31 - bitno;
			scale1 -= adj;
			val1 = bin_delta.frac << adj;
		} else {
			/*
			 * 32-bit window filled entirely with frac bits.
			 */
			scale1 -= 31;
			val1 = bin_delta.frac >> (bitno - 31);
		}
	} else {
		/* flsll() labels the LSB as bit 1 */
		bitno = flsll(bin_delta.sec) - 1;
		if (bitno < 31) {
			/*
			 * 32-bit window contains (bitno + 1) bits from sec
			 * and (31 - bitno) bits from frac.
			 */
			adj = 31 - bitno;
			scale1 = -adj;
			val1 = (bin_delta.sec << adj) |
			    (bin_delta.frac >> (64 - adj));
		} else {
			/*
			 * 32-bit window filled entirely from sec.
			 */
			scale1 = bitno - 31;
			val1 = bin_delta.sec >> scale1;
		}
	}
	
	/*
	 * 10^18 = 0xDE0B6B3A7640000
	 * approximating with the 32 MSBs: 0xDE0B6B3A * 2^28
	 */
	val2 = 0xDE0B6B3A;
	scale2 = 28;

	/*
	 * At this point, val1 and val2 are both 32-bit quantities with bit
	 * 31 set.  We want to compute the product and extract the 16 MSBs
	 * (starting with the most significant bit set) and keep track of
	 * the exponent corresponding to units of seconds.
	 */
	product = val1 * val2;
	product_scale = scale1 + scale2;
	/* flsll() labels the LSB as bit 1 */
	bitno = flsll(product) - 1;
	if (bitno < 15) {
		adj = 15 - bitno;
		product_scale -= adj;
		product <<= adj;
	} else {
		adj = bitno - 15;
		product_scale += adj;
		product >>= adj;
	}
	if (product_scale < 0) {
		adj = -product_scale;
		product_scale = 0;
		product >>= adj;
	}
	
	*delta = product;
	*scale = product_scale;
}

static struct ip6_pdm_entry *
ip6_pdm_lookup(uint64_t *key, struct ip6_pdm_bucket **ipbp)
{
	struct ip6_pdm_bucket *ipb;
	struct ip6_pdm_entry *ipe;
	unsigned int i;
	uint32_t hash;

	hash = jenkins_hash32((uint32_t *)key, IP6_PDM_KEY_QUADS * 2,
	    V_ip6_pdm_state.hash_secret);
	ipb = &V_ip6_pdm_state.hash_base[hash & V_ip6_pdm_state.hash_mask];
	*ipbp = ipb;
	IPB_LOCK(ipb);
	
	/*
	 * Always returns with locked bucket.
	 */
	TAILQ_FOREACH(ipe, &ipb->ipb_entries, ipe_link) {
		for (i = 0; i < IP6_PDM_KEY_QUADS; i++)
			if (key[i] != ipe->key[i])
				break;
		if (i == IP6_PDM_KEY_QUADS)
			break;
	}

	return (ipe);
}

static struct ip6_pdm_entry *
ip6_pdm_create(struct ip6_pdm_bucket *ipb, uint64_t *key)
{
	struct ip6_pdm_entry *entry;
	unsigned int i;
	
	/*
	 * 1. Create a new entry, or
	 * 2. Reclaim an existing entry, or
	 * 3. Fail
	 */

	IPB_LOCK_ASSERT(ipb);
	
	entry = NULL;
	if (ipb->ipb_num_entries < V_ip6_pdm_state.hash_bucket_limit)
		entry = uma_zalloc(V_ip6_pdm_state.zone, M_NOWAIT);

	if (entry == NULL) {
		/*
		 * At bucket limit, or out of memory - reclaim last
		 * entry in bucket.
		 */
		entry = TAILQ_LAST(&ipb->ipb_entries, bucket_entries);
		if (entry == NULL) {
			/* XXX count this event */
			return (NULL);
		}
	}

	TAILQ_INSERT_HEAD(&ipb->ipb_entries, entry, ipe_link);
	for (i = 0; i < IP6_PDM_KEY_QUADS; i++)
		entry->key[i] = key[i];
	entry->flags = 0;

	return (entry);
}

static void
ip6_pdm_bucket_trim(struct ip6_pdm_bucket *ipb, unsigned int limit)
{
	struct ip6_pdm_entry *ipe, *ipe_tmp;
	unsigned int entries;
	
	callout_drain(&ipb->ipb_timer);
		
	IPB_LOCK(ipb);
	entries = 0;
	TAILQ_FOREACH_SAFE(ipe, &ipb->ipb_entries, ipe_link, ipe_tmp) {
		entries++;
		if (entries > limit)
			ip6_pdm_entry_drop(ipe, ipb);
	}
	KASSERT(ipb->ipb_num_entries == limit,
	    ("%s: ipb->ipb_num_entries %d not %d", __func__,
		ipb->ipb_num_entries, limit));
	if (limit == 0) {
		KASSERT(TAILQ_EMPTY(&ipb->ipb_entries),
		    ("%s: ipb->ipb_entries not empty", __func__));
		ipb->ipb_num_entries = -1; /* disable bucket */
	}
	IPB_UNLOCK(ipb);
}

static void
ip6_pdm_entry_drop(struct ip6_pdm_entry *ipe, struct ip6_pdm_bucket *ipb)
{

	IPB_LOCK_ASSERT(ipb);

	TAILQ_REMOVE(&ipb->ipb_entries, ipe, ipe_link);
	ipb->ipb_num_entries--;
	uma_zfree(V_ip6_pdm_state.zone, ipe);
}

static int
sysctl_net_inet6_ip6_pdm_enabled(SYSCTL_HANDLER_ARGS)
{
	struct ip6_pdm_bucket *ipb;
	int error;
	unsigned int new;
	unsigned int i;
	
	new = V_ip6_pdm_state.enabled;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr) {
		if (V_ip6_pdm_state.enabled && !new) {
			/* enabled -> disabled */
			V_ip6_pdm_state.enabled = 0;
			for (i = 0; i < V_ip6_pdm_state.hash_buckets; i++) {
				ipb = &V_ip6_pdm_state.hash_base[i];
				ip6_pdm_bucket_trim(ipb, 0);
			}
		} else if (!V_ip6_pdm_state.enabled && new) {
			/* disabled -> enabled */
			for (i = 0; i < V_ip6_pdm_state.hash_buckets; i++) {
				ipb = &V_ip6_pdm_state.hash_base[i];
				IPB_LOCK(ipb);
				KASSERT(TAILQ_EMPTY(&ipb->ipb_entries),
				    ("%s: ipb->ipb_entries not empty", __func__));
				KASSERT(ipb->ipb_num_entries == -1,
				    ("%s: ipb->ipb_num_entries %d not -1", __func__,
					ipb->ipb_num_entries));
				ipb->ipb_num_entries = 0; /* enable bucket */
				IPB_UNLOCK(ipb);
				/* XXX start callout */
			}			
			V_ip6_pdm_state.enabled = 1;
		}
	}
	return (error);
}

static int
sysctl_net_inet6_ip6_pdm_hash_bucket_limit(SYSCTL_HANDLER_ARGS)
{
	struct ip6_pdm_bucket *ipb;
	int error;
	unsigned int new;
	unsigned int i;
	
	new = V_ip6_pdm_state.hash_bucket_limit;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr) {
		if ((new == 0) || (new > INT_MAX))
			error = EINVAL;
		else {
			V_ip6_pdm_state.hash_bucket_limit = new;
			if (new < V_ip6_pdm_state.hash_bucket_limit) {
				for (i = 0; i < V_ip6_pdm_state.hash_buckets;
				     i++) {
					ipb = &V_ip6_pdm_state.hash_base[i];
					ip6_pdm_bucket_trim(ipb, new);
				}
			}
		}
			
	}
	return (error);
}
