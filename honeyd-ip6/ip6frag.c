/*
 * Copyright (c) 2002, 2003, 2004, 2005 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2012, 2013 Sven Schindler <sschindl@cs.uni-potsdam.de>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/tree.h>
#include <stdlib.h>
//#include <dumbnet.h>
#include <dnet.h>
#include <event.h>
#include <syslog.h>
#include "honeyd.h"
#include "template.h"
#include "ip6frag.h"
#include <string.h>

/* note that dstopts may be part of the fragmentable part too */
uint8_t unfragmentable_header[] = { IPPROTO_HOPOPTS, IPPROTO_ROUTING };

SPLAY_HEAD(frag6tree, fragment6)
fragments6;

#define DIFF(a,b) do { \
	if ((a) < (b)) return -1; \
	if ((a) > (b)) return 1; \
} while (0)

int frag6compare(struct fragment6 *a, struct fragment6 *b)
{
    int cmp = 0;
    cmp = addr_cmp(&a->src_addr, &b->src_addr);
    if (cmp < 0)
        return -1;
    if (cmp > 0)
        return 1;

    cmp = addr_cmp(&a->dst_addr, &b->dst_addr);
    if (cmp < 0)
        return -1;
    if (cmp > 0)
        return 1;

    DIFF(a->ip6_id, b->ip6_id);

    return (0);
}

SPLAY_PROTOTYPE(frag6tree, fragment6, node, frag6compare);
SPLAY_GENERATE(frag6tree, fragment6, node, frag6compare);

void ip6_fragment_init(void)
{
    SPLAY_INIT(&fragments6);
}

struct fragment6* ip6_fragment_find(struct addr *src_addr,
                                    struct addr *dst_addr, uint32_t id)
{
    struct fragment6 tmp, *result = NULL;

    tmp.src_addr = *src_addr;
    tmp.dst_addr = *dst_addr;
    tmp.ip6_id = id;

    result = SPLAY_FIND(frag6tree, &fragments6, &tmp);
    return result;
}

int is_first_fragment_received(struct fragment6 *fragment)
{
    struct frag6ent *first = TAILQ_FIRST(&fragment->fraglist);
    if (first->off == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int is_last_fragment_received(struct fragment6 *fragment)
{
    if (fragment->total_len != -1)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int is_gap_beetween_fragments(struct fragment6 *fragment)
{
    uint32_t total_len = 0;
    struct frag6ent *tmp = TAILQ_FIRST(&fragment->fraglist);
    TAILQ_FOREACH(tmp,&fragment->fraglist,next)
    {
        total_len += tmp->len;
        /* if there is a gap between the offset and the last packet then we are not finished */
        if (tmp->off > total_len)
        {
            return 1;
        }

    }
    return 0;
}

int is_fragment_complete(struct fragment6 *fragment)
{
    /* we havent received the last fragment yet */
    if (!is_last_fragment_received(fragment))
    {
        return 0;
    }

    if (!is_first_fragment_received(fragment))
    {
        syslog(LOG_DEBUG, "first fragment not yet received");
        return 0;
    }

    if (is_gap_beetween_fragments(fragment))
    {
        return 0;
    }

    return 1;
}

int is_no_fragments_received(struct fragment6 *fragment)
{
    if (TAILQ_FIRST(&fragment->fraglist) == NULL)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void insert_fragment_entry_into_existing_queue(struct frag6ent *entry,struct fragment6 *fragment)
{
    struct frag6ent *tmp, *before;
    /* walk through the queue and check where we can insert the fragment */
    tmp = TAILQ_FIRST(&fragment->fraglist);
    before = tmp;
    while (tmp != NULL && entry->off > tmp->off)
    {
        before = tmp;
        tmp = TAILQ_NEXT(tmp,next);
    }

    if (tmp != NULL )
        TAILQ_INSERT_BEFORE(tmp, entry, next);
    else
        TAILQ_INSERT_AFTER(&fragment->fraglist, before, entry, next);
}

/**
 * Inserts a new fragment into the fragment list of a fragmented packet.
 * It returns 0 if the fragment could be added successfully but some
 * fragments are still missing, it returns 1 if all fragments are available
 * and no error occured. 
 */
int ip6_insert_fragment(struct fragment6 *fragment, uint16_t off,
                        uint16_t frag_len, u_char *data)
{
    struct frag6ent *entry;

    entry = (struct frag6ent*) calloc(1, sizeof(struct frag6ent));
    if (entry == NULL )
    {
        syslog(LOG_DEBUG,
               "was not able to allocate memory for a fragment entry");
    }

    entry->data = malloc(frag_len);
    if (entry->data == NULL )
    {
        syslog(LOG_DEBUG, "could not allocate memory for ipv6 fragment entry");
        return 0;
    }

    memcpy(entry->data, data, frag_len);
    entry->off = off;
    entry->len = frag_len;

    if (is_no_fragments_received(fragment))
    {
        TAILQ_INSERT_HEAD(&fragment->fraglist, entry, next);
        return 0;
    }

    insert_fragment_entry_into_existing_queue(entry,fragment);

    /* check if we received all fragments */
    if (is_fragment_complete(fragment))
    {
        return 1;
    }

    return 0;
}

ip6_fragment_timeout(int fd, short which, void *arg)
{
  struct fragment6 *tmp = arg;
  struct addr src;
 
  syslog(LOG_DEBUG, "Expiring IPv6 fragment from %s, id %d",
      addr_ntoa(&tmp->src_addr), ntohs(tmp->ip6_id));
  
  free_fragments(tmp);
} 

struct fragment6* ip6_fragment_new(struct addr *src_addr, struct addr *dst_addr,
                                   uint32_t id)
{
    struct fragment6 *result = NULL;
    struct timeval tv = { IP6FRAG_TIMEOUT, 0};

    result = calloc(1, sizeof(struct fragment6));
    if (result == NULL )
    {
        syslog(LOG_DEBUG, "was not able to alloc memory for ipv6 fragment");
        return NULL ;
    }

    memcpy(&result->src_addr, src_addr, sizeof(struct addr));
    memcpy(&result->dst_addr, dst_addr, sizeof(struct addr));
    result->ip6_id = id;
    result->total_len = -1;

    /* create a new fragment list */
    TAILQ_INIT(&result->fraglist);
  
    /* set fragment timeout */
    evtimer_set(&result->timeout, ip6_fragment_timeout, result);
    evtimer_add(&result->timeout, &tv);


    SPLAY_INSERT(frag6tree, &fragments6, result);

    return result;
}

int array_contains(void *array, void *element, int element_size, int length)
{
    int i;
    for (i = 0; i < length; i++)
    {
        if (!memcmp(array + i, element, element_size))
            return 1;
    }

    return 0;
}

int is_ext_header_fragmentable(uint8_t nxt_ext_hdr)
{
    if (array_contains(unfragmentable_header, &nxt_ext_hdr,
                       sizeof(uint8_t),
                       sizeof(unfragmentable_header) / sizeof(uint8_t)))
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int is_destination_options_followed_by_routing_hdr(uint8_t ext_hdr_id,struct ip6_ext_hdr * ext_hdr)
{
    if (ext_hdr_id == IPPROTO_DSTOPTS && ((struct ip6_ext_hdr *) ext_hdr)->ext_nxt == IPPROTO_ROUTING)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int is_complete_payload_fragmentable(struct ip6_hdr *ip6)
{
    if (is_ext_header_fragmentable(ip6->ip6_nxt))
    {
        /* nxt header may be destination options which may also be part of the umfragmentable header, if the next
         * header is a routing header
         */
        u_char *pkt_ptr = (u_char *) (ip6 + 1);

        if (!is_destination_options_followed_by_routing_hdr(ip6->ip6_nxt,(struct ip6_ext_hdr *) pkt_ptr))
        {
            return 1;
        }
    }
    return 0;
}



/**
 * Sets last_ext_hdr to the last header of the unfragmentable ip6 packet part. If the passed
 * ip6 packet does not comtain any extension headers then the last_ext_hdr pointer is set to NULL.
 * Returns the length of the unfragmentable part (length of the fragment header not included)
 */
int get_last_unfragmentable_ext_hdr(struct ip6_hdr *ip6,
                                    struct ip6_ext_hdr *last_ext_hdr)
{

    u_char *pkt_ptr = (u_char *) (ip6 + 1);
    uint8_t nxt_ext_hdr;
    int len = IP6_HDR_LEN;

    last_ext_hdr = NULL;

    if(is_complete_payload_fragmentable(ip6))
    {
        return IP6_HDR_LEN;
    }

    /* add the ext header lenght as long as we dont face a fragmentable header */
    while (pkt_ptr < ((u_char*) ip6) + ip6->ip6_plen)
    {
        last_ext_hdr = (struct ip6_ext_hdr *) pkt_ptr;
        /* TODO: replace magic number 8 */
        nxt_ext_hdr = ((struct ip6_ext_hdr *) pkt_ptr)->ext_nxt;
        /* ext len given in 8 octets */
        pkt_ptr = pkt_ptr + (1 + ((struct ip6_ext_hdr *) pkt_ptr)->ext_len) * 8;
        len += (1 + ((struct ip6_ext_hdr *) pkt_ptr)->ext_len) * 8;
        if (is_ext_header_fragmentable(nxt_ext_hdr))
        {

            if (!is_destination_options_followed_by_routing_hdr(nxt_ext_hdr,(struct ip6_ext_hdr *) pkt_ptr))
            {
                return len;
            }
        }
    }
    return -1;
}

/**
 * Returns the size of all unfragmentable ip headers up to the fragment header.
 * You can use this function to calculate the acutal data length.
 * Its the total ip len - this size - length of fragment header.
 */
int get_size_of_unfragmentable_part(struct ip6_hdr *ip6)
{
    return get_last_unfragmentable_ext_hdr(ip6, NULL );
}

struct ip6_hdr * assemble_fragments(struct ip6_hdr *ip6, struct fragment6 *frag)
{
    int size_of_unfragmentable_part;
    struct ip6_hdr *ip6_assembled;
    struct frag6ent * tmp;

    /* alloc space for the assembled packet */
    size_of_unfragmentable_part = get_size_of_unfragmentable_part(ip6);
    ip6_assembled = (struct ip6_hdr*) malloc(
                        size_of_unfragmentable_part + frag->total_len);
    if (ip6 == NULL )
    {
        syslog(LOG_DEBUG,
               "could not realloc memory for assembling ipv6 packet");
        return NULL ;
    }

    /* copy the unfragmentable part */
    memcpy(ip6_assembled, ip6, size_of_unfragmentable_part);

    TAILQ_FOREACH(tmp,&frag->fraglist,next)
    {
        memcpy(
            ((u_char *) ip6_assembled) + size_of_unfragmentable_part
            + tmp->off, tmp->data, tmp->len);
    }

    ip6_assembled->ip6_plen = htons(
                                  size_of_unfragmentable_part + frag->total_len - IP6_HDR_LEN);
    /* TODO: set the nxt header of the last header in the unfragmentable part */
    ip6_assembled->ip6_nxt = frag->nxt_hdr;

    return ip6_assembled;
}

void free_fragments(struct fragment6 *frag)
{
    struct frag6ent *frag_ent, *nxt;
    evtimer_del(&frag->timeout);

    for (frag_ent = TAILQ_FIRST(&frag->fraglist);
            frag_ent != TAILQ_END(&frag->fraglist); frag_ent = nxt)
    {
        nxt = TAILQ_NEXT(frag_ent, next);
        free(frag_ent);
    }

    SPLAY_REMOVE(frag6tree, &fragments6, frag);
    free(frag);
}

/**
 * returns 1 if all fragments have been received, sets pip6 to the
 * assembled packets.
 */
int ip6_fragment(struct template *tmpl, struct ip6_hdr **pip6,
                 struct ip6_ext_hdr *frag_hdr)
{
    struct addr src, dst;
    struct fragment6 *existing_fragment;
    struct ip6_ext_data_fragment *frag_hdr_data;
    u_char *data = NULL;
    uint16_t off;
    uint16_t plen;
    uint16_t data_len;
    int packet_complete;
    struct ip6_hdr *ip6 = *pip6;

    frag_hdr_data = (struct ip6_ext_data_fragment *) &frag_hdr->ext_data;

    addr_pack(&src, ADDR_TYPE_IP6, IP6_ADDR_BITS, &ip6->ip6_src, IP6_ADDR_LEN);
    addr_pack(&dst, ADDR_TYPE_IP6, IP6_ADDR_BITS, &ip6->ip6_dst, IP6_ADDR_LEN);

    existing_fragment = ip6_fragment_find(&src, &dst, frag_hdr_data->ident);
    if (existing_fragment == NULL )
    {
        existing_fragment = ip6_fragment_new(&src, &dst, frag_hdr_data->ident);
    }

    /* set the fragments next header */
    existing_fragment->nxt_hdr = frag_hdr->ext_nxt;

    /* we dont need to multiply that by 8 because the flag field is 3 bit long */
    off = ntohs(frag_hdr_data->offlg & IP6_OFF_MASK);
    plen = ntohs(ip6->ip6_plen);

    /* TODO: check if the fragment has a valid length */

    /* data follows the fragmentatfragmentation header header */
    data = (u_char *) (frag_hdr_data + 1);
    /* TODO: data len is total len - all ext header lengths (unfragmentable part + fragment header)  */
    data_len = plen + IP6_HDR_LEN - ((get_size_of_unfragmentable_part(ip6) + sizeof(struct ip6_ext_hdr)));

    /* set the total len */
    if (!(frag_hdr_data->offlg & IP6_MORE_FRAG))
    {
        existing_fragment->total_len = off + data_len;
    }

    syslog(LOG_DEBUG, "Received ipv6 fragment from %s: %d@%d", addr_ntoa(&src), data_len, off);

    /* insert the fragment and check if we are finished */
    packet_complete = ip6_insert_fragment(existing_fragment, off, data_len,
                                          data);
    if (packet_complete)
    {
        //build packet
        *pip6 = assemble_fragments(ip6, existing_fragment);
        free_fragments(existing_fragment);
        return 1;
    }

    return 0;
}
