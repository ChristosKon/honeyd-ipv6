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

#include <stdlib.h>
#include <stdio.h>
#include <dnet.h> 
#include <sys/tree.h>
#include <sys/queue.h>
#include <netinet/icmp6.h>
#include <event.h>
#include <pcap.h>
#include <string.h>
#include "interface.h"
#include "syslog.h"
#include <netinet/icmp6.h>
#include "icmp6.h"
#include "honeyd.h"
#include <string.h>
#include <arpa/inet.h>
#include "template.h"
#include "log.h"
#include "interface.h"
#include "err.h"

#define ALL_ROUTER_MULTICAST_ADDR "FF02::02"
#define IPV6_MULTICAST_ETH "33:33:00:00:00:02"
#define UNSPECIFIED_ADDRESS "::"

/* prototypes can be redefined for unit tests */
void (*icmp6_send_neighbor_advertisement)(const struct interface * inter,
        struct addr *src_eth, struct addr *dst_eth, struct in6_addr *src_ip6,
        struct in6_addr *dst_ip6) = icmp6_send_neighbor_adv;
struct template *(*find_template)(const char *) = template_find; //XXX we need a proper name for mocked function pointer

/* timer and event for sending the first router solicitation */
struct event *router_sol_ev;
struct timeval *router_sol_tv;

/* tree where we store our neighbor requests in */
SPLAY_HEAD(ndp_req_tree,ndp_neighbor_req) ndp_reqs;

/* compare function for the tree macro */
static int ndp_req_compare(struct ndp_neighbor_req *a,
                           struct ndp_neighbor_req *b)
{
    return (addr_cmp(&a->target_ip_addr, &b->target_ip_addr));
}

/* generate prototypes */
SPLAY_PROTOTYPE(ndp_req_tree, ndp_neighbor_req, next, ndp_req_compare);
SPLAY_GENERATE(ndp_req_tree, ndp_neighbor_req, next, ndp_req_compare);

/* multicast groups */
SPLAY_HEAD(multicast_group_tree,multicast_group) multicast_groups;

static int multicast_group_compare(struct multicast_group *a,
                                   struct multicast_group *b)
{
    return (addr_cmp(&a->multicast_addr, &b->multicast_addr));
}

SPLAY_PROTOTYPE(multicast_group_tree, multicast_group, next,multicast_group_compare);
SPLAY_GENERATE(multicast_group_tree, multicast_group, next,multicast_group_compare);

static int addr_entry_compare(struct addr_entry *a, struct addr_entry *b)
{
    return (addr_cmp(&a->addr, &b->addr));
}

SPLAY_PROTOTYPE(addr_tree, addr_entry, next, addr_entry_compare);
SPLAY_GENERATE(addr_tree, addr_entry, next, addr_entry_compare);

/* router adds that we receive */
/* currently one router is supported */
struct router_advertisement * router_adv = NULL;

struct addr * allocate_memory_for_address(void)
{
    struct addr *address;
    address = malloc(sizeof(struct addr));
    if (address == NULL )
    {
        errx(1, "allocate_memory_for_address: malloc failed");
    }
    return address;
}

void set_IPv6_addr_type_and_bits(struct addr * address)
{
    address->addr_bits = IP6_ADDR_BITS;
    address->addr_type = ADDR_TYPE_IP6;
}

struct addr * allocate_memory_for_ipv6_address(void)
{
    struct addr *address = allocate_memory_for_address();
    set_IPv6_addr_type_and_bits(address);
    return address;
}

struct addr * allocate_memory_for_eth_address(void)
{
    struct addr *address = allocate_memory_for_address();
    address->addr_bits = ETH_ADDR_BITS;
    address->addr_type = ADDR_TYPE_ETH;
    return address;
}

struct ndp_neighbor_req *
find_or_create_neighbor_entry(struct addr * target_ip_addr)
{
    struct ndp_neighbor_req *ret;
    /* if an entry does exist then update it, if not create a new one */
    ret = ndp_neighbor_find(target_ip_addr);
    if (ret == NULL )
    {
        if ((ret = calloc(1, sizeof(struct ndp_neighbor_req))) == NULL )
        {
            syslog(LOG_DEBUG, "not enough memory for neighbor ad");
            return NULL ;
        }
        ret->source_ip_addr.addr_type = ADDR_TYPE_NONE;
        ret->target_ip_addr.addr_type = ADDR_TYPE_NONE;
    }
    return ret;
}


void insert_into_neighbor_cache(struct ndp_neighbor_req * entry)
{
    if (SPLAY_FIND(ndp_req_tree,&ndp_reqs,entry) == NULL )
    {
        SPLAY_INSERT(ndp_req_tree, &ndp_reqs, entry);
    }
}


struct ndp_neighbor_req* assign_source_and_target_to_neighbor_entry(
    struct ndp_neighbor_req* entry, struct addr* source_mac_addr,
    struct addr* source_ip_addr, struct addr* target_mac_addr,
    struct addr* target_ip_addr)
{
    if (source_mac_addr != NULL )
    {
        memcpy(&entry->source_mac_addr, source_mac_addr, sizeof(struct addr));
    }
    if (source_ip_addr != NULL )
    {
        memcpy(&entry->source_ip_addr, source_ip_addr, sizeof(struct addr));
        set_IPv6_addr_type_and_bits(&entry->source_ip_addr);
    }
    if (target_mac_addr != NULL )
    {
        memcpy(&entry->target_mac_addr, target_mac_addr, sizeof(struct addr));
    }
    if (target_ip_addr != NULL )
    {
        memcpy(&entry->target_ip_addr, target_ip_addr, sizeof(struct addr));
        set_IPv6_addr_type_and_bits(&entry->target_ip_addr);
    }

    return entry;
}


/* create a new ndp entry and add it to the tree - called when a new template is created*/
struct ndp_neighbor_req *
ndp_neighbor_new(const struct interface *inter, struct addr * source_mac_addr,
                 struct addr * source_ip_addr, struct addr *target_mac_addr,
                 struct addr *target_ip_addr)
{
    struct ndp_neighbor_req *ret;

    ret = find_or_create_neighbor_entry(target_ip_addr);
    ret->inter = inter;
    ret = assign_source_and_target_to_neighbor_entry(ret, source_mac_addr,
            source_ip_addr, target_mac_addr, target_ip_addr);

    insert_into_neighbor_cache(ret);
    return ret;
}

struct ndp_neighbor_req *
ndp_neighbor_find(struct addr * target_ip_addr)
{
    struct ndp_neighbor_req req;
    req.target_ip_addr = *target_ip_addr;

    return SPLAY_FIND(ndp_req_tree,&ndp_reqs,&req);
}

struct ndp_neighbor_req * ndp_neighbor_delete(struct addr * target_ip_addr)
{
    struct ndp_neighbor_req req;
    req.target_ip_addr = *target_ip_addr;
    return SPLAY_REMOVE(ndp_req_tree,&ndp_reqs,&req);
}

/*
 * called as soon as libevents dispatcher is running, sends
 * a rounter solicitation on each available interface
 * Please note that currently just one router advertisement
 * is supported
 */
void send_router_solicitation_cb(int fd, short event, void *arg)
{
    int i, number_of_interfaces = interface_count();
    /* send a solicitation for each ipv6 interface that is in use */
    /* TODO: only send if interface is ipv6 interface */
    for (i = 0; i < number_of_interfaces; i++)
    {
        icmp6_send_router_sol(interface_get(i));
    }
    free(router_sol_ev);
    free(router_sol_tv);
}

//called on start up, first router solicitation
void schedule_router_solicitation(void)
{
    router_sol_ev = malloc(sizeof(struct event));
    router_sol_tv = malloc(sizeof(struct timeval));
    int fd = -1;
    event_set(router_sol_ev, fd, EV_TIMEOUT, send_router_solicitation_cb, router_sol_ev);
    timerclear(router_sol_tv);
    router_sol_tv->tv_sec = 0;
    event_add(router_sol_ev, router_sol_tv);
}

void ndp_init(void)
{
    SPLAY_INIT(&ndp_reqs);
    schedule_router_solicitation();
}

void multicast_init(void)
{
    SPLAY_INIT(&multicast_groups);
}

int is_icmp6_checksum_correct(struct ip6_hdr *ip6, struct icmp6_hdr *icmp6)
{
    int iplen = ntohs(ip6->ip6_plen) + IP6_HDR_LEN;
    u_int16_t cksum = icmp6->icmp6_cksum;
    ip6_checksum(ip6, iplen);
    if (icmp6->icmp6_cksum != cksum)
        return 0;
    return 1;
}

/**
 * ICMPv6 dispatcher, all incoming ICMPv6 packets get passed to the corresponding handler.
 */
void icmp6_recv_cb(const struct interface * inter, struct ip6_hdr *ip6,
                   struct icmp6_hdr * icmp6)
{
    if (!is_icmp6_checksum_correct(ip6, icmp6))
    {
        syslog(LOG_DEBUG, "icmp packet with invalid checksum received");
        return;
    }

    switch (icmp6->icmp6_type)
    {
    case ND_NEIGHBOR_SOLICIT:
        handle_neighbor_solicitation(inter, ip6, icmp6);
        break;
    case ND_NEIGHBOR_ADVERT:
        handle_neighbor_advertisement(inter, ip6, icmp6);
        break;
    case ND_ROUTER_ADVERT:
        handle_router_advertisement(inter, ip6, icmp6);
        break;
    case ICMP6_ECHO_REQUEST:
        handle_echo_request(inter, ip6, icmp6);
        break;
    default:
        syslog(LOG_DEBUG, "unhandled icmp6 type: %d", icmp6->icmp6_type);
        break;
    }

    return;
}

/**
 * Searches through neibor solicitation options for an ehternet address and returns the first one found.
 */
struct addr * get_link_addr_from_neighbor_solicitation(
    struct nd_neighbor_solicit *neighbor_solicit, int ip_plen)
{

    struct nd_opt_hdr *current_opt = (struct nd_opt_hdr *) (neighbor_solicit + 1);
    struct addr * eth_addr = allocate_memory_for_eth_address();
    int processed_bytes = sizeof(struct nd_neighbor_solicit);

    while (processed_bytes < ip_plen)
    {
        switch (current_opt->nd_opt_type)
        {
        case ND_OPT_SOURCE_LINKADDR:
            memcpy(&eth_addr->addr_eth, current_opt + 1, ETH_ADDR_LEN);
            return eth_addr;
        default:
            break;
        }

        processed_bytes += current_opt->nd_opt_len * 8;/* len in 8 octets */
        current_opt = current_opt + (current_opt->nd_opt_len * 4);/* 1 octet is 4xsizeof(opt header) */
    }
    return NULL ;
}

/**
 * This function sends a neighbor advertisement if honeyd is responsible for the solicitation.
 * In the following function the source address means the honeyd machine and the dest address
 * is the sender of the neighbor solicitation.
 */
void handle_neighbor_solicitation(const struct interface *inter,
                                  struct ip6_hdr *ip6, struct icmp6_hdr *icmp6)
{

    struct addr * src_eth_addr, *dst_eth_addr = NULL, *src_ip_addr, *dst_ip_addr;
    /* the option header might be set and contains the source address */
    struct nd_neighbor_solicit *neighbor_solicit;
    char * template_name;
    struct template *tmpl;

    src_eth_addr = allocate_memory_for_eth_address();
    src_ip_addr = allocate_memory_for_ipv6_address();
    dst_ip_addr = allocate_memory_for_ipv6_address();

    memcpy(&src_ip_addr->addr_ip6, &ip6->ip6_src, IP6_ADDR_LEN);
    memcpy(&dst_ip_addr->addr_ip6, &ip6->ip6_dst, IP6_ADDR_LEN);

    neighbor_solicit = (struct nd_neighbor_solicit*) icmp6;

    /* check if this address concerns us - this is if a template exists */
    template_name = get_solicited_addr_as_str(icmp6);

    tmpl = find_template(template_name);

    if (tmpl == NULL )
    {
        return;
    }
    else
    {
        syslog(LOG_DEBUG, "received a neighbor solicitation for %s from %s",
               template_name, addr_ntoa(src_ip_addr));
    }

    /* set the ethernet address of our template */
    if (tmpl->ethernet_addr == NULL )
    {
        syslog(LOG_DEBUG,
               "Cant handle neighbor solicitation because no ethernet address for template %s configured.",
               template_name);
    }
    else
    {

        memcpy(src_eth_addr, tmpl->ethernet_addr, sizeof(struct addr));
        dst_eth_addr = get_link_addr_from_neighbor_solicitation(neighbor_solicit,ntohs(ip6->ip6_plen));

        icmp6_send_neighbor_advertisement(inter, src_eth_addr, dst_eth_addr,
                                          &neighbor_solicit->nd_ns_target,
                                          (struct in6_addr*) &src_ip_addr->addr_ip6);

        ndp_neighbor_new(inter, src_eth_addr, dst_ip_addr, dst_eth_addr, src_ip_addr);
        syslog(LOG_DEBUG, "added solicitation source to neighbor cache (%s)",
               addr_ntoa(dst_eth_addr));

    }

    free(src_eth_addr);
    free(template_name);

    if (dst_eth_addr != NULL )
    {
        free(dst_eth_addr);
    }
}

int is_address_managed_by_honeyd(struct addr *ip6_addr)
{

    if (template_find(addr_ntoa(ip6_addr)) != NULL )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void bytes_to_ethernet_addr(struct addr * ethernet_addr, char * bytes)
{
    ethernet_addr->addr_type = ADDR_TYPE_ETH;
    ethernet_addr->addr_bits = ETH_ADDR_BITS;
    memcpy(&ethernet_addr->addr_eth, bytes, ETH_ADDR_LEN);
}

void bytes_to_ip6_addr(struct addr * addr_struct,char * ip6_bytes)
{
    addr_struct->addr_type = ADDR_TYPE_IP6;
    addr_struct->addr_bits = IP6_ADDR_BITS;
    memcpy(&addr_struct->addr_ip6, ip6_bytes,IP6_ADDR_LEN);
}

void ip6_addr_t_to_addr(struct addr *addr_struct,ip6_addr_t *ip6)
{
    bytes_to_ip6_addr(addr_struct,(char*)ip6);
}

void in6_addr_to_addr(struct addr * addr_struct,struct in6_addr * in6)
{
    bytes_to_ip6_addr(addr_struct,(char*)in6);
}


void call_ndp_callback(struct ndp_neighbor_req * req)
{
    if (req->cb != NULL )
    {
        (*req->cb)(req, 0, req->arg);
    }
}

void handle_neighbor_advertisement(const struct interface *inter,
                                   struct ip6_hdr *ip6, struct icmp6_hdr *icmp6)
{
    struct ndp_neighbor_req * req;
    struct nd_neighbor_advert *neighbor_advert;
    struct nd_opt_hdr *opt;
    struct addr source_mac_addr, source_ip_addr, target_mac_addr,
           target_ip_addr;
    struct template * tmpl;

    neighbor_advert = (struct nd_neighbor_advert*) icmp6;
    in6_addr_to_addr(&target_ip_addr,&neighbor_advert->nd_na_target);

    /* ignore our own advertisements */
    if (is_address_managed_by_honeyd(&target_ip_addr))
    {
        return;
    }

    syslog(LOG_DEBUG, "received neighbor advertisement for %s",
           addr_ntoa(&target_ip_addr));
    
    /* return if no option followes the advert header */
    if (ip6->ip6_plen - sizeof(struct nd_neighbor_advert) <= 0)
    {
        syslog(LOG_DEBUG,
               "the advertisement has no link layer address attached");
        return;
    }

    /* Get requested ethernet address, TODO: check if there are more options possible */
    opt = (struct nd_opt_hdr*) (neighbor_advert + 1);
    bytes_to_ethernet_addr(&target_mac_addr,(char*)(opt+1));

    ip6_addr_t_to_addr(&source_ip_addr,&ip6->ip6_dst);


    /* ignore advertisements that are not for us */
    if (!is_address_managed_by_honeyd(&source_ip_addr))
    {
        syslog(LOG_DEBUG, "advertisement is not for us us");
        return;
    }

    /* get the source addresses needed to create a new neighbor entry */
    tmpl = template_find(addr_ntoa(&source_ip_addr));
    memcpy(&source_mac_addr, tmpl->ethernet_addr, sizeof(struct addr));


    /* TODO: decide whether we want to process advertisements triggered by others? */
    req = ndp_neighbor_new(inter, &source_mac_addr, &source_ip_addr,
                           &target_mac_addr, &target_ip_addr);

    call_ndp_callback(req);
}

void store_in_router_cache(struct router_advertisement *advertisement)
{
    /* renew our router information */
    if (router_adv != NULL )
    {
        free(router_adv);
    }
    router_adv = advertisement;
    syslog(LOG_DEBUG, "received router advertisement for prefix %s",
           addr_ntoa(&router_adv->prefix));
}

/*
 * Processes a router advertisement and stores the received address
 * in a router cache
 */
void handle_router_advertisement(const struct interface *inter,
                                 struct ip6_hdr *ip6, struct icmp6_hdr *icmp6)
{
    //struct ip6_hdr *ip6 = (struct ip6_hdr *)(pkt+ETH_HDR_LEN);
    struct nd_router_advert *advert = (struct nd_router_advert *) icmp6;
    struct nd_opt_hdr *opt = (struct nd_opt_hdr *) (advert + 1);

    struct router_advertisement *new_router_adv;
    new_router_adv = (struct router_advertisement *) malloc(sizeof(struct router_advertisement));

    /* lets process all the options like mtu, prefix len etc. and save what we need */
    int plen = ntohs(ip6->ip6_plen);
    int processed_bytes = sizeof(struct nd_router_advert);

    /* the loop does not get entered if we dont have any options */
    while (processed_bytes < plen)
    {

        switch (opt->nd_opt_type)
        {
        case ND_OPT_MTU:
            break;
        case ND_OPT_PREFIX_INFORMATION:
            /* set prefix and prefix length */
            new_router_adv->prefix_len = ((struct nd_opt_prefix_info *) opt)->nd_opt_pi_prefix_len;
            bytes_to_ip6_addr(&new_router_adv->prefix,(char *)(&((struct nd_opt_prefix_info *) opt)->nd_opt_pi_prefix));
            break;
        case ND_OPT_SOURCE_LINKADDR:
            /* set ethernet address */
            bytes_to_ethernet_addr(&new_router_adv->src_eth_addr,(char *)(opt + 1));
            break;
        default:
            break;
        }

        processed_bytes += opt->nd_opt_len * 8;/* len in 8 octets */
        opt = opt + (opt->nd_opt_len * 4);/* 1 octet is 4xsizeof(opt header) */
    }

    store_in_router_cache(new_router_adv);
}

/**
 * Computes the solicited node address for a given ip adress.
 */
void compute_solicited_node_address(struct addr *ip6_addr, struct addr *dst)
{

    memcpy(dst, ip6_addr, sizeof(struct addr));

    dst->addr_bits = IP6_ADDR_BITS;
    dst->addr_type = ADDR_TYPE_IP6;

    /* XXX overwrite the prefix */
    dst->addr_data8[0] = 0xFF;
    dst->addr_data8[1] = 0x02;
    dst->addr_data8[2] = 0x0;
    dst->addr_data8[3] = 0x0;
    dst->addr_data8[4] = 0x0;
    dst->addr_data8[5] = 0x0;
    dst->addr_data8[6] = 0x0;
    dst->addr_data8[7] = 0x0;
    dst->addr_data8[8] = 0x0;
    dst->addr_data8[9] = 0x0;
    dst->addr_data8[10] = 0x0;
    dst->addr_data8[11] = 0x1;
    dst->addr_data8[12] = 0xFF;

}

void compute_multicast_eth_addr(struct addr *ip6_addr,
                                struct addr *dst_eth_addr)
{
    dst_eth_addr->addr_bits = ETH_ADDR_BITS;
    dst_eth_addr->addr_type = ADDR_TYPE_ETH;
    /* copy the last few bytes into the ethernet address */
    memcpy(&dst_eth_addr->addr_eth, ((uint8_t *) (&ip6_addr->addr_data8)) + 10, ETH_ADDR_LEN);
    dst_eth_addr->addr_data8[0] = 0x33;
    dst_eth_addr->addr_data8[1] = 0x33;
}

void set_icmpv6_type_and_code_for_ns(struct nd_neighbor_solicit *neighbor_solicit)
{
    neighbor_solicit->nd_ns_type = ND_NEIGHBOR_SOLICIT;
    neighbor_solicit->nd_ns_code = ICMP_CODE_NONE;
    neighbor_solicit->nd_ns_reserved= 0;
}

void set_source_eth_option_in_ns(struct nd_opt_hdr* opt,struct addr * src_eth_addr)
{
    opt->nd_opt_len = 1;	//len in octets
    opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    memcpy(opt + 1, &src_eth_addr->addr_eth, ETH_ADDR_LEN);
}


void icmp6_send_neighbor_sol(const struct interface *inter,
                             struct addr *src_ip_addr, struct addr *src_eth_addr,
                             struct addr *request_ip_addr,
                             void (*cb)(struct ndp_neighbor_req *, int, void *), void *arg)
{

    /* create the icmp packet */
    int pkt_len = sizeof(struct nd_neighbor_solicit) + sizeof(struct nd_opt_hdr)	+ ETH_ADDR_LEN;
    u_char pkt[pkt_len];
    struct nd_neighbor_solicit *neighbor_solicit =	(struct nd_neighbor_solicit*) pkt;
    struct nd_opt_hdr * opt = (struct nd_opt_hdr*) (pkt+ sizeof(struct nd_neighbor_solicit));
    struct addr dst_eth_addr, dst_solicited_node_ip;

    /* create a neighbor req to store the callback */
    struct ndp_neighbor_req * req;
    req = ndp_neighbor_new(inter, src_eth_addr, src_ip_addr, NULL,request_ip_addr);
    req->cb = cb;
    req->arg = arg;

    set_icmpv6_type_and_code_for_ns(neighbor_solicit);

    //create the broadcast ip and eth address
    compute_solicited_node_address(request_ip_addr, &dst_solicited_node_ip);
    compute_multicast_eth_addr(&dst_solicited_node_ip, &dst_eth_addr);

    /* set the target */
    memcpy(&neighbor_solicit->nd_ns_target, &request_ip_addr->addr_data8,
           IP6_ADDR_LEN);

    /* set our address as option */
    set_source_eth_option_in_ns(opt,src_eth_addr);

    syslog(LOG_DEBUG, "sending neighbor solicitation for %s",
           addr_ntoa(request_ip_addr));

    icmp6_send_pkt(inter, src_eth_addr, &dst_eth_addr,
                   (struct in6_addr*) (&src_ip_addr->addr_data8),
                   (struct in6_addr*) (&dst_solicited_node_ip.addr_data8), pkt,
                   pkt_len);
}

void set_icmpv6_type_and_code_for_rs(struct nd_router_solicit *router_solicit)
{
    router_solicit->nd_rs_type = ND_ROUTER_SOLICIT;
    router_solicit->nd_rs_code = ICMP_CODE_NONE;
    router_solicit->nd_rs_reserved = 0;
}


/**
 * Sends a router solicitation.
 */
void icmp6_send_router_sol(const struct interface *inter)
{
    /* create the icmp packet, no options needed */
    int pkt_len = sizeof(struct nd_router_solicit);
    u_char pkt[pkt_len];

    struct nd_router_solicit *router_solicit = (struct nd_router_solicit*) pkt;
    struct addr dst_eth_addr, src_eth_addr, dst_ip_addr, src_ip_addr;

    syslog(LOG_DEBUG, "sending router solicititation on %s",
           inter->if_ent.intf_name);

    /* set source to unspecified address */
    src_eth_addr = inter->if_ent.intf_link_addr;
    addr_aton(UNSPECIFIED_ADDRESS, &src_ip_addr);


    /* set destination ip and eth */
    addr_aton(IPV6_MULTICAST_ETH, &dst_eth_addr);
    addr_aton(ALL_ROUTER_MULTICAST_ADDR, &dst_ip_addr);

    set_icmpv6_type_and_code_for_rs(router_solicit);

    icmp6_send_pkt(inter, &src_eth_addr, &dst_eth_addr,
                   (struct in6_addr*) (&src_ip_addr.addr_data8),
                   (struct in6_addr*) (&dst_ip_addr.addr_data8), pkt, pkt_len);
}

void icmp6_send_neighbor_adv(const struct interface * inter,
                             struct addr *src_eth, struct addr *dst_eth, struct in6_addr *src_ip6,
                             struct in6_addr *dst_ip6)
{
    struct icmp6_hdr * icmp6;
    int pkt_len = sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr)
    + ETH_ADDR_LEN;

    /* our icmp6 package will be 32 byte long */
    u_char pkg[pkt_len];

    icmp6 = (struct icmp6_hdr*) pkg;
    icmp6->icmp6_type = ND_NEIGHBOR_ADVERT;
    icmp6->icmp6_code = ICMP_CODE_NONE;

    /* set flag and target address */
    struct nd_neighbor_advert* advert = (struct nd_neighbor_advert*) icmp6;
    advert->nd_na_flags_reserved= ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;

    /* set the target address, unfortunately the addr_pack function does not work */
    memcpy(advert->nd_na_target.s6_addr, src_ip6, IP6_ADDR_LEN);

    /* TODO: set target to all-nodes multicast if original source is unspecified address? Not yet a problem. */

    /* attach the option header containing the target link layer */
    struct nd_opt_hdr * opt =(struct nd_opt_hdr*) &pkg[sizeof(struct nd_neighbor_advert)];
    opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
    opt->nd_opt_len = 1;/* length of the complete header in octets*/
    uint8_t *optaddr = (uint8_t *) &pkg[sizeof(struct nd_neighbor_advert)
                                        + sizeof(struct nd_opt_hdr)];
    /* copy the template address */
    memcpy(optaddr, &src_eth->addr_eth, ETH_ADDR_LEN);

    icmp6_send_pkt(inter, src_eth, dst_eth, src_ip6, dst_ip6, pkg, pkt_len);
}

void set_icmpv6_type_and_code_for_echo_reply(struct icmp6_hdr *icmp6_response_hdr)
{
    icmp6_response_hdr->icmp6_type = ICMP6_ECHO_REPLY;
    icmp6_response_hdr->icmp6_code = ICMP_CODE_NONE;
}


/*
 * Sends an echo reply for hosts managed by honeyd.
 * requests to multicast adresses are not supported
 */
void handle_echo_request(const struct interface *inter, struct ip6_hdr *ip6,
                         struct icmp6_hdr *icmp6)
{
    struct addr src_ip_addr, dst_ip_addr;
    struct icmp6_hdr *icmp6_request_hdr = NULL, *icmp6_response_hdr = NULL;
    u_int request_pkt_len = ntohs(ip6->ip6_plen) + IP6_HDR_LEN + ETH_HDR_LEN;

    struct template * tmpl = NULL;
    int data_field_len;
    data_field_len = request_pkt_len - ETH_HDR_LEN - IP6_HDR_LEN - sizeof(struct icmp6_hdr);
    int response_pkt_len = sizeof(struct icmp6_hdr) + data_field_len;

    u_char *request_data_field = NULL;
    u_char icmp_response_pkt[response_pkt_len];

    icmp6_request_hdr = icmp6;
    request_data_field = (u_char*) icmp6_request_hdr + sizeof(struct icmp6_hdr);

    /* get the target ip address and check if we are responsible for it */
    ip6_addr_t_to_addr(&dst_ip_addr,&ip6->ip6_dst);
    if(!is_address_managed_by_honeyd(&dst_ip_addr))
    {
        return;
    }

    ip6_addr_t_to_addr(&src_ip_addr,&ip6->ip6_src);

    icmp6_response_hdr = (struct icmp6_hdr *) &icmp_response_pkt[0];
    set_icmpv6_type_and_code_for_echo_reply(icmp6_response_hdr);
    icmp6_response_hdr->icmp6_id=icmp6_request_hdr->icmp6_id;
    icmp6_response_hdr->icmp6_seq=icmp6_request_hdr->icmp6_seq;

    /* copy unique icmpv6 payload */
    memcpy(icmp_response_pkt+sizeof(struct icmp6_hdr),request_data_field,data_field_len);

    /* send echo reply */
    tmpl = template_find(addr_ntoa(&dst_ip_addr));

    syslog(LOG_DEBUG, "received echo request for %s from %s with sequence number %d", addr_ntoa(&dst_ip_addr),
           addr_ntoa(&src_ip_addr), ntohs(icmp6_request_hdr->icmp6_seq));

    icmp6_send_pkt(inter, tmpl->ethernet_addr, NULL,
                   (struct in6_addr*) &ip6->ip6_dst, (struct in6_addr*) &ip6->ip6_src,
                   icmp_response_pkt, data_field_len + sizeof(struct icmp6_hdr));


}

int is_invoking_icmp_fitting_in_mtu(int invoking_pkt_len)
{
    if (invoking_pkt_len + sizeof(struct icmp6_hdr)+ sizeof(struct ip6_hdr)>HONEYD_MTU)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

void icmp6_error_send(struct addr *src, struct ip6_hdr *invoking_ip6, int type,
                      int code)
{
    int response_pkt_len;
    struct icmp6_hdr *icmp6;
    int invoking_pkt_len = ntohs(invoking_ip6->ip6_plen) + IP6_HDR_LEN;
    struct template * tmpl;
    /* the response packet carries as much as possible of the invoking packet as will fit without
     exceeding the mtu, therefore the packet size here should not exceed mtu-ip6_hdr size */
    if (is_invoking_icmp_fitting_in_mtu(invoking_pkt_len))
    {
        response_pkt_len = invoking_pkt_len + sizeof(struct icmp6_hdr);
    }
    else
    {
        /* cut packet */
        response_pkt_len = HONEYD_MTU - IP6_HDR_LEN;
    }

    u_char response_pkt[response_pkt_len];
    icmp6 = (struct icmp6_hdr *) response_pkt;
    icmp6->icmp6_type = type;
    icmp6->icmp6_code = code;

    /* copy as much as possible of invoking packet */
    memcpy(response_pkt + sizeof(struct icmp6_hdr), invoking_ip6,
           response_pkt_len - sizeof(struct icmp6_hdr));

    tmpl = template_find(addr_ntoa(src));
    if (tmpl != NULL )
    {
        icmp6_send_pkt(tmpl->inter, tmpl->ethernet_addr, NULL,
                       (struct in6_addr*) (&src->addr_data8),
                       (struct in6_addr*) &invoking_ip6->ip6_src, response_pkt,
                       response_pkt_len);
    }

}

/*
 * Returns the address of a neighbor solicitation as str.
 * Returns NULL in case of an error.
 */
char *get_solicited_addr_as_str(struct icmp6_hdr *icmp6)
{

    if (icmp6 == NULL || icmp6->icmp6_type != ND_NEIGHBOR_SOLICIT)
    {
        return NULL ;
    }

    struct nd_neighbor_solicit *neighbor_solicit = (struct nd_neighbor_solicit*) icmp6;
    char *ret = (char *) malloc(INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &neighbor_solicit->nd_ns_target, ret, INET6_ADDRSTRLEN);

    return ret;
}

/*
 * Currently this function just returns the only saved router advertisement.
 */
struct router_advertisement * find_router_adv()
{
    return router_adv;
}

void add_to_multicast_group_cache(struct multicast_group *group_to_add)
{
    SPLAY_INSERT(multicast_group_tree, &multicast_groups, group_to_add);
    syslog(LOG_DEBUG, "added multicast group %s",
           addr_ntoa(&group_to_add->multicast_addr));
}

/*
 * Adds a new multicast group to the multicast group tree. Template adresses can
 * be added to a multicast address which is stored in this tree. This way we can
 * lookup an address belonging to a multicast group.
 */
int multicast_group_new(struct addr *multicast_addr)
{
    struct multicast_group *tmp, *res;

    tmp = (struct multicast_group*) malloc(sizeof(struct multicast_group));
    if (tmp == NULL )
    {
        syslog(LOG_DEBUG, "could not allocate memory for new multicast group");
        return -1;
    }

    tmp->multicast_addr = *multicast_addr;

    res = SPLAY_FIND(multicast_group_tree,&multicast_groups,tmp);
    if (res != NULL )
    {
        syslog(LOG_DEBUG,
               "cannot add multicast group because it does already exist");
        free(tmp);
        return -1;
    }
    else
    {
        SPLAY_INIT(&tmp->templates);
        add_to_multicast_group_cache(tmp);
    }
    return 0;
}

int is_multicast_group_registered(struct multicast_group *group)
{
    struct multicast_group *registered_group;
    registered_group = SPLAY_FIND(multicast_group_tree,&multicast_groups,group);
    if (registered_group == NULL )
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int is_member_of_multicast_group(struct addr_entry *entry, struct multicast_group *group)
{
    if (SPLAY_FIND(addr_tree,&group->templates,entry) != NULL )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/*
 * Adds a new host to a multicast addr.
 */
int add_host_to_multicast_group(struct addr *host, struct addr *multicast_addr)
{
    struct multicast_group tmp_group,*group;
    struct addr_entry * host_entry = NULL;
    struct addr_entry tmp_entry;

    tmp_group.multicast_addr = *multicast_addr;
    tmp_entry.addr = *host;

    if (!is_multicast_group_registered(&tmp_group))
    {
        syslog(LOG_DEBUG,
               "cannot add host to multicast group because group does not exist");
        return -1;
    }
    else
    {
        /* check if host is already member of group */
        group = SPLAY_FIND(multicast_group_tree,&multicast_groups,&tmp_group);
        if (is_member_of_multicast_group(&tmp_entry,group))
        {
            syslog(LOG_DEBUG,
                   "cannot add host to multicast group. host is already member.");
            return -1;
        }
        else
        {
            /* insert host */
            host_entry = (struct addr_entry *) malloc(	sizeof(struct addr_entry));
            if (host_entry == NULL )
            {
                syslog(LOG_DEBUG,
                       "could not allocate memory for new host entry");
                return -1;
            }
            else
            {
                host_entry->addr = *host;
                SPLAY_INSERT(addr_tree, &group->templates, host_entry);
            }
        }
    }

    syslog(LOG_DEBUG, "added %s to multicast group %s", addr_ntoa(host),
           addr_ntoa(multicast_addr));
    return 0;
}

struct addr *
get_first_member_of_multicast_group(struct addr * multicast_addr)
{
    struct multicast_group tmp_group, *group;
    struct addr_entry * res;

    if (multicast_addr == NULL )
    {
        return NULL ;
    }

    tmp_group.multicast_addr = *multicast_addr;

    /* check if group exists */
    group = SPLAY_FIND(multicast_group_tree,&multicast_groups,&tmp_group);
    if (group == NULL )
    {
        return NULL ;
    }
    else
    {
        res = SPLAY_MIN(addr_tree,&group->templates);
        if (res != NULL )
            return &res->addr;
        else
            return NULL ;
    }
}

/* Unit tests */

void assert_is_true(int value, char * error_message)
{
    if (!value)
    {
        errx(1, error_message);
    }
}

void initialize_addresses_with_test_values(struct addr* source_mac_addr,
        struct addr* target_mac_addr, struct addr* source_ip_addr,
        struct addr* target_ip_addr)
{
    addr_aton("00:11:22:33:44:55", source_mac_addr);
    addr_aton("66:77:88:99:10:11", target_mac_addr);
    addr_aton("2001:db8::5", source_ip_addr);
    addr_aton("2001:db8::6", target_ip_addr);
}

void test_ndp_neighbor_delete(void)
{
    struct addr source_mac_addr, source_ip_addr, target_mac_addr,
           target_ip_addr;
    struct ndp_neighbor_req * req;

    initialize_addresses_with_test_values(&source_mac_addr, &target_mac_addr,
                                          &source_ip_addr, &target_ip_addr);
    //use an IPv6 address that differs from other tests
    addr_aton("2001:db8::1", &target_ip_addr);

    req = ndp_neighbor_new(NULL, &source_mac_addr, &source_ip_addr,
                           &target_mac_addr, &target_ip_addr);
    assert_is_true(req != NULL,
                   "ndp_neighbor_new does not return a valid neighbor request");

    req = ndp_neighbor_find(&target_ip_addr);
    assert_is_true(req != NULL,
                   "ndp_neighbor_find does not return a valid neighbor request");

    req = ndp_neighbor_delete(&target_ip_addr);
    assert_is_true(req != NULL,
                   "ndp_neighbor_delete does not return a valid neighbor request");

    req = ndp_neighbor_find(&target_ip_addr);
    assert_is_true(req == NULL,
                   "ndp_neighbor_delete did not delete a neighbor request");

    fprintf(stderr, "\t%s: OK\n", __func__);

}

void test_ndp_neighbor_new(void)
{
    struct addr source_mac_addr, source_ip_addr, target_mac_addr,
           target_ip_addr;
    struct ndp_neighbor_req * req;

    initialize_addresses_with_test_values(&source_mac_addr, &target_mac_addr,
                                          &source_ip_addr, &target_ip_addr);
    //use an IPv6 address that differs from other tests
    addr_aton("2001:db8::2", &target_ip_addr);

    req = ndp_neighbor_new(NULL, &source_mac_addr, &source_ip_addr,
                           &target_mac_addr, &target_ip_addr);

    assert_is_true(req != NULL,
                   "ndp_neighbor_new does not return a valid neighbor request");
    assert_is_true(addr_cmp(&source_mac_addr, &req->source_mac_addr) == 0,
                   "wrong source mac address of new request");
    assert_is_true(addr_cmp(&target_mac_addr, &req->target_mac_addr) == 0,
                   "wrong target mac address of new request");
    assert_is_true(addr_cmp(&source_ip_addr, &req->source_ip_addr) == 0,
                   "wrong source ip address of new request");
    assert_is_true(addr_cmp(&target_ip_addr, &req->target_ip_addr) == 0,
                   "wrong target ip address of new request");

    assert_is_true(source_ip_addr.addr_bits == IP6_ADDR_BITS,
                   "wrong source ip addr bits");
    assert_is_true(target_ip_addr.addr_bits == IP6_ADDR_BITS,
                   "wrong target ip addr bits");

    req = ndp_neighbor_find(&target_ip_addr);

    assert_is_true(req != NULL,
                   "ndp_neighbor_new does not return a valid neighbor request");
    assert_is_true(addr_cmp(&source_mac_addr, &req->source_mac_addr) == 0,
                   "wrong source mac address after neighbor find");
    assert_is_true(addr_cmp(&target_mac_addr, &req->target_mac_addr) == 0,
                   "wrong target mac address after neighbor find");
    assert_is_true(addr_cmp(&source_ip_addr, &req->source_ip_addr) == 0,
                   "wrong source ip address after neighbor find");
    assert_is_true(addr_cmp(&target_ip_addr, &req->target_ip_addr) == 0,
                   "wrong target ip address after neighbor find");

    fprintf(stderr, "\t%s: OK\n", __func__);

}

char * get_packet_from_hex_string(char * hex_string, int packet_length_in_bytes)
{
    char *pos = hex_string;
    int i;
    int packet_length = strlen(hex_string) / 2;

    char * ip6_packet_bytes = (char *) malloc(packet_length);

    if (ip6_packet_bytes == NULL )
    {
        errx(1, "could not allocate memory for test packet");
    }

    for (i = 0; i < packet_length; i++)
    {
        sscanf(pos, "%2hhx", &ip6_packet_bytes[i]);
        pos += 2 * sizeof(char);
    }

    return ip6_packet_bytes;
}

struct template *template_find_mock(const char *ip_addr_str)
{
    struct template * tmpl;
    struct addr * eth_addr;
    tmpl = (struct template *) malloc(sizeof(struct template));
    eth_addr = (struct addr *) malloc(sizeof(struct addr));
    addr_aton("00:11:22:33:44:55", eth_addr);
    tmpl->ethernet_addr = eth_addr;
    return tmpl;
}

void icmp6_send_neighbor_adv_mock(const struct interface * inter,
                                  struct addr *src_eth, struct addr *dst_eth, struct in6_addr *src_ip6,
                                  struct in6_addr *dst_ip6)
{
    //to test: source, dest, ethernet payload
    struct addr *actual_src_ip6 = allocate_memory_for_ipv6_address();
    struct addr *actual_dst_ip6 = allocate_memory_for_ipv6_address();

    struct addr *expected_src_ip6 = allocate_memory_for_ipv6_address();
    struct addr *expected_dst_ip6 = allocate_memory_for_ipv6_address();

    addr_aton("2001:db8::2", expected_src_ip6);
    addr_aton("2001:db8::99", expected_dst_ip6);

    memcpy(&actual_src_ip6->addr_ip6, src_ip6, IP6_ADDR_LEN);
    memcpy(&actual_dst_ip6->addr_ip6, dst_ip6, IP6_ADDR_LEN);


    assert_is_true(addr_cmp(actual_src_ip6, expected_src_ip6) == 0,
                   "Wrong source address in neighbor advertisement");
    assert_is_true(addr_cmp(actual_dst_ip6, expected_dst_ip6) == 0,
                   "Wrong destination address in neighbor advertisement");

    free(actual_src_ip6);
    free(actual_dst_ip6);
    free(expected_src_ip6);
    free(expected_dst_ip6);
}

void test_handle_neighbor_solicitation()
{
    struct ip6_hdr *ip6;
    struct icmp6_hdr *icmp6;
    const struct interface *inter = NULL;

    /* neighbor solicitation for 2001:db8::2 from 2001:db8::99*/
    char *ip6_packet_hex_string =
    "6000000000203aff20010db8000000000000000000000099ff0200000000000000000001ff00000287009e220000000020010db80000000000000000000000020101aa000435d137";
    int packet_length = strlen(ip6_packet_hex_string) / 2;

    char *ip6_packet_bytes = get_packet_from_hex_string(ip6_packet_hex_string,
            packet_length);

    ip6 = (struct ip6_hdr*) ip6_packet_bytes;
    icmp6 = (struct icmp6_hdr*) (ip6 + 1);

    icmp6_send_neighbor_advertisement = icmp6_send_neighbor_adv_mock;
    find_template = template_find_mock;
    handle_neighbor_solicitation(inter, ip6, icmp6);

    fprintf(stderr, "\t%s: OK\n", __func__);
}

void icmp6_test(void)
{
    test_ndp_neighbor_delete();
    test_ndp_neighbor_new();
    test_handle_neighbor_solicitation();
}
