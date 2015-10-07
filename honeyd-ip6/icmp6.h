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

#ifndef _ICMP6_
#define _ICMP6_

#include <netinet/icmp6.h>
#include <stdio.h>

struct ndp_neighbor_req{

	SPLAY_ENTRY(ndp_neighbor_req) next;

	const struct interface * inter;

	/* XXX this is a little bit confusing - the target addr is the
	* addr of the requesting system, source contains the honeyd virtual
	* ethernet addr */	
	struct addr target_ip_addr;
	struct addr target_mac_addr;
	
	struct addr source_ip_addr;
	struct addr source_mac_addr;

	void (*cb)(struct ndp_neighbor_req *, int, void *);
	void *arg;
	
	struct template *owner;
};

struct addr_entry{
	SPLAY_ENTRY(addr_entry) next;
	struct addr addr;
};

SPLAY_HEAD(addr_tree,addr_entry);

struct multicast_group{
	SPLAY_ENTRY(multicast_group) next;
	struct addr multicast_addr;
	struct addr_tree templates;	
	/* associated templates */
};

struct router_advertisement{
	int prefix_len;
	struct addr prefix;
	struct addr src_eth_addr;	
};

void ndp_init(void);
void multicast_init(void);

void icmp6_recv_cb(const struct interface*, struct ip6_hdr*, struct icmp6_hdr*);

int checksum_pseudo_header(unsigned char *, unsigned char *, unsigned char, unsigned char *, int); 

void handle_neighbor_solicitation(const struct interface *, struct ip6_hdr*, struct icmp6_hdr*);

void handle_neighbor_advertisement(const struct interface *,struct ip6_hdr*, struct icmp6_hdr*);

void handle_router_advertisement(const struct interface *,struct ip6_hdr*, struct icmp6_hdr*);

struct router_advertisement * find_router_adv();

void handle_echo_request(const struct interface *, struct ip6_hdr*, struct icmp6_hdr*);

struct ndp_neighbor_req * ndp_neighbor_new(const struct interface *, struct addr *, struct addr *, struct addr*, struct addr*);

struct ndp_neighbor_req * ndp_neighbor_find(struct addr *);

void icmp6_send_neighbor_adv(const struct interface *,struct addr *,struct addr *,struct in6_addr *,struct in6_addr *);

void icmp6_send_neighbor_sol(const struct interface *, struct addr *, struct addr *,
			 struct addr *, void (*cb)(struct ndp_neighbor_req *, int, void *), void *arg);

void icmp6_send_router_sol(const struct interface *);

void icmp6_error_send(struct addr *src ,struct ip6_hdr *invoking_ip6,int type, int code);

char *get_solicited_addr_as_str(struct icmp6_hdr *icmp6);

int multicast_group_new(struct addr *multicast_addr);

int add_host_to_multicast_group(struct addr *host, struct addr *multicast_addr);

struct addr *
get_first_member_of_multicast_group(struct addr * multicast_addr);

void compute_solicited_node_address(struct addr *ip6_addr, struct addr *dst);

void ip6_addr_t_to_addr(struct addr *addr_struct,ip6_addr_t *ip6);

void icmp6_test(void);

#endif
