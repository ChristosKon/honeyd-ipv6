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

#ifndef _IP6FRAG_H_
#define _IP6FRAG_H_

#define IP6FRAG_TIMEOUT    30

struct frag6ent {
	TAILQ_ENTRY(frag6ent) next;
	uint16_t len;
	uint16_t off;
	u_char *data;
};

struct fragment6 {
	SPLAY_ENTRY(fragment6) node;
	TAILQ_ENTRY(fragment6) next;
	TAILQ_HEAD(frag6q, frag6ent) fraglist;
	struct addr src_addr;
	struct addr dst_addr;
	uint32_t ip6_id;
	uint32_t total_len;
	uint8_t nxt_hdr;
	struct event timeout;
};

void ip6_fragment_init(void);
int get_size_of_unfragmentable_part(struct ip6_hdr*);
int get_last_unfragmentable_ext_hdr(struct ip6_hdr*,struct ip6_ext_hdr *);
int ip6_fragment(struct template *, struct ip6_hdr **,struct ip6_ext_hdr *);


#endif
