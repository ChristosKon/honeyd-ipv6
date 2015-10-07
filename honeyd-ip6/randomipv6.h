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

#ifndef _RANDOMIPV6_ 
#define _RANDOMIPV6_ 

#include <sys/tree.h>

#define RANDOM_IPV6_DEFAULT_TEMPLATE "randomipv6default"

struct rejected_ipv6_addr{
	RB_ENTRY(rejected_ipv6_addr) next_rejected_ipv6_addr;
	char *addr_str;
};


int random_create_ipv6_template(const char *template_name, const struct interface *inter,float randomipv6_percentage,unsigned long long max_random_ipv6_hosts,FILE * logfp);

void randomipv6_init();

void exclude_addr_from_generator(char * addr_str);

void generate_mock_blocked_entries(int);

char *get_template_name_from_packet(struct ip6_hdr *ip6);

#endif
