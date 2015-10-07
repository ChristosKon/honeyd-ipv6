/*
 * Copyright (c) 2002, 2003 Niels Provos <provos@citi.umich.edu>
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

#include "config.h"

#include <sys/queue.h>
#include <sys/tree.h>

#include <pcap.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <dnet.h>
#include <syslog.h>
#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "network.h"

#define BITS_IN_BYTE 8

/*
 * TODO: I think this function is not necessary anymore
 * Copies the first passed bits from source to target. addr_net is doing  basically the same
 * thing therefore we dont need this function.
 */

void subaddr(struct addr * source_addr, struct addr * target_addr, int prefix){
        int rounds = prefix/(sizeof(uint8_t)*BITS_IN_BYTE);
        int i=0,j=0,lastbits;
        int addr_len = source_addr->addr_type == ADDR_TYPE_IP? IP_ADDR_LEN: IP6_ADDR_LEN;
        uint8_t byte,bitmask=0;
        
	/* copy type and bits */
	target_addr->addr_type = source_addr->addr_type;
	target_addr->addr_bits = source_addr->addr_bits;

	/* one more round if the prefix is not a multiple of 8 */
        if((lastbits=prefix%(sizeof(uint8_t)*BITS_IN_BYTE))!=0)
                rounds++;
 
        /* iterate over the address length and copy the
        bits to the target address, set all the other bits
        to 0 */
        while(i < addr_len){
                /* set the address to 0 first */
                byte = 0;
                if(i<rounds){
                        byte = source_addr->addr_data8[i];
                        /* copy the last few bytes in the last round */
                        if(i==rounds-1){
                                for(j=0;j<lastbits;j++){
                                         bitmask>>=1;
                                        /* set the first bit to 1 */
                                        bitmask|=0x80;
                                }
                                byte = source_addr->addr_data8[i] & bitmask;
                        }
                }
                target_addr->addr_data8[i]=byte;
                i++;
        }
 }


/*
 * Compares two ip6 networks.
 */
enum net_order network_compare6(struct network *a, struct network *b){

	struct addr addr_a,addr_b;	
	struct addr addr_anet, addr_bnet;
	int smaller_prefix;
	int orig_aaddr_bits,orig_baddr_bits;

	addr_a=a->net;
	addr_b=b->net;

	/* get the network addresses of both networks
	(maybe an ip address has been passed) and check
	if the network with the smaller prefix is bigger,
	smaller or contains the network with the longer prefix */

	/* return if the network types are different */
	if(a->net.addr_type != b->net.addr_type){
		return NET_DIFFTYPE;
	}	
	
	/* the same address and prefix means that the networks are equal */
	if(addr_cmp(&addr_a,&addr_b)==0 && addr_a.addr_bits==addr_b.addr_bits){
		return NET_EQUALS;
	}

	/* get the smalles prefix, cut the addresses and compare the head */
	smaller_prefix = addr_a.addr_bits < addr_b.addr_bits?addr_a.addr_bits:addr_b.addr_bits;
	

	/* backup the original bit addr bits */
	orig_aaddr_bits = addr_a.addr_bits;
	orig_baddr_bits = addr_b.addr_bits;

	/* get the smaller prefix */
	addr_a.addr_bits = smaller_prefix;
	addr_net(&addr_a,&addr_anet);
	addr_b.addr_bits = smaller_prefix;
	addr_net(&addr_b,&addr_bnet);	

	if(addr_cmp(&addr_anet,&addr_bnet)<0){
		return NET_PRECEEDS;
	}else if(addr_cmp(&addr_anet,&addr_bnet)>0){
		return NET_FOLLOWS;
	}else{
		//addr_a.addr_bits = orig_aaddr_bits;
		//addr_b.addr_bits = orig_baddr_bits;

		//if(addr_cmp(&addr_a,&addr_b)>0){
		if(orig_aaddr_bits>orig_baddr_bits){
			return NET_CONTAINED;
		}else{
			return NET_CONTAINS;
		}	
	}

	return NET_DIFFTYPE;
}

/*
 *  compare two network ranges
 */

enum net_order
network_compare(struct network *a, struct network *b)
{
	struct addr addr_a, addr_b;
	struct addr addr_aend, addr_bend;

	/* return if the network types are different */
	if(a->net.addr_type != b->net.addr_type){
		return NET_DIFFTYPE;
	}	

	/* in case of ip6 we return the result of network_compare6 */
	if(b->net.addr_type == ADDR_TYPE_IP6){
		return network_compare6(a,b);
	}

	/* Set up the addresses; still IPv4 dependent */
	addr_a = a->net;
	addr_a.addr_bits = IP_ADDR_BITS;
	addr_b = b->net;
	addr_b.addr_bits = IP_ADDR_BITS;
	/* get broadcast addresses - addr_bcast only calculates the broadcast
	address if its a network address (does not work with ip6 at all),
	in case of a usual ip it just copies it */
	addr_bcast(&a->net, &addr_aend);
	addr_aend.addr_bits = IP_ADDR_BITS;
	addr_bcast(&b->net, &addr_bend);
	addr_bend.addr_bits = IP_ADDR_BITS;

	/* add_cmp compares two networks of the same type */
	if (addr_cmp(&addr_aend, &addr_b) < 0)
		return (NET_PRECEEDS);
	if (addr_cmp(&addr_a, &addr_bend) > 0)
		return (NET_FOLLOWS);
	if (addr_cmp(&addr_a, &addr_b) <= 0 && 
	    addr_cmp(&addr_aend, &addr_bend) >= 0){
		if (addr_cmp(&a->net, &b->net) == 0)
			return (NET_EQUALS);
		return (NET_CONTAINS);
	}
	return (NET_CONTAINED);
}

/* Unittests */

static void
network_test_compare(void)
{
	struct addr one, two;
	struct network net_one, net_two;

	addr_pton("1.0.0.0/24", &one);
	addr_pton("2.0.0.0/24", &two);
	net_one.net = one;
	net_two.net = two;

	if (network_compare(&net_one, &net_two) != NET_PRECEEDS)
		errx(1, "network_compare");
	if (network_compare(&net_two, &net_one) != NET_FOLLOWS)
		errx(1, "network_compare");
	if (network_compare(&net_two, &net_two) != NET_EQUALS)
		errx(1, "network_compare");

	addr_pton("2.1.0.0/24", &one);
	addr_pton("2.0.0.0/8", &two);
	net_one.net = one;
	net_two.net = two;
	if (network_compare(&net_one, &net_two) != NET_CONTAINED)
		errx(1, "network_compare: !contained");
	if (network_compare(&net_two, &net_one) != NET_CONTAINS)
		errx(1, "network_compare: !contains");

	fprintf(stderr, "\t%s: OK\n", __func__);
}

static void
network_test_compare6(void){

	struct addr one, two;
	struct network net_one, net_two;

	addr_pton("2001:db8:1::1/64",&one);
	addr_pton("2001:db8:2::2/96",&two);

	net_one.net = one;
	net_two.net = two;

	if(network_compare6(&net_one,&net_two) != NET_PRECEEDS)
		errx(1,"network_compare6");

	if (network_compare6(&net_two, &net_one) != NET_FOLLOWS)
		errx(1, "network_compare6");
	
	if (network_compare6(&net_two, &net_two) != NET_EQUALS)
		errx(1, "network_compare6");

	addr_pton("2001:db8:2::/32",&one);
	addr_pton("2001:db8:1::1/16",&two);
	
	net_one.net = one;
	net_two.net = two;

	if (network_compare6(&net_one, &net_two) != NET_CONTAINED)
		errx(1, "network_compare6: !contained");
	if (network_compare6(&net_two, &net_one) != NET_CONTAINS)
		errx(1, "network_compare6: !contains");
	
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
network_test(void)
{
	network_test_compare();
	network_test_compare6();
}
