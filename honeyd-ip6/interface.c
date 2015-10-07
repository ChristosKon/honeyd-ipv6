/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
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

#include <sys/ioctl.h>
#include <sys/tree.h>
#include <sys/queue.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <event.h>
#include <pcap.h>
#include <dnet.h>

#include "honeyd.h"
#include "interface.h"
#include "network.h"
#include "router.h"			/* for network compare */
#include "debug.h"

#define NUMBER_OF_ALIASES 10

/* Prototypes */
int pcap_dloff(pcap_t *);

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);

static char *interface_expandips(int, char **, int);
static void interface_recv(int, short, void *);
static void interface_poll_recv(int, short, void *);

int interface_verify_config = 0;
int interface_dopoll;
char *interface_filter = NULL;

static TAILQ_HEAD(ifq, interface) interfaces;
static intf_t *intf;
static pcap_handler if_recv_cb = NULL;

void
interface_prevent_init(void)
{
#ifdef DISABLE_KQUEUE
	if (!interface_dopoll) 
		setenv("EVENT_NOKQUEUE", "yes", 1);
#endif
#ifdef DISABLE_POLL
	if (!interface_dopoll) 
		setenv("EVENT_NOPOLL", "yes", 1);
#endif
}

void
interface_initialize(pcap_handler cb)
{
	TAILQ_INIT(&interfaces);

	/* intfopen allows access to the interface configuration */
	if ((intf = intf_open()) == NULL)
		err(1, "intf_open");

	if_recv_cb = cb;
}

static void addr_remove_scope_id(struct addr* ip6) {
  /* TODO: remove magic numbers */
  if (ip6->addr_data8[0]==0xfe && ip6->addr_data8[1]==0x80) {
	  /* delete scope id */
		ip6->addr_data8[2]=0;
		ip6->addr_data8[3]=0;
	}
}

/* Get a new interface structure */

static struct interface *
interface_new(char *dev)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	struct interface *inter;
	struct addr * ip6addr;

	if ((inter = calloc(1, sizeof(struct interface)+(sizeof(struct addr)*10))) == NULL)
		err(1, "%s: calloc", __func__);


	if (dev == NULL) {
		if ((dev = pcap_lookupdev(ebuf)) == NULL)
			errx(1, "pcap_lookupdev: %s", ebuf);
	}
	
	TAILQ_INSERT_TAIL(&interfaces, inter, next);

	inter->if_ent.intf_len = sizeof(struct intf_entry) + sizeof(struct addr)*NUMBER_OF_ALIASES;
	strlcpy(inter->if_ent.intf_name, dev, sizeof(inter->if_ent.intf_name));

	if (intf_get(intf, &inter->if_ent) < 0)
		err(1, "%s: intf_get", __func__);

	int i;
	for(i=0;i<inter->if_ent.intf_alias_num;i++){
		 if (inter->if_ent.intf_alias_addrs[i].addr_type == ADDR_TYPE_IP6){
			/* clear the embedded scope id if its a unicast link local address */
			ip6addr = &inter->if_ent.intf_alias_addrs[i];
			addr_remove_scope_id(ip6addr);
      /* TODO: remove warning when implementation is completely finished */			
			syslog(LOG_DEBUG,"Found IPv6 address: %s",addr_ntoa(&inter->if_ent.intf_alias_addrs[i]));
      syslog(LOG_DEBUG,"Warning: Please note that IPv6 is not completely supported yet.");      
		}
			
	}
			

	/* check if the interface has an ip assigned to it */
	if (inter->if_ent.intf_addr.addr_type != ADDR_TYPE_IP &&
			inter->if_ent.intf_addr.addr_type != ADDR_TYPE_IP6 )
		errx(1, "%s: bad interface configuration: %s is not IP",
		    __func__, dev);

	return (inter);
}

/*
 * Returns the number of configured interfaces
 */

int
interface_count(void)
{
	struct interface *inter;
	int count = 0;

	TAILQ_FOREACH(inter, &interfaces, next)
		count++;

	return (count);
}

/*
 * Returns the interface with the specified offset in the list
 */

struct interface *
interface_get(int off)
{
	struct interface *inter;
	int count = 0;

	TAILQ_FOREACH(inter, &interfaces, next) {
		if (count++ == off)
			return inter;
	}

	return (NULL);
}

struct interface *
interface_find(char *name)
{
	struct interface *inter;

	TAILQ_FOREACH(inter, &interfaces, next) {
		if (strcasecmp(inter->if_ent.intf_name, name) == 0)
			return (inter);
	}

	return (NULL);
}

struct interface *
interface_find_addr(struct addr *addr)
{
	struct interface *inter;

	TAILQ_FOREACH(inter, &interfaces, next) {
		if (addr_cmp(addr, &inter->if_ent.intf_addr) == 0)
			return (inter);
	}

	return (NULL);
}

struct interface *
interface_find_responsible(struct addr *addr)
{
	struct interface *inter;
	struct network net, ifnet;
	struct addr netaddr;	
	int nalias = 0;
	int tmp_addr_bits;	

	/* return NULL if no address is passed */
	if(addr == NULL){
		return (NULL);
	}

	/* the passed address has the network size of 128 bit */
	net.net = *addr;
	
	TAILQ_FOREACH(inter, &interfaces, next) {
		/* check the address and all the aliases too */
		do{
			/* get the interface address and convert it to a network address
			save the result in ifnet.net - in case of alias!=null its an alias*/
			if(nalias==0){
				/* the main address */
				ifnet.net = inter->if_ent.intf_addr;
				/*use the original network size instead of the reassigend 32 */
				ifnet.net.addr_bits = inter->if_addrbits;
			}else{
				/* the aliases */
				//syslog(LOG_DEBUG,"addrbits: %d", inter->if_ent.intf_alias_addrs[nalias-1].addr_bits);
				ifnet.net = inter->if_ent.intf_alias_addrs[nalias-1];
				/* we dont need to set the network size here (as in ip4) because we didnt do a reassignemt */
			}
			/* backup the addr bits before getting the network mask */
			//syslog(LOG_DEBUG,"########### %s",addr_ntoa(&ifnet.net));
			tmp_addr_bits = ifnet.net.addr_bits;
			addr_net(&ifnet.net, &netaddr);
			ifnet.net=netaddr;
			
			if(nalias==0){
				/* in case of ip4 if_addrbits is 24 - the network mask */
				ifnet.net.addr_bits = inter->if_addrbits;
			}else{
				/* in case of an alias address we dont need to reassign the addr bits */
				ifnet.net.addr_bits=tmp_addr_bits;
			}

			/* TODO: run through the aliases too and dont forget 
			to add ip6 support to the network compare function */	
			if (network_compare(&ifnet, &net) == NET_CONTAINS)
				return (inter);
	
			nalias++;
		}while(nalias<=inter->if_ent.intf_alias_num);
	}
	return (NULL);
}

void
interface_close(struct interface *inter)
{
	TAILQ_REMOVE(&interfaces, inter, next);

	if (inter->if_eth != NULL)
		eth_close(inter->if_eth);
	pcap_close(inter->if_pcap);

	free(inter);
}

void
interface_close_all(void)
{
	struct interface *inter;

	while((inter = TAILQ_FIRST(&interfaces)) != NULL)
		interface_close(inter);
}

void
interface_ether_filter(struct interface *inter,
    int naddresses, char **addresses)
{
	char line[48];
	char *dst;

	dst = interface_expandips(naddresses, addresses, 0);

	if (snprintf(inter->if_filter, sizeof(inter->if_filter),
		"(arp or ip or ip6 or proto 47 or "
		"(udp and src port 67 and dst port 68) or (ip %s%s%s))",
		dst ? "and (" : "", dst ? dst : "", dst ? ")" : "") >= 
	    sizeof(inter->if_filter))
		errx(1, "%s: pcap filter exceeds maximum length", __func__);

	inter->if_eth = eth_open(inter->if_ent.intf_name);
	if (inter->if_eth == NULL)
		errx(1, "%s: eth_open: %s", inter->if_ent.intf_name);

	snprintf(line, sizeof(line), " and not ether src %s",
	    addr_ntoa(&inter->if_ent.intf_link_addr));
	strlcat(inter->if_filter, line, sizeof(inter->if_filter));
}

void
interface_regular_filter(struct interface *inter,
    int naddresses, char **addresses)
{
	char *dst;

	/* Destination addresses only */
	dst = interface_expandips(naddresses, addresses, 1);

	if (snprintf(inter->if_filter, sizeof(inter->if_filter),
		"ip %s%s%s",
		dst ? "and (" : "", dst ? dst : "", dst ? ")" : "") >= 
	    sizeof(inter->if_filter))
		errx(1, "%s: pcap filter exceeds maximum length", __func__);
}

void
interface_init(char *dev, int naddresses, char **addresses)
{
	struct bpf_program fcode;
	char ebuf[PCAP_ERRBUF_SIZE];
	struct interface *inter;
	int time, promisc = 0;
	int pcap_fd;

	if (dev != NULL && interface_find(dev) != NULL) {
		fprintf(stderr, "Warning: Interface %s already configured\n",
		    dev);
		return;
	}

	/* creates a new interface - reserves memory and hangs the interface into the queue */
	/* at the moment this function returns an error if just an ipv6 address has been entered */
	inter = interface_new(dev);
	if (interface_filter == NULL) {
		/* 
		 * Compute the monitored IP addresses.  If we are ethernet,
		 * ignore our own packets.
		 */
		if (inter->if_ent.intf_link_addr.addr_type == ADDR_TYPE_ETH) {
			interface_ether_filter(inter, naddresses, addresses);

			/* 
			 * We open all interfaces before parsing the
			 * configuration, this means that for now, we
			 * open all ethernet interfaces in promiscuous
			 * mode.
			 */

			promisc = 1;
		} else {
			syslog(LOG_DEBUG,"Your interface type is not ethernet but %d",inter->if_ent.intf_link_addr.addr_type);
			interface_regular_filter(inter, naddresses, addresses);
		}
	} else {
		promisc = 1;

		/* Use an externally supplied filter */
		strlcpy(inter->if_filter, interface_filter,
		    sizeof(inter->if_filter));
	}

	/* In most cases, we want to compare the addresses directly */
	inter->if_addrbits = inter->if_ent.intf_addr.addr_bits;
	inter->if_ent.intf_addr.addr_bits = IP_ADDR_BITS;
	
	/* Don't open interfaces for real if we just want to verify config */
	if (interface_verify_config)
		return;
	
	time = interface_dopoll ? 10 : 30;
	if ((inter->if_pcap = pcap_open_live(inter->if_ent.intf_name,
		 inter->if_ent.intf_mtu + 40, promisc, time, ebuf)) == NULL)
		errx(1, "pcap_open_live: %s", ebuf);

	/* Get offset to packet data */
	/* pcap_dloff is a function of honeyd */
	inter->if_dloff = pcap_dloff(inter->if_pcap);

	/* we are only listening promisuously if no interface filter has been set
	and if the interface type is ethernet - thats not the case for a local interface? */	
	syslog(LOG_INFO, "listening %son %s: %s",
	    promisc ? "promiscuously " : "",
	    inter->if_ent.intf_name, inter->if_filter);

	/* 3rd parameter is the filter string to compile */
	if (pcap_compile(inter->if_pcap, &fcode, inter->if_filter, 1, 0) < 0 ||
	    pcap_setfilter(inter->if_pcap, &fcode) < 0)
		errx(1, "bad pcap filter: %s", pcap_geterr(inter->if_pcap));
	
#ifdef HAVE_PCAP_GET_SELECTABLE_FD
	pcap_fd = pcap_get_selectable_fd(inter->if_pcap);
#else
	pcap_fd = pcap_fileno(inter->if_pcap);
#endif
#if defined(BIOCIMMEDIATE)
	{
		int on = 1;
		DFPRINTF(2, (stderr, "%s: Setting BIOCIMMEDIATE on %d\n",
			__func__, pcap_fd));
		if (ioctl(pcap_fd, BIOCIMMEDIATE, &on) < 0)
			warn("BIOCIMMEDIATE");
	}
#endif
	/* this is the part where the interface callbacks get registered */
	if (!interface_dopoll) {
		event_set(&inter->if_recvev, pcap_fd,
		    EV_READ, interface_recv, inter);
		event_add(&inter->if_recvev, NULL);
	} else {
		struct timeval tv = HONEYD_POLL_INTERVAL;

		syslog(LOG_INFO, "switching to polling mode");
		/* interface_poll_recv also calls interface_recv
		   and adds itself as timed callback function - that is
		   resulting in a loop which is basically polling */
		evtimer_set(&inter->if_recvev, interface_poll_recv, inter);
		evtimer_add(&inter->if_recvev, &tv);
	}
	
}

/*
 * Expands several command line arguments into a complete pcap filter string.
 * Deals with normal CIDR notation and IP-IP ranges.
 */

static char *
interface_expandips(int naddresses, char **addresses, int dstonly)
{
	static char filter[1024];
	char line[1024], *p;
	struct addr dst;

	if (naddresses == 0)
		return (NULL);

	filter[0] = '\0';

	while (naddresses--) {
		/* Get current address */
		p = *addresses++;

		if (filter[0] != '\0') {
			if (strlcat(filter, " or ", sizeof(filter)) >= sizeof(filter))
				errx(1, "%s: too many address for filter", 
				    __func__);
		}

		/* XXX  addr_pton uses DNS and can block */
		if (addr_pton(p, &dst) != -1) {
			snprintf(line, sizeof(line), "%s%s%s",
			    dstonly ? "dst " : "",
			    dst.addr_bits != 32 ? "net ": "host ", p);
		} else {
			char *first, *second;
			struct addr astart, aend;
			struct in_addr in;
			ip_addr_t istart, iend;

			second = p;

			first = strsep(&second, "-");
			if (second == NULL)
				errx(1, "%s: Invalid network range: %s",
				    __func__, p);

			line[0] = '\0';
			if (addr_pton(first, &astart) == -1 ||
			    addr_pton(second, &aend) == -1)
				errx(1, "%s: bad addresses %s-%s", __func__,
				    first, second);
			if (addr_cmp(&astart, &aend) >= 0)
			    errx(1, "%s: inverted range %s-%s", __func__,
				first, second);

			/* Completely, IPv4 specific */
			istart = ntohl(astart.addr_ip);
			iend = ntohl(aend.addr_ip);
			while (istart <= iend) {
				char single[32];
				int count = 0, done = 0;
				ip_addr_t tmp;

				do {
					ip_addr_t bit = 1 << count;
					ip_addr_t mask;

					mask = ~(~0 << count);
					tmp = istart | mask;

					if (istart & bit)
						done = 1;

					if (iend < tmp) {
						count--;
						mask = ~(~0 << count);
						tmp = istart | mask;
						break;
					} else if (done)
						break;
					
					count++;
				} while (count < IP_ADDR_BITS);

				if (line[0] != '\0')
					strlcat(line, " or ", sizeof(line));
				in.s_addr = htonl(istart);
				snprintf(single, sizeof(single),
				    "dst net %s/%d",
				    inet_ntoa(in), 32 - count);

				strlcat(line, single, sizeof(line));

				istart = tmp + 1;
			}
		}
		
		if (strlcat(filter, line, sizeof(filter)) >= sizeof(filter))
			errx(1, "%s: too many address for filter", 
			    __func__);
	}

	return (filter);
}

/* Interface receiving functions */


/* this function gets called as soon as a packet arrives */
static void
interface_recv(int fd, short type, void *arg)
{
	struct interface *inter = arg;
	
	if (!interface_dopoll)
		event_add(&inter->if_recvev, NULL);

	/* dispatch the just received packet */
	/* the parameter inter->if_pcap was set in the main method with the result of pcap_open_live */
	if (pcap_dispatch(inter->if_pcap, -1, if_recv_cb, (u_char *)inter) < 0)
		syslog(LOG_ERR, "pcap_dispatch: %s",
		    pcap_geterr(inter->if_pcap));
}
 
static void
interface_poll_recv(int fd, short type, void *arg)
{
	struct interface *inter = arg;
	struct timeval tv = HONEYD_POLL_INTERVAL;

	evtimer_add(&inter->if_recvev, &tv);

	interface_recv(fd, type, arg);
}

/* Unittests */
static void
interface_test_insert_and_find(void)
{
	struct interface *inter;
	struct addr tmp;

	if ((inter = calloc(1, sizeof(struct interface))) == NULL)
		err(1, "%s: calloc", __func__);

	addr_pton("10.0.0.254", &inter->if_ent.intf_addr);
	inter->if_addrbits = 24;
	strlcpy(inter->if_ent.intf_name, "fxp0",
	    sizeof(inter->if_ent.intf_name));

	TAILQ_INSERT_TAIL(&interfaces, inter, next);

	addr_pton("10.0.0.1", &tmp);
	if ( inter != interface_find_responsible(&tmp) )
		errx(1, "interface_find_responsible failed");
	if ( inter != interface_find("fxp0") )
		errx(1, "interface_find failed");

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
interface_test(void)
{
	interface_test_insert_and_find();
}
