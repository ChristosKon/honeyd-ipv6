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

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <pcap.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <assert.h>

#undef timeout_pending
#undef timeout_initialized

#include <dnet.h>
#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "subsystem.h"
#include "personality.h"
#include "xprobe_assoc.h"
#include "ipfrag.h"
#include "ip6frag.h"
#include "router.h"
#include "network.h"
#include "tcp.h"
#include "udp.h"
#include "hooks.h"
#include "pool.h"
#include "plugins_config.h"
#include "plugins.h"
#include "interface.h"

#include <netinet/icmp6.h>
#include "icmp6.h"

#include "arp.h"
#include "gre.h"
#include "log.h"
#include "osfp.h"
#include "parser.h"
#include "ui.h"
#include "ethernet.h"
#include "tagging.h"
#include "stats.h"
#include "dhcpclient.h"
#include "rrdtool.h"
#include "histogram.h"
#include "update.h"
#include "util.h"
#include "randomipv6.h"

#ifdef HAVE_PYTHON
#include <Python.h>
#include "pyextend.h"
#include "pydataprocessing.h"
#include "pydatahoneyd.h"
#endif

/* TODO: does base honeyd need pthread? */
#include <pthread.h>

#define IPV6_RANDOM_MODE_DEACTIVATED 0
#define DEFAULT_RANDOM_IPV6_PROBABILITY 0.0
#define MAX_NUMBER_OF_IPV6_RANDOM_HOSTS
#define SIZE_OF_IPV6_FRAGMENT_HEADER 8


/* Prototypes */
void honeyd_tcp_timeout(int, short, void *);
void honeyd_udp_timeout(int, short, void *);
void honeyd_delay_cb(int, short, void *);
void honeyd_delay_cb6(int, short, void *);

enum forward honeyd_route_packet(struct ip_hdr *, u_int, struct addr *, struct addr *, int *);
enum forward honeyd_route_packet6(struct ip6_hdr *, u_int, struct addr *, struct addr *, int *);

void tcp_retrans_timeout(int, short, void *);
void icmp_error_send(struct template *, struct addr *, uint8_t, uint8_t, struct ip_hdr *, struct spoof);

/* IP6 specific prototypes */
void honeyd_recv_cb6(u_char *, const struct pcap_pkthdr *, const u_char *);

struct tree tcpcons;
struct conlru tcplru;
struct tree udpcons;
struct conlru udplru;

struct spoof no_spoof; /* spoof settings for default packet processing */

struct config config =
{
    NULL,
    PATH_HONEYDDATA "/nmap.prints",
    PATH_HONEYDDATA "/xprobe2.conf",
    PATH_HONEYDDATA "/nmap.assoc",
    PATH_HONEYDDATA "/pf.os",
    IPV6_RANDOM_MODE_DEACTIVATED,
    DEFAULT_RANDOM_IPV6_PROBABILITY,
    MAX_NUMBER_OF_IPV6_RANDOM_HOSTS
};

struct stats_network stats_network =
{
    0, /* input bytes */
    0 /* output bytes */
};

SPLAY_PROTOTYPE(tree, tuple, node, conhdr_compare);
SPLAY_GENERATE(tree, tuple, node, conhdr_compare);

struct rrdtool_drv *honeyd_rrd_drv;
struct rrdtool_db *honeyd_traffic_db;
struct event honeyd_rrd_ev;
FILE *honeyd_servicefp;
struct timeval honeyd_uptime;
static FILE *honeyd_logfp;
static ip_t *honeyd_ip;
struct pool *pool_pkt;
struct pool *pool_delay;
rand_t *honeyd_rand;
int honeyd_sig;
int honeyd_nconnects;
int honeyd_nchildren;
int honeyd_ttl = HONEYD_DFL_TTL;
struct tcp_con honeyd_tmp;
int honeyd_show_include_dir;
int honeyd_show_data_dir;
int honeyd_show_version;
int honeyd_show_usage;
int honeyd_debug;
uid_t honeyd_uid = 32767;
gid_t honeyd_gid = 32767;
int honeyd_needsroot; /* Need different IDs */
int honeyd_disable_webserver = 0;
int honeyd_disable_update = 0;
int honeyd_ignore_parse_errors = 0;
int honeyd_verify_config = 0;
int honeyd_webserver_fix_permissions = 0;
char *honeyd_webserver_address = "127.0.0.1";
int honeyd_webserver_port = 80;
char *honeyd_webserver_root = PATH_HONEYDDATA "/webserver/htdocs";
char *honeyd_rrdtool_path = PATH_RRDTOOL;

/* can be used by unittests to do bad stuff */
void (*honeyd_delay_callback)(int, short, void *) = honeyd_delay_cb;
void (*honeyd_delay_callback6)(int, short, void *) = honeyd_delay_cb6;

static char *logfile = NULL; /* Log file names */
static char *servicelog = NULL;


static struct option honeyd_long_opts[] =
{
    { "include-dir", 0, &honeyd_show_include_dir, 1 },
    { "data-dir", 0, &honeyd_show_data_dir, 1 },
    { "version", 0, &honeyd_show_version, 1 },
    { "help", 0, &honeyd_show_usage, 1 },
    { "webserver-address", required_argument, NULL, 'A' },
    { "webserver-port", required_argument, NULL, 'W' },
    { "webserver-root", required_argument, NULL, 'X' },
    { "rrdtool-path", required_argument, NULL, 'Y' },
    { "disable-webserver", 0, &honeyd_disable_webserver, 1 },
    { "disable-update", 0, &honeyd_disable_update, 1 },
    { "verify-config", 0, &honeyd_verify_config, 1 },
    { "ignore-parse-errors", 0, &honeyd_ignore_parse_errors, 1 },
    { "fix-webserver-permissions", 0, &honeyd_webserver_fix_permissions, 1 },
    { 0, 0, 0, 0 }
};

void usage(void)
{
    fprintf(stderr,
            "Usage: honeyd [OPTIONS] [net ...]\n\n"
            "where options include:\n"
            "  -d                     Do not daemonize, be verbose.\n"
            "  -P                     Enable polling mode.\n"
            "  -l logfile             Log packets and connections to logfile.\n"
            "  -s logfile             Logs service status output to logfile.\n"
            "  -i interface           Listen on interface.\n"
            "  -p file                Read nmap-style fingerprints from file.\n"
            "  -x file                Read xprobe-style fingerprints from file.\n"
            "  -a assocfile           Read nmap-xprobe associations from file.\n"
            "  -0 osfingerprints      Read pf-style OS fingerprints from file.\n"
            "  -u uid		  Set the uid Honeyd should run as.\n"
            "  -g gid		  Set the gid Honeyd should run as.\n"
            "  -f configfile          Read configuration from file.\n"
            "  -c host:port:name:pass Reports starts to collector.\n"
            "  --webserver-address=address Address on which webserver listens.\n"
            "  --webserver-port=port  Port on which webserver listens.\n"
            "  --webserver-root=path  Root of document tree.\n"
            "  --fix-webserver-permissions Change ownership and permissions.\n"
            "  --rrdtool-path=path    Path to rrdtool.\n"
            "  --disable-webserver    Disables internal webserver\n"
            "  --disable-update       Disables checking for security fixes.\n"
            "  --verify-config        Verify configuration file then exit.\n"
            "  -V, --version          Print program version and exit.\n"
            "  -h, --help             Print this message and exit.\n"
            "\n"
            "For plugin development:\n"
            "  --include-dir          Prints out header files directory and exits.\n"
            "  --data-dir             Prints out data/plug-in directory and exits.\n");

    exit(1);
}

/* XXX ches debug */
void print_spoof(char *msg, struct spoof s)
{
    char buf2[100], buf3[100];

    if (s.new_src.addr_type == ADDR_TYPE_NONE)
        strlcpy(buf2, "**no addr**", sizeof(buf2));
    else
        addr_ntop(&s.new_src, buf2, sizeof(buf2));

    if (s.new_dst.addr_type == ADDR_TYPE_NONE)
        strlcpy(buf3, "**no addr**", sizeof(buf3));
    else
        addr_ntop(&s.new_dst, buf3, sizeof(buf3));
}

void honeyd_settcp46(struct tcp_con *con, struct ip_hdr *ip,
                     struct ip6_hdr *ip6, struct tcp_hdr *tcp, int local)
{
    struct tuple *hdr = &con->conhdr;

    memset(hdr, 0, sizeof(struct tuple));
    if (ip != NULL )
    {
        con->addr_family=AF_INET;
        hdr->ip_src = ip->ip_src;
        hdr->ip_dst = ip->ip_dst;
        /* no ip6 addr has been set */
        hdr->src_addr.addr_type = ADDR_TYPE_NONE;
        hdr->dst_addr.addr_type = ADDR_TYPE_NONE;
    }
    else if (ip6 != NULL )
    {
        con->addr_family=AF_INET6;
        hdr->src_addr.addr_type = ADDR_TYPE_IP6;
        hdr->src_addr.addr_bits = IP6_ADDR_BITS;
        hdr->src_addr.addr_ip6 = ip6->ip6_src;
        hdr->dst_addr.addr_type = ADDR_TYPE_IP6;
        hdr->dst_addr.addr_bits = IP6_ADDR_BITS;
        hdr->dst_addr.addr_ip6 = ip6->ip6_dst;
    }

    hdr->sport = ntohs(tcp->th_sport);
    hdr->dport = ntohs(tcp->th_dport);
    hdr->type = SOCK_STREAM;
    hdr->local = local;
    con->rcv_flags = tcp->th_flags;
    con->cmd.pfd = -1;
    con->cmd.perrfd = -1;
}

void honeyd_settcp(struct tcp_con *con, struct ip_hdr *ip, struct tcp_hdr *tcp,
                   int local)
{
    honeyd_settcp46(con, ip, NULL, tcp, local);
}

void honeyd_settcp6(struct tcp_con *con, struct ip6_hdr *ip6,
                    struct tcp_hdr *tcp, int local)
{
    honeyd_settcp46(con, NULL, ip6, tcp, local);
}

void honeyd_setudp(struct udp_con *con, struct ip_hdr *ip, struct ip6_hdr *ip6,
                   struct udp_hdr *udp, int local, int addr_family)
{
    struct tuple *hdr = &con->conhdr;

    memset(hdr, 0, sizeof(struct tuple));
    if (addr_family == AF_INET6)
    {
        hdr->src_addr.addr_type = ADDR_TYPE_IP6;
        hdr->src_addr.addr_bits = IP6_ADDR_BITS;
        hdr->src_addr.addr_ip6 = ip6->ip6_src;

        hdr->dst_addr.addr_type = ADDR_TYPE_IP6;
        hdr->dst_addr.addr_bits = IP6_ADDR_BITS;
        hdr->dst_addr.addr_ip6 = ip6->ip6_dst;

        syslog(LOG_DEBUG, "setting up with src %s and dst %s ",
               addr_ntoa(&hdr->src_addr), addr_ntoa(&hdr->dst_addr));
    }
    else
    {
        hdr->ip_src = ip->ip_src;
        hdr->ip_dst = ip->ip_dst;

        hdr->src_addr.addr_type = ADDR_TYPE_NONE;
        hdr->dst_addr.addr_type = ADDR_TYPE_NONE;
    }
    hdr->sport = ntohs(udp->uh_sport);
    hdr->dport = ntohs(udp->uh_dport);
    hdr->type = SOCK_DGRAM;
    hdr->local = local;
    con->softerrors = 0;
    con->cmd.pfd = -1;
    con->cmd.perrfd = -1;

    TAILQ_INIT(&con->incoming);
}

struct tuple *
tuple_find(struct tree *root, struct tuple *key)
{
    return SPLAY_FIND(tree, root, key);
}

/*
 * Iterate over all connection objects.
 */

int tuple_iterate(struct conlru *head, int (*f)(struct tuple *, void *),
                  void *arg)
{
    struct tuple *conhdr;

    TAILQ_FOREACH(conhdr, head, next)
    {
        if ((*f)(conhdr, arg) == -1)
            return (-1);
    }

    return (0);
}

static void syslog_init(int argc, char *argv[])
{
    int options, i;
    char buf[MAXPATHLEN];

#ifdef LOG_PERROR
    options = LOG_PERROR | LOG_PID | LOG_CONS;
#else
    options = LOG_PID|LOG_CONS;
#endif
    openlog("honeyd", options, LOG_DAEMON);

    /* Create a string containing all the command line
     * arguments and pass it to syslog:
     */

    buf[0] = '\0';
    for (i = 1; i < argc; i++)
    {
        if (i > 1 && strlcat(buf, " ", sizeof(buf)) >= sizeof(buf))
            break;
        if (strlcat(buf, argv[i], sizeof(buf)) >= sizeof(buf))
            break;
    }

    syslog(LOG_NOTICE, "started with %s", buf);
}

/*
 * Update traffic statistics for honeyd.
 */

void honeyd_rrd_cb(int fd, short what, void *arg)
{
    static int count;
    char line[1024];
    struct event *ev = arg;
    struct timeval tv;

    snprintf(line, sizeof(line), "%f:%f",
             (double) count_get_minute(stats_network.input_bytes) / 60.0,
             (double) count_get_minute(stats_network.output_bytes) / 60.0);

    rrdtool_db_update(honeyd_traffic_db, NULL, line);

    timerclear(&tv);
    tv.tv_sec = 60;
    evtimer_add(ev, &tv);

    /* Create a graph every five minutes */
    if (count++ % 5 == 0)
    {
        char filename[1024];
        struct timeval tv;

        /* Hourly graph */
        timerclear(&tv);
        tv.tv_sec = -7200;

        snprintf(filename, sizeof(filename), "%s/graphs/traffic_hourly.gif",
                 honeyd_webserver_root);

        rrdtool_graph(honeyd_traffic_db, filename, &tv, NULL,
                      "DEF:inoctets=/tmp/honeyd_traffic.rrd:input:AVERAGE "
                      "DEF:outoctets=/tmp/honeyd_traffic.rrd:output:AVERAGE "
                      "AREA:inoctets#00FF00:\"In traffic\" "
                      "LINE1:outoctets#0000FF:\"Out traffic\"");

        /* Daily graph */
        timerclear(&tv);
        tv.tv_sec = -86400;

        snprintf(filename, sizeof(filename), "%s/graphs/traffic_daily.gif",
                 honeyd_webserver_root);

        rrdtool_graph(honeyd_traffic_db, filename, &tv, NULL,
                      "DEF:inoctets=/tmp/honeyd_traffic.rrd:input:AVERAGE "
                      "DEF:outoctets=/tmp/honeyd_traffic.rrd:output:AVERAGE "
                      "AREA:inoctets#00FF00:\"In traffic\" "
                      "LINE1:outoctets#0000FF:\"Out traffic\"");
    }
}

void honeyd_rrd_start(const char *rrdtool_path)
{
    /* Initialize our traffic stats for rrdtool */
    char *honeyd_traffic_filename = "/tmp/honeyd_traffic.rrd";
    if ((honeyd_rrd_drv = rrdtool_init(rrdtool_path)) == NULL )
        errx(1, "%s: cannot start rrdtool", __func__);
    if ((honeyd_traffic_db = rrdtool_db_start(honeyd_rrd_drv,
                             honeyd_traffic_filename, 60)) == NULL )
        errx(1, "%s: cannot create rrd db: %s", __func__,
             honeyd_traffic_filename);

    rrdtool_db_datasource(honeyd_traffic_db, "input", "GAUGE", 600);
    rrdtool_db_datasource(honeyd_traffic_db, "output", "GAUGE", 600);

    rrdtool_db_commit(honeyd_traffic_db);

    /* Start the periodic traffic update timer */
    evtimer_set(&honeyd_rrd_ev, honeyd_rrd_cb, &honeyd_rrd_ev);
    honeyd_rrd_cb(-1, EV_TIMEOUT, &honeyd_rrd_ev);
}

/*
 * Initializes data structures pertaining to the daemon
 */

void honeyd_init(void)
{
    struct rlimit rl;
    struct passwd *pwd;

    /* Record our start time */
    gettimeofday(&honeyd_uptime, NULL );

    /* Find the correct ids for nobody */
    if ((pwd = getpwnam("nobody")) != NULL )
    {
        honeyd_uid = pwd->pw_uid;
        honeyd_gid = pwd->pw_gid;
    }

    /* Initalize ongoing connection state */
    SPLAY_INIT(&tcpcons);
    TAILQ_INIT(&tcplru);
    SPLAY_INIT(&udpcons);
    TAILQ_INIT(&udplru);

    memset(&honeyd_tmp, 0, sizeof(honeyd_tmp));

    /* Raising file descriptor limits */
    rl.rlim_max = RLIM_INFINITY;
    rl.rlim_cur = RLIM_INFINITY;
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
    {
        /* Linux does not seem to like this */
        if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
            err(1, "getrlimit: NOFILE");
        rl.rlim_cur = rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
            err(1, "setrlimit: NOFILE");
    }
#ifdef RLIMIT_NPROC
    if (getrlimit(RLIMIT_NPROC, &rl) == -1)
        err(1, "getrlimit: NPROC");
    rl.rlim_max = rl.rlim_max / 2;
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NPROC, &rl) == -1)
        err(1, "setrlimit: NPROC");
#endif

    stats_network.input_bytes = count_new();
    stats_network.output_bytes = count_new();
}

#ifdef HAVE_PYTHON
static int
honeyd_is_webserver_enabled(void)
{
    if (honeyd_webserver_port <= 0)
        return 0;
    if (honeyd_disable_webserver)
        return 0;

    return (1);
}
#endif

void honeyd_exit(int status)
{
    honeyd_logend(honeyd_logfp);
    honeyd_logend(honeyd_servicefp);

    template_free_all(TEMPLATE_FREE_DEALLOCATE);

    interface_close_all();

    rand_close(honeyd_rand);
    ip_close(honeyd_ip);
    closelog();
    unlink(PIDFILE);

#ifdef HAVE_PYTHON
    if (honeyd_is_webserver_enabled())
        pyextend_webserver_exit();
    pyextend_exit();
#endif

    // added by oliver
    exit(status);
}

/* Encapsulate a packet into Ethernet */

void honeyd_ether_cb46(const struct interface * inter,
                       struct addr *dst_mac_addr, struct addr *src_mac_addr, void *arg,
                       int eth_type)
{
    struct ip_hdr *ip = NULL;
    struct ip6_hdr *ip6 = NULL;
    u_char pkt[HONEYD_MTU + 40]; /* XXX - Enough? */
    u_int len = 0, iplen = 0;

    switch (eth_type)
    {
    case ETH_TYPE_IP:
        ip = arg;
        iplen = ntohs(ip->ip_len);
        break;
    case ETH_TYPE_IPV6:
        ip6 = arg;
        iplen = ntohs(ip6->ip6_plen) + IP6_HDR_LEN;
        break;
    }

    eth_pack_hdr(pkt, dst_mac_addr->addr_eth, /* destination */
                 src_mac_addr->addr_eth, /* source */
                 eth_type);

    len = ETH_HDR_LEN + iplen;

    if (sizeof(pkt) < len)
    {
        syslog(LOG_WARNING, "%s: IP packet is larger than buffer: %d", __func__,
               len);
        goto out;
    }

    memcpy(pkt + ETH_HDR_LEN, arg, iplen);
    if (eth_send(inter->if_eth, pkt, len) != len)
    {
        syslog(LOG_ERR, "%s: couldn't send packet size %d: %m", __func__, len);
    }
    else
    {
        count_increment(stats_network.output_bytes, iplen);
    }

out: if (eth_type == ETH_TYPE_IPV6)
    {
        pool_free(pool_pkt, ip6);
    }
    else
    {
        pool_free(pool_pkt, ip);
    }
}

void honeyd_ether_cb(struct arp_req * req, int success, void *arg)
{
    honeyd_ether_cb46(req->inter, &req->ha, &req->src_ha, arg, ETH_TYPE_IP);
}

/*
 * arg is the ipv6 header
 */
void honeyd_ether_cb6(struct ndp_neighbor_req * req, int success, void * arg)
{
    honeyd_ether_cb46(req->inter, &req->target_mac_addr, &req->source_mac_addr,
                      arg, ETH_TYPE_IPV6);
}

/*
 * Delivers an IP packet to a specific interface.
 * Generates ARP request if necessary.
 */

void honeyd_deliver_ethernet(struct interface *inter, struct addr *src_pa,
                             struct addr *src_ha, struct addr *dst_pa, struct ip_hdr *ip,
                             u_int iplen)
{
    /* the arp structure is just used to store the mac addresses -very confusing */
    struct arp_req *req;

    ip_checksum(ip, iplen);

    /* Ethernet delivery if possible */
    if ((req = arp_find(dst_pa)) == NULL )
    {
        arp_request(inter, src_pa, src_ha, dst_pa, honeyd_ether_cb, ip);
    }
    else if (req->cnt == -1)
    {
        /*
         * The source MAC of the original requestor does not help
         * us here, but we can overwrite it with the MAC of this
         * honeypot without causing any harm.
         */
        req->src_ha = *src_ha;
        honeyd_ether_cb(req, 1, ip);
    }
    else
    {
        /*
         * Fall through in case that this packet needs
         * to be dropped.
         */
        pool_free(pool_pkt, ip);
    }
}

/*
 * Returs 1 if the passed type id is an ext header id, else false.
 */
int is_ext_hdr_id(int ext_hdr_id)
{
    int i;
    /* TODO: replace magic numbers */
    uint8_t ext_hdr_ids[] =
    { 0, 43, 44, 51, 50, 60, 59 };
    for (i = 0; i < sizeof(ext_hdr_ids); i++)
    {
        if (ext_hdr_ids[i] == ext_hdr_id)
            return 1;
    }
    return 0;
}

int get_ext_hdr_length(struct ip6_ext_hdr *ext_hdr) {
	/* ext len given in 8 octets + first 8 bytes */
	return ext_hdr->ext_len * 8 + 8;
}

/*
 * Sets the pointer to the next (ext) header of the package, and returns its position, if the header
 * could not be found then it returns -1
 */
int get_ip6_next_hdr(u_char **next_hdr, struct ip6_hdr *ip6,
                     uint8_t requested_next_hdr_id)
{
    u_char *pkt_ptr = (u_char *) (ip6 + 1);
    uint8_t nxt_ext_hdr_id;
    int position_in_pkt = IP6_HDR_LEN;
    int ext_hdr_len;

    if (ip6->ip6_nxt == requested_next_hdr_id)
    {
        *next_hdr = pkt_ptr;
        return IP6_HDR_LEN;
    }
    else if (!is_ext_hdr_id(ip6->ip6_nxt))
    {
        return -1;
    }

    /* walk through the package and try to find the requested header */
    while (pkt_ptr < ((u_char*) ip6) + ip6->ip6_plen)
    {
        nxt_ext_hdr_id = ((struct ip6_ext_hdr *) pkt_ptr)->ext_nxt;
        if (nxt_ext_hdr_id != requested_next_hdr_id && !is_ext_hdr_id(nxt_ext_hdr_id))
        {
            return -1;
        }
        ext_hdr_len = get_ext_hdr_length((struct ip6_ext_hdr *)pkt_ptr);
        pkt_ptr += ext_hdr_len;
        position_in_pkt += ext_hdr_len;
        if (nxt_ext_hdr_id == requested_next_hdr_id)
        {
            *next_hdr = pkt_ptr;
            return position_in_pkt;
        }

    }

    return -1;
}

u_int get_number_of_fragments(u_int iplen, u_int unfrag_fraghdr_size, u_int size_of_fragmentable_part)
{
	u_int number_of_fragments;
	/* calculate the number of fragmens */
	if ((iplen - unfrag_fraghdr_size) % (size_of_fragmentable_part) == 0)
	{
		number_of_fragments = (iplen - unfrag_fraghdr_size)
				/ (size_of_fragmentable_part);
	}
	else
	{
		number_of_fragments = ((iplen - unfrag_fraghdr_size)
				/ (size_of_fragmentable_part)) + 1;
	}
	return number_of_fragments;
}

void ip6_set_more_fragments_bit(u_int current_fragment_number,
		u_int number_of_fragments, struct ip6_ext_hdr* frag_hdr)
{
	/* set more fragments bit if needed */
	if (current_fragment_number != number_of_fragments - 1)
	{
		frag_hdr->ext_data.fragment.offlg |= IP6_MORE_FRAG;
	}
	else
	{
		frag_hdr->ext_data.fragment.offlg &= ~(IP6_MORE_FRAG);
	}
}


void ip6_copy_chunk_to_fragment(u_char *ip6_fragment_pkt, u_char *unfragmented_ip6_pkt,u_int fragment_size,
		u_int size_of_unfragmentable_part, u_int bytes_sent)
{
	u_char *start_of_fragmentable_part, *start_of_bytes_left;
	u_int unfrag_fraghdr_size = size_of_unfragmentable_part + SIZE_OF_IPV6_FRAGMENT_HEADER;
	start_of_fragmentable_part = ip6_fragment_pkt + unfrag_fraghdr_size;
	start_of_bytes_left = unfragmented_ip6_pkt + size_of_unfragmentable_part + bytes_sent;
	memcpy(start_of_fragmentable_part, start_of_bytes_left, fragment_size - unfrag_fraghdr_size);
}


/* TODO: path mtu discovery */
void ip6_send_fragments(const struct interface *inter, struct addr *src_mac_addr,
                        struct addr *target_mac_addr, struct ip6_hdr *ip6, u_int iplen)
{
    struct ip6_hdr *ip6_fragment;
    u_char *unfragmented_ip6_pkt, *ip6_fragment_pkt;
    struct ip6_ext_hdr *frag_hdr, *last_unfragmentable_ext_hdr = NULL;
    u_int number_of_fragments, fragment_size, size_of_fragmentable_part, current_fragment_number;
    u_int bytes_left = iplen - IP6_HDR_LEN, bytes_sent = 0, is_not_last_fragment;

    u_int size_of_unfragmentable_part = get_size_of_unfragmentable_part(ip6);
    u_int unfrag_fraghdr_size = size_of_unfragmentable_part + SIZE_OF_IPV6_FRAGMENT_HEADER;

    unfragmented_ip6_pkt = (u_char *) ip6;

    /* calculate the size of the fragmentable part (it needs to be a multiple of 8) */
    size_of_fragmentable_part = HONEYD_MTU - unfrag_fraghdr_size;
    size_of_fragmentable_part -= (size_of_fragmentable_part % 8);


	number_of_fragments = get_number_of_fragments(iplen, unfrag_fraghdr_size,size_of_fragmentable_part);

    for (current_fragment_number = 0; current_fragment_number < number_of_fragments; current_fragment_number++)
    {

        ip6_fragment = (struct ip6_hdr *) pool_alloc(pool_pkt);
        ip6_fragment_pkt = (u_char*) ip6_fragment;

        is_not_last_fragment = bytes_left > size_of_fragmentable_part;
        if (is_not_last_fragment)
        {
            fragment_size = size_of_fragmentable_part + unfrag_fraghdr_size;
            bytes_left -= size_of_fragmentable_part;
        }
        else
        {
            fragment_size = bytes_left + unfrag_fraghdr_size;
            bytes_left = 0;
        }

        /* copy unfragmentable part */
        memset(ip6_fragment_pkt,0,HONEYD_MTU);
        memcpy(ip6_fragment_pkt, unfragmented_ip6_pkt, size_of_unfragmentable_part);
        ip6_fragment->ip6_plen = htons(fragment_size - IP6_HDR_LEN);

        /* create the fragment header */
        frag_hdr = (struct ip6_ext_hdr*) (ip6_fragment_pkt + size_of_unfragmentable_part);
        get_last_unfragmentable_ext_hdr(ip6_fragment, last_unfragmentable_ext_hdr);
        if (last_unfragmentable_ext_hdr == NULL )
        {
            frag_hdr->ext_nxt = ip6->ip6_nxt;
        }
        else
        {
            frag_hdr->ext_nxt = last_unfragmentable_ext_hdr->ext_nxt;
        }

        /* set the fragment offset */
        frag_hdr->ext_data.fragment.offlg |= (htons(bytes_sent) & IP6_OFF_MASK);

        /* copy the data chunk */
        ip6_copy_chunk_to_fragment(ip6_fragment_pkt,unfragmented_ip6_pkt,fragment_size,size_of_unfragmentable_part,bytes_sent);
        bytes_sent += fragment_size - unfrag_fraghdr_size;

        /* set the next header to fragment header */
        if (last_unfragmentable_ext_hdr == NULL )
        {
            ip6_fragment->ip6_nxt = IPPROTO_FRAGMENT;
        }
        else
        {
            last_unfragmentable_ext_hdr->ext_nxt = IPPROTO_FRAGMENT;
        }

        ip6_set_more_fragments_bit(current_fragment_number, number_of_fragments,frag_hdr);
        honeyd_deliver_ethernet6(inter, src_mac_addr, target_mac_addr, ip6_fragment, fragment_size);
    }

    return;
}

int is_fragmented_ipv6_packet(struct ip6_hdr *ip6)
{
	u_char *next_hdr = NULL;
	return get_ip6_next_hdr(&next_hdr, ip6, IPPROTO_FRAGMENT) != -1;
}

/***
 * Function requires valid router advertisements
 */
int is_ip6_addr_in_our_network(struct addr *ip6_addr)
{
	struct router_advertisement *router_adv = NULL;
	struct addr target_net;
	struct addr ip6_addr_modified_bits = *ip6_addr;
	router_adv = find_router_adv();

	if (router_adv != NULL)
	{
		ip6_addr_modified_bits.addr_bits = router_adv->prefix_len;
	    addr_net(&ip6_addr_modified_bits, &target_net);
	    if (addr_cmp(&target_net, &router_adv->prefix) != 0)
	    {
	         return 0;
	    }
	}
	return 1;
}


void ip6_deliver_packet_to_local_neighbor(const struct interface *inter,struct ip6_hdr *ip6,
		struct addr *source_mac_addr, struct addr *source_ip_addr, struct addr *target_ip_addr)
{
	struct router *gw = NULL;
	struct ndp_neighbor_req *ndp_req = ndp_neighbor_find(target_ip_addr);
	struct template *gw_template = NULL;

	if (ndp_req != NULL )
	{
	     honeyd_ether_cb46(inter, &ndp_req->target_mac_addr, source_mac_addr, ip6, ETH_TYPE_IPV6);
	}
	else
	{
		/* send packet with gateway source or host source depending on whether we use a gateway */
	    if (router_used)
	    {
	        gw = entry_routers_ip6->data;
	        if (gw != NULL )
	        {
	              gw_template = template_find(addr_ntoa(&gw->addr));
	              if (gw_template != NULL )
	              {
	                 icmp6_send_neighbor_sol(inter, &gw->addr, gw_template->ethernet_addr, target_ip_addr, honeyd_ether_cb6, ip6);
	              }
	         }
	    }
	    else
	    {
	         icmp6_send_neighbor_sol(inter, source_ip_addr, source_mac_addr,  target_ip_addr, honeyd_ether_cb6, ip6);
	    }
	 }
}


void ip6_deliver_packet_to_router(const struct interface *inter, struct ip6_hdr *ip6,struct addr *source_mac_addr)
{
	struct router_advertisement *router_adv = NULL;
	router_adv = find_router_adv();
	if (router_adv != NULL )
	{
	    honeyd_ether_cb46(inter, &router_adv->src_eth_addr, source_mac_addr, ip6, ETH_TYPE_IPV6);
	}
	else
	{
	     syslog(LOG_DEBUG, "cannot send packet because no ethernet address and router advertisement is available...");
	 }
}

void honeyd_deliver_ethernet6(const struct interface *inter,
                              struct addr *source_mac_addr, struct addr *target_mac_addr,
                              struct ip6_hdr *ip6, u_int iplen)
{
    struct addr target_ip_addr, source_ip_addr;
    int target_in_same_net = 1;


    if (!is_fragmented_ipv6_packet(ip6))
    {
        ip6_checksum(ip6, iplen);
    }

    /* fragment if necessary  */
    if (iplen > HONEYD_MTU)
    {
        ip6_send_fragments(inter, source_mac_addr, target_mac_addr, ip6, iplen);
        return;
    }

    /* check if the target ip address is located within our network */
    ip6_addr_t_to_addr(&target_ip_addr,&ip6->ip6_dst);
    ip6_addr_t_to_addr(&source_ip_addr,&ip6->ip6_src);


    /* if we know the target mac address already just send the packet */
    if (target_mac_addr != NULL )
    {
          honeyd_ether_cb46(inter, target_mac_addr, source_mac_addr, ip6, ETH_TYPE_IPV6);
          return;
    }

    target_in_same_net = is_ip6_addr_in_our_network(&target_ip_addr);
    if (target_in_same_net)
    {
    	ip6_deliver_packet_to_local_neighbor(inter,ip6,source_mac_addr, &source_ip_addr, &target_ip_addr);
    }
    else
    {
    	ip6_deliver_packet_to_router(inter, ip6,source_mac_addr);
    }
}

/*
 * Makes sure that we end up owning the memory referenced by
 * the delay descriptor.  We either tell to not free the
 * memory or just make our own copy.
 */

struct ip_hdr *
honeyd_delay_own_memory(struct delay *delay, struct ip_hdr *ip, u_int iplen)
{
    /* If we are not supposed to free the buffer then we do not own it */
    if (!(delay->flags & DELAY_FREEPKT))
    {
        void *tmp = pool_alloc(pool_pkt);

        memcpy(tmp, ip, iplen);
        ip = tmp;
    }
    else
    {
        /*
         * We are handling the memory ourselves: if we
         * delegate the memory to the ARP handler, it will get
         * freed later.
         */
        delay->flags &= ~DELAY_FREEPKT;
    }

    return (ip);
}

/**
 * XXX do we want to merge this function with honeyd_delay_own_memory?
 */
struct ip6_hdr *
honeyd_delay_own_memory6(struct delay *delay, struct ip6_hdr *ip6, u_int iplen)
{
    /* If we are not supposed to free the buffer then we do not own it */
    if (!(delay->flags & DELAY_FREEPKT))
    {
        void *tmp = pool_alloc(pool_pkt);

        memcpy(tmp, ip6, iplen);
        ip6 = tmp;
    }
    else
    {
        /*
         * We are handling the memory ourselves: if we
         * delegate the memory to the ARP handler, it will get
         * freed later.
         */
        delay->flags &= ~DELAY_FREEPKT;
    }

    return (ip6);
}

/*
 * This function delivers the actual packet to the network.
 * It supports internal delivery, external delivery via ip_send
 * and external delivery via ethernet encapsulation.
 *
 * This function handles the following cases:
 * - TTL is 0: send ICMP time exceeded in transit message
 * - External: Packet is delivered to the real network
 * - Tunnel: Packet is GRE encapsulated and sent to a remote location
 * - Ethernet: A physical machine has been integrate into the virtual
 *	routing topology and we need to ethernet encapsulate the packet.
 * - Arp: The destination machine is configured to be on the physical link,
 *    so arp for it and ethernet encapsulate the packet.
 * - Everything else:  The packet is delivered internally after potential
 *    fragment reassembly.
 *
 * It needs to unreference the passed template value.
 */

static __inline void honeyd_send_normally(struct ip_hdr *ip, u_int iplen)
{
    ip_checksum(ip, iplen);

    if (ip_send(honeyd_ip, ip, iplen) != iplen)
    {
        int level = LOG_ERR;
        if (errno == EHOSTDOWN || errno == EHOSTUNREACH)
            level = LOG_DEBUG;
        syslog(level, "couldn't send packet: %m");
    }
    else
    {
        count_increment(stats_network.output_bytes, iplen);
    }
}

void honeyd_delay_cb(int fd, short which, void *arg)
{
    struct delay *delay = arg;
    struct ip_hdr *ip = delay->ip;
    struct template *tmpl = delay->tmpl;
    u_int iplen = delay->iplen;

    if (!ip->ip_ttl)
    {
        /* Fix up TTL */
        ip->ip_ttl++;
        ip_checksum(ip, ip->ip_hl << 2);
        icmp_error_send(tmpl, &delay->src, ICMP_TIMEXCEED,
                        ICMP_TIMEXCEED_INTRANS, ip, delay->spoof);
    }
    else if (delay->flags & DELAY_UNREACH)
    {
        /* Fix up TTL */
        ip->ip_ttl++;
        ip_checksum(ip, ip->ip_hl << 2);
        icmp_error_send(tmpl, &delay->src, ICMP_UNREACH, ICMP_UNREACH_NET, ip,
                        delay->spoof);
        /* this is if we have to delay the request to an external machine */
    }
    else if (delay->flags & DELAY_EXTERNAL)
    {
        struct addr dst;
        addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);

        /* This is the source template */
        if (tmpl != NULL && tmpl->ethernet_addr != NULL
                && interface_find_responsible(&dst) == tmpl->inter)
        {
            struct addr src;

            /* To do ARP, we need to know all this information */
            addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src,
                      IP_ADDR_LEN);

            ip = honeyd_delay_own_memory(delay, ip, iplen);

            /* This function computes the IP checksum for us */
            honeyd_deliver_ethernet(tmpl->inter, &src, tmpl->ethernet_addr,
                                    &dst, ip, iplen);
        }
        else
        {
            honeyd_send_normally(ip, iplen);
        }
    }
    else if (delay->flags & DELAY_TUNNEL)
    {
        ip_checksum(ip, iplen);

        if (gre_encapsulate(honeyd_ip, &delay->src, &delay->dst, ip, iplen)
                == -1)
            syslog(LOG_ERR, "couldn't GRE encapsulate packet: %m");
        else
            count_increment(stats_network.output_bytes, iplen);
        /* Not sure but I think the delay ethernet flag gets set for external machines too */
    }
    else if (delay->flags & DELAY_ETHERNET)
    {
        extern struct network *reverse;
        struct interface *inter = tmpl->inter;
        struct router *router;
        struct addr addr;

        /*
         * If a physical honeypot has been integrated into the
         * virtual routing topology, we need to find the
         * corresponding router.
         */
        addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
        router = network_lookup(reverse, &addr);
        if (router == NULL )
            errx(1, "%s: bad configuration", __func__);

        /*
         * If we are routing for an external sender, then we
         * might have to copy the packet into an allocated
         * buffer.
         */

        ip = honeyd_delay_own_memory(delay, ip, iplen);
        /* This function computes the IP checksum for us */
        honeyd_deliver_ethernet(inter, &router->addr,
                                &inter->if_ent.intf_link_addr, &addr, ip, iplen);
        /* this should be the most used condition */
    }
    else
    {
        struct addr addr;
        uint16_t ipoff;

        template_free(tmpl);

        addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);

        /* Internal delivery */
        tmpl = template_find_best(addr_ntoa(&addr), ip, iplen);
        tmpl = template_ref(tmpl);

        /* Check for fragmentation */
        ipoff = ntohs(ip->ip_off);
        if ((ipoff & IP_OFFMASK) || (ipoff & IP_MF))
        {
            struct ip_hdr *nip;
            u_short niplen;

            if (ip_fragment(tmpl, ip, iplen, &nip, &niplen) == 0)
                honeyd_dispatch(tmpl, nip, niplen);
        }
        else
            honeyd_dispatch(tmpl, ip, iplen);
    }

    if (delay->flags & DELAY_FREEPKT)
        pool_free(pool_pkt, ip);
    template_free(tmpl);

    if (delay->flags & DELAY_NEEDFREE)
        pool_free(pool_delay, delay);
}

/*
 * There is no ip6_send, hence we need to write an equivalent function for ipv6
 */
void honeyd_send_normally6(struct ip6_hdr *ip6, int iplen)
{
    struct addr src, dst;
    struct template *tmpl = NULL;
    struct router * gw;

    ip6_addr_t_to_addr(&src,&ip6->ip6_src);
    ip6_addr_t_to_addr(&dst,&ip6->ip6_dst);

    if (router_used)
    {
        gw = network_lookup(entry_routers_ip6, &src);
        /* just take the first entry router on the list */
        if (gw == NULL )
        {
            gw = entry_routers_ip6->data;
        }

        if (gw == NULL )
        {
            syslog(LOG_DEBUG, "honeyd_send_normally6: could not find a gateway for %s, %d", addr_ntoa(&src), ip6->ip6_hlim);
            return;
        }

        /* find the entry routers template to get the interface and the ethernet address */
        tmpl = template_find(addr_ntoa(&gw->addr));
    }
    else
    {
        tmpl = template_find(addr_ntoa(&src));
    }


    if (tmpl != NULL && tmpl->inter != NULL )
    {
        honeyd_deliver_ethernet6(tmpl->inter, tmpl->ethernet_addr, NULL, ip6, iplen);
    }
    else
    {
        syslog(LOG_DEBUG,
               "could not send packet because source or the ethernet address of the source is unknown");
    }

}


void ip6_delay_external(struct delay *delay)
{
	struct addr src, dst;
	struct ip6_hdr *ip6 = delay->ip6;
	struct template *tmpl = delay->tmpl;
	u_int iplen = delay->iplen, is_packet_for_hardware_interface;
	addr_pack(&dst, ADDR_TYPE_IP6, IP6_ADDR_BITS, &ip6->ip6_dst, IP6_ADDR_LEN);
	is_packet_for_hardware_interface = tmpl != NULL && tmpl->ethernet_addr != NULL && interface_find_responsible(&dst) == tmpl->inter;
	if (is_packet_for_hardware_interface)
	{
	    ip6_addr_t_to_addr(&src,&ip6->ip6_src);
	    ip6 = honeyd_delay_own_memory6(delay, ip6, iplen);
	    honeyd_deliver_ethernet6(tmpl->inter, tmpl->ethernet_addr, NULL, ip6, iplen);
	}
	else
	{
	    honeyd_send_normally6(ip6, iplen);
	}
}

void ip6_delay_internal(struct delay *delay)
{
	struct ip6_hdr *ip6 = delay->ip6;
	struct template *tmpl = delay->tmpl;
	struct addr addr;
	struct ip6_ext_hdr *frag_hdr = NULL;

	template_free(tmpl);

	addr_pack(&addr, ADDR_TYPE_IP6, IP6_ADDR_BITS, &ip6->ip6_dst, IP6_ADDR_LEN);

	/* Internal delivery */
	tmpl = template_find(addr_ntoa(&addr));
	tmpl = template_ref(tmpl);

	/* Check for fragmentation */
	get_ip6_next_hdr((u_char**) &frag_hdr, ip6, IPPROTO_FRAGMENT);
	if (frag_hdr != NULL )
	{
		/* tmpl may be null */
		/* if packet assembling is not finished the return */
		if (ip6_fragment(tmpl, &ip6, frag_hdr))
		{
			honeyd_dispatch6(tmpl, ip6);
		}
	}
	else
	{
		honeyd_dispatch6(tmpl, ip6);
	}
}

void ip6_delay_ethernet(struct delay *delay)
{
	extern struct network *reverse6;
	struct ip6_hdr *ip6 = delay->ip6;
	struct template *tmpl = delay->tmpl;
	struct interface *inter = tmpl->inter;
	struct router *router;
	struct addr addr;
	u_int iplen = delay->iplen;

	/*
	 * If a physical honeypot has been integrated into the
	 * virtual routing topology, we need to find the
	 * corresponding router.
	 */
	ip6_addr_t_to_addr(&addr, &ip6->ip6_dst);
	router = network_lookup(reverse6, &addr);
	if (router == NULL )
		errx(1, "%s: bad configuration", __func__);

	/*
	 * If we are routing for an external sender, then we
	 * might have to copy the packet into an allocated
	 * buffer.
	 */

	ip6 = honeyd_delay_own_memory6(delay, ip6, iplen);

	/* This function computes the IP checksum for us */
	honeyd_deliver_ethernet6(inter, &router->addr,
			&inter->if_ent.intf_link_addr, ip6, iplen);

	/* XXX deliver ethernet automatically frees the pool, hence we need
	 not to free the pool when using honeyd_send_normally6, but in this
	 case an explicit free is needed, this is very confusing
	 - should the ethernet send function really do a clear?  */
	if (delay->flags & DELAY_FREEPKT)
	{
		pool_free(pool_pkt, ip6);
	}
	template_free(tmpl);
	/* this should be the most used condition */
}



void honeyd_delay_cb6(int fd, short which, void *arg)
{
    struct delay *delay = arg;
    struct ip6_hdr *ip6 = delay->ip6;
    struct template *tmpl = delay->tmpl; 

    if (!ip6->ip6_hlim)
    {
        icmp6_error_send(&delay->src, ip6, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT);
    }
    else if (delay->flags & DELAY_UNREACH)
    {
        icmp6_error_send(&delay->src, ip6, ICMP6_DST_UNREACH,ICMP6_DST_UNREACH_ADDR);
    }
    else if (delay->flags & DELAY_EXTERNAL)
    {
        ip6_delay_external(delay);
    }
    else if (delay->flags & DELAY_TUNNEL)
    {
        syslog(LOG_DEBUG, "NOT YET IMPLEMENTED: tunnel packet");
    }
    else if (delay->flags & DELAY_ETHERNET)
    {
       ip6_delay_ethernet(delay);
    }
    else
    {

        ip6_delay_internal(delay);
    }

    if (delay->flags & DELAY_NEEDFREE)
        pool_free(pool_delay, delay);
    /* TODO: verify */
    template_free(tmpl);
}

/*
 * Delays a packet for a specified amount of ms to simulate routing delay.
 * Host is used for the router that might generate a XCEED message.
 */

void honeyd_delay_packet46(struct template *tmpl, struct ip_hdr *ip,
                           struct ip6_hdr *ip6, u_int iplen, const struct addr *src,
                           const struct addr *dst, int ms, int flags, struct spoof spoof,
                           int addr_family)
{
    struct delay *delay, tmp_delay;
    struct timeval tv;

    if (ms)
    {
        delay = pool_alloc(pool_delay);
        flags |= DELAY_NEEDFREE;

        /*
         * If the IP packet is not allocated separately, we
         * need to allocate it here.
         */
        if ((flags & DELAY_FREEPKT) == 0)
        {
            void *tmp;

            if (iplen < HONEYD_MTU)
                tmp = pool_alloc(pool_pkt);
            else
                tmp = pool_alloc_size(pool_pkt, iplen);

            if (addr_family == AF_INET)
            {
                memcpy(tmp, ip, iplen);
                ip = tmp;
            }
            else if (addr_family == AF_INET6)
            {
                memcpy(tmp, ip6, iplen);
                ip6 = tmp;
            }

            flags |= DELAY_FREEPKT;
        }
    }
    else
    {
        memset(&tmp_delay, 0, sizeof(tmp_delay));
        delay = &tmp_delay;
    }

    if (addr_family == AF_INET)
    {
        delay->ip = ip;
    }
    if (addr_family == AF_INET6)
    {
        delay->ip6 = ip6;
    }

    delay->iplen = iplen;

    if (src != NULL )
        delay->src = *src;
    if (dst != NULL )
        delay->dst = *dst;

    delay->tmpl = template_ref(tmpl);
    delay->flags = flags;
    delay->spoof = spoof;

    if (ms)
    {
        if (addr_family == AF_INET)
            evtimer_set(&delay->timeout, honeyd_delay_callback, delay);
        if (addr_family == AF_INET6)
            evtimer_set(&delay->timeout, honeyd_delay_callback6, delay);

        timerclear(&tv);
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        evtimer_add(&delay->timeout, &tv);
    }
    else
    {
        if (addr_family == AF_INET)
            honeyd_delay_callback(-1, EV_TIMEOUT, delay);
        if (addr_family == AF_INET6)
            honeyd_delay_callback6(-1, EV_TIMEOUT, delay);
    }
}

void honeyd_delay_packet(struct template *tmpl, struct ip_hdr *ip, u_int iplen,
                         const struct addr *src, const struct addr *dst, int ms, int flags,
                         struct spoof spoof)
{
    honeyd_delay_packet46(tmpl, ip, NULL, iplen, src, dst, ms, flags, spoof,
                          AF_INET);

}

void honeyd_delay_packet6(struct template *tmpl, struct ip6_hdr *ip6,
                          u_int iplen, const struct addr *src, const struct addr *dst, int ms,
                          int flags, struct spoof spoof)
{
    honeyd_delay_packet46(tmpl, NULL, ip6, iplen, src, dst, ms, flags, spoof,
                          AF_INET6);
}

/*
 * This function allows us to deliver packets to virtual hosts as well
 * as to external hosts.  If virtual routing topologies are enabled,
 * characteristics like packet loss, latency and ttl decrements are
 * taken into consideration.
 */
void honeyd_ip_send(u_char *pkt, u_int iplen, struct spoof spoof)
{
    struct template *tmpl = NULL;
    struct ip_hdr *ip = (struct ip_hdr *) pkt;
    enum forward res = FW_EXTERNAL;
    int delay = 0, flags = 0;
    struct addr addr, src;

    print_spoof("honeyd_ip_send", spoof);

    if (iplen > HONEYD_MTU)
    {
        u_short off = ntohs(ip->ip_off);
        if ((off & IP_DF) == 0)
            ip_send_fragments(HONEYD_MTU, ip, iplen, spoof);
        goto drop;
    }

    if (spoof.new_dst.addr_type != ADDR_TYPE_NONE)
        ip->ip_dst = spoof.new_dst.addr_ip;

    addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
    addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);

    /* Find the template for the external address */
    tmpl = template_find_best(addr_ntoa(&addr), ip, iplen);
    if (tmpl != NULL && tmpl->flags & TEMPLATE_EXTERNAL)
        flags |= DELAY_ETHERNET;

    /* But all sending decisions are really based on the source template */
    tmpl = template_find_best(addr_ntoa(&src), ip, iplen);

    if (router_used)
    {
        extern struct network *reverse;
        struct router *router;

        router = network_lookup(reverse, &src);
        if (router == NULL )
        {
            syslog(LOG_NOTICE, "No reverse routing map for %s",
                   addr_ntoa(&src));
            goto drop;
        }

        /*
         * If the router itself is sending the packet, the first
         * routing table lookup does not decrease the ttl.
         */
        if (addr_cmp(&src, &router->addr) == 0)
            ip->ip_ttl++; /* XXX - Ugly hack */

        /* if a spoofed src address in config file has been set the update the addr  */
        if (spoof.new_src.addr_type != ADDR_TYPE_NONE)
            ip->ip_src = spoof.new_src.addr_ip;
        res = honeyd_route_packet(ip, iplen, &router->addr, &addr, &delay);
        if (res == FW_DROP)
            goto drop;
    }

    /* Remember that the packet buffer has to be freed at the end */
    flags |= DELAY_FREEPKT;
    if (res == FW_EXTERNAL)
        flags |= DELAY_EXTERNAL;

    if (spoof.new_src.addr_type != ADDR_TYPE_NONE)
    {
        ip->ip_src = spoof.new_src.addr_ip;
    }
    if (spoof.new_dst.addr_type != ADDR_TYPE_NONE)
        ip->ip_dst = spoof.new_dst.addr_ip;

    /* Delay the packet if necessary, otherwise deliver it directly */
    honeyd_delay_packet(tmpl, ip, iplen, NULL, NULL, delay, flags, spoof);
    return;

drop:
    /* Deallocate the packet */
    pool_free(pool_pkt, pkt);
}

void honeyd_ip6_send(u_char *pkt, u_int iplen, struct spoof spoof)
{

    struct template *tmpl = NULL;
    struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    enum forward res = FW_EXTERNAL;
    int delay = 0, flags = 0;
    struct addr addr, src;

    print_spoof("honeyd_ip_send", spoof);

    if (spoof.new_dst.addr_type != ADDR_TYPE_NONE)
        ip6->ip6_dst = spoof.new_dst.addr_ip6;

    ip6_addr_t_to_addr(&addr, &ip6->ip6_dst);
    ip6_addr_t_to_addr(&src, &ip6->ip6_src);

    /* Find the template for the external address */
    tmpl = template_find(addr_ntoa(&addr));
    if (tmpl != NULL && tmpl->flags & TEMPLATE_EXTERNAL)
    {
        flags |= DELAY_ETHERNET;
    }

    /* But all sending decisions are really based on the source template */
    tmpl = template_find(addr_ntoa(&src));

    if (router_used)
    {
        extern struct network *reverse6;
        struct router *router;
        router = network_lookup(reverse6, &src);
        if (router == NULL )
        {
            syslog(LOG_NOTICE, "No reverse routing map for %s",
                   addr_ntoa(&src));
            goto drop;
        }

        res = honeyd_route_packet6(ip6, iplen, &router->addr, &addr, &delay);
        /*
         * If the router itself is sending the packet, the first
         * routing table lookup does not decrease the ttl.
         */

        if (addr_cmp(&src, &router->addr) == 0)
            ip6->ip6_hlim++; /* XXX - Ugly hack */

        if (res == FW_DROP)
            goto drop;
    }

    /* Remember that the packet buffer has to be freed at the end */
    flags |= DELAY_FREEPKT;
    if (res == FW_EXTERNAL)
        flags |= DELAY_EXTERNAL;

    /* Delay the packet if necessary, otherwise deliver it directly */
    honeyd_delay_packet6(tmpl, ip6, iplen, NULL, NULL, delay, flags, spoof);
    return;

drop:
    /* Deallocate the packet */
    syslog(LOG_DEBUG, "packet drop");
    pool_free(pool_pkt, pkt);
}

static void connection_insert(struct tree *tree, struct conlru *head,
                              struct tuple *hdr)
{
    SPLAY_INSERT(tree, tree, hdr);
    TAILQ_INSERT_HEAD(head, hdr, next);
}

static void connection_remove(struct tree *tree, struct conlru *head,
                              struct tuple *hdr)
{
    SPLAY_REMOVE(tree, tree, hdr);
    TAILQ_REMOVE(head, hdr, next);

    evtimer_del(&hdr->timeout);
}

/* Called when a connection received data and has not been idle */

static void connection_update(struct conlru *head, struct tuple *hdr)
{
    TAILQ_REMOVE(head, hdr, next);
    TAILQ_INSERT_HEAD(head, hdr, next);

    generic_timeout(&hdr->timeout, HONEYD_IDLE_TIMEOUT);
}
/**
 * Creates a new TCP connection.
 */
struct tcp_con *
tcp_new46(struct ip_hdr *ip, struct ip6_hdr *ip6, struct tcp_hdr *tcp,
          int local)
{
    struct tcp_con *con;
    if (honeyd_nconnects >= HONEYD_MAX_CONNECTS)
    {
        /*
         * We seem to be in an overload situation - remove the
         * oldest connection available.
         */
        con = (struct tcp_con *) TAILQ_LAST(&tcplru, conlru);
        tcp_free(con);
    }

    if ((con = calloc(1, sizeof(struct tcp_con))) == NULL )
    {
        syslog(LOG_WARNING, "calloc: %m");
        return (NULL );
    }

    honeyd_nconnects++;
    if (ip6 == NULL )
    {
        con->addr_family = AF_INET;
        honeyd_settcp(con, ip, tcp, local);
    }
    else
    {
        con->addr_family = AF_INET6;
        honeyd_settcp6(con, ip6, tcp, local);
    }

    evtimer_set(&con->conhdr.timeout, honeyd_tcp_timeout, con);
    evtimer_set(&con->retrans_timeout, tcp_retrans_timeout, con);

    connection_insert(&tcpcons, &tcplru, &con->conhdr);

    honeyd_log_flownew(honeyd_logfp, IP_PROTO_TCP, &con->conhdr);

    return (con);
}

struct tcp_con *
tcp_new(struct ip_hdr *ip, struct tcp_hdr *tcp, int local)
{
    return tcp_new46(ip, NULL, tcp, local);
}

struct tcp_con *
tcp_new6(struct ip6_hdr *ip6, struct tcp_hdr *tcp, int local)
{
    return tcp_new46(NULL, ip6, tcp, local);
}

void tcp_free(struct tcp_con *con)
{

    struct port *port = con->port;
    struct port_encapsulate *pending = con->conhdr.pending;

    if (pending != NULL )
        port_encapsulation_free(pending);

    if (port != NULL )
        port_free(port->subtmpl, port);

    connection_remove(&tcpcons, &tcplru, &con->conhdr);

    hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM, &con->conhdr, NULL, 0);
    honeyd_log_flowend(honeyd_logfp, IP_PROTO_TCP, &con->conhdr);

    evtimer_del(&con->retrans_timeout);

    if (con->cmd_pfd > 0)
        cmd_free(&con->cmd);
    if (con->payload != NULL )
        free(con->payload);
    if (con->readbuf != NULL )
        free(con->readbuf);
    if (con->tmpl != NULL )
        template_free(con->tmpl);

    honeyd_nconnects--;
    free(con);
}

void tcp_retrans_timeout(int fd, short event, void *arg)
{
    struct tcp_con *con = arg;

    /* Restart transmitting from the last acknowledged segment */
    con->poff = 0;

    con->retrans_time *= 2;
    /* Upper bound on the retransmit time */
    if (con->retrans_time >= 60)
    {
        tcp_free(con);
        return;
    }

    switch (con->state)
    {
    case TCP_STATE_SYN_SENT:
        con->snd_una--;
        tcp_send(con, TH_SYN, NULL, 0);
        con->snd_una++;

        generic_timeout(&con->retrans_timeout, con->retrans_time);
        break;

    case TCP_STATE_SYN_RECEIVED:
        con->snd_una--;
        tcp_send(con, TH_SYN | TH_ACK, NULL, 0);
        con->snd_una++;

        generic_timeout(&con->retrans_timeout, con->retrans_time);
        break;

    default:
        /* Will reschedule retransmit timeout if needed */
        tcp_senddata(con, TH_ACK);
        break;
    }
}

struct udp_con *
udp_new(struct ip_hdr *ip, struct ip6_hdr *ip6, struct udp_hdr *udp, int local,
        int addr_family)
{
    struct udp_con *con;

    if ((con = calloc(1, sizeof(struct udp_con))) == NULL )
    {
        syslog(LOG_WARNING, "calloc: %m");
        return (NULL );
    }

    if (ip6 == NULL )
        con->addr_family = AF_INET;
    else
        con->addr_family = AF_INET6;

    honeyd_setudp(con, ip, ip6, udp, local, addr_family);

    if (addr_family == AF_INET6)
    {
        syslog(LOG_DEBUG, "inserting new udp connection for src %s and dst %s",
               addr_ntoa(&con->conhdr.src_addr),
               addr_ntoa(&con->conhdr.dst_addr));
    }

    connection_insert(&udpcons, &udplru, &con->conhdr);

    evtimer_set(&con->conhdr.timeout, honeyd_udp_timeout, con);

    honeyd_log_flownew(honeyd_logfp, IP_PROTO_UDP, &con->conhdr);

    return (con);
}

void udp_free(struct udp_con *con)
{

    struct conbuffer *buf;
    struct port *port = con->port;
    struct port_encapsulate *pending = con->conhdr.pending;

    if (pending != NULL )
        port_encapsulation_free(pending);

    if (port != NULL )
        port_free(port->subtmpl, port);

    connection_remove(&udpcons, &udplru, &con->conhdr);

    hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM, &con->conhdr, NULL, 0);
    honeyd_log_flowend(honeyd_logfp, IP_PROTO_UDP, &con->conhdr);

    while ((buf = TAILQ_FIRST(&con->incoming))!= NULL)
    {
        TAILQ_REMOVE(&con->incoming, buf, next);
        free(buf->buf);
        free(buf);
    }

    if (con->cmd_pfd > 0)
        cmd_free(&con->cmd);
    if (con->tmpl != NULL )
        template_free(con->tmpl);

    free(con);
}

void honeyd_tcp_timeout(int fd, short event, void *arg)
{
    struct tcp_con *con = arg;

    syslog(LOG_DEBUG, "Expiring TCP %s (%p) in state %d",
           honeyd_contoa(&con->conhdr), con, con->state);

    tcp_free(con);
}

void honeyd_udp_timeout(int fd, short event, void *arg)
{
    struct udp_con *con = arg;

    syslog(LOG_DEBUG, "Expiring UDP %s (%p)", honeyd_contoa(&con->conhdr), con);

    udp_free(con);
}

struct action *
honeyd_protocol(struct template *tmpl, int proto)
{
    switch (proto)
    {
    case IP_PROTO_TCP:
        return (&tmpl->tcp);
    case IP_PROTO_UDP:
        return (&tmpl->udp);
    case IP_PROTO_ICMP:
        return (&tmpl->icmp);
    default:
        return (NULL );
    }
}

int honeyd_block(struct template *tmpl, int proto, int number)
{
    struct port *port;
    struct action *action;

    if (tmpl == NULL )
        return (0);

    port = port_find(tmpl, proto, number);
    if (port == NULL )
        action = honeyd_protocol(tmpl, proto);
    else
        action = &port->action;

    return (action->status == PORT_BLOCK);
}

void honeyd_varexpand(struct tcp_con *con, char *line, u_int linesize)
{
    char asc[32], *p;
    struct addr src, dst;

    addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &con->con_ipdst, IP_ADDR_LEN);
    addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &con->con_ipsrc, IP_ADDR_LEN);

    /* Do some simple replacements */
    p = addr_ntoa(&src);
    while (strrpl(line, linesize, "$ipsrc", p) != NULL )
        ;
    p = addr_ntoa(&dst);
    while (strrpl(line, linesize, "$ipdst", p) != NULL )
        ;
    p = honeyd_logdate();
    while (strrpl(line, linesize, "$date", p) != NULL )
        ;
    snprintf(asc, sizeof(asc), "%d", con->con_sport);
    while (strrpl(line, linesize, "$sport", asc) != NULL )
        ;
    snprintf(asc, sizeof(asc), "%d", con->con_dport);
    while (strrpl(line, linesize, "$dport", asc) != NULL )
        ;
}

/*
 * Returns the configuration of a particular port by looking
 * at the default template of connections. For example the
 * action->action may be the pl script to execute.
 */

struct action *
honeyd_port(struct template *tmpl, int proto, u_short number)
{
    struct port *port;
    struct action *action;

    if (tmpl == NULL )
        return (NULL );

    port = port_find(tmpl, proto, number);
    if (port == NULL )
        action = honeyd_protocol(tmpl, proto);
    else
        action = &port->action;

    return (action);
}

/*
 * Create a proxy connection, either use precomputed addrinfo or
 * generate correct address information.
 */

int proxy_connect(struct tuple *hdr, struct command *cmd, struct addrinfo *ai,
                  char *line, void *arg)
{
    int res;

    /* Check if the address has been resolved for us already */
    if (ai == NULL )
    {
        char *name, *strport = line;
        u_short nport;

        name = strsep(&strport, ":");
        if (strport == NULL || (nport = atoi(strport)) == 0)
            return (-1);

        if ((ai = cmd_proxy_getinfo(name, hdr->type, nport)) == NULL )
            return (-1);
        res = cmd_proxy_connect(hdr, cmd, ai, arg);
        freeaddrinfo(ai);
    }
    else
        res = cmd_proxy_connect(hdr, cmd, ai, arg);

    return (res);
}

/* Cleans up receive and send buffers if cmd does not start */

void tcp_connectfail(struct tcp_con *con)
{
    if (con->payload)
    {
        free(con->payload);
        con->payload = NULL;
    }
    if (con->readbuf)
    {
        free(con->readbuf);
        con->readbuf = NULL;
    }
}

/* Sets up buffers for a fully connected TCP connection */

int tcp_setupconnect(struct tcp_con *con)
{
    struct tuple *hdr = &con->conhdr;

    /* Allocate buffers */
    if ((con->payload = malloc(TCP_DEFAULT_SIZE)) == NULL )
    {
        syslog(LOG_WARNING, "malloc %s: %m", honeyd_contoa(hdr));
        goto err;
    }
    if ((con->readbuf = malloc(TCP_DEFAULT_SIZE)) == NULL )
    {
        syslog(LOG_WARNING, "malloc %s: %m", honeyd_contoa(hdr));
        goto err;
    }
    con->psize = TCP_DEFAULT_SIZE;
    con->rsize = TCP_DEFAULT_SIZE;

    return (0);

err: tcp_connectfail(con);

    return (-1);
}

void generic_connect(struct template *tmpl, struct tuple *hdr,
                     struct command *cmd, void *con)
{
    char line[512], command[512];
    char *argv[32], *p, *p2;
    struct action *action = NULL;
    struct port *port;
    int proto = 0;
    int i;

    if (hdr->type == SOCK_STREAM)
        proto = IP_PROTO_TCP;
    else
        proto = IP_PROTO_UDP;

    if (tmpl == NULL )
        goto out;

    if ((port = port_find(tmpl, proto, hdr->dport)) == NULL )
    {
        /* We need to use the default action for the protocol */
        action = proto == IP_PROTO_TCP ? &tmpl->tcp : &tmpl->udp;
    }
    else
        action = &port->action;

    if (action->status == PORT_OPEN)
    {
        if (action->action == NULL || strlen(action->action) == 0)
            goto out;
    }

    if (proto == IP_PROTO_TCP && tcp_setupconnect(con) == -1)
        goto out;

    /* Connect to the already started sub system */
    if (action->status == PORT_SUBSYSTEM)
    {
        if (cmd_subsystem_schedule_connect(hdr, cmd, port, con) == -1)
            goto out;
        return;
    }
    else if (action->status == PORT_PYTHON)
    {
#ifdef HAVE_PYTHON
        if (pyextend_connection_start(hdr, cmd, con,
                                      action->action_extend) == -1)
            goto out;
        return;
#endif
    }

    /* 3-way handshake has been completed */
    if (proto == IP_PROTO_TCP && action->status == PORT_RESERVED)
    {
        if (cmd_subsystem_localconnect(hdr, cmd, port, con) == -1)
            goto err;
        return;
    }

    if (action->status == PORT_OPEN || action->aitop == NULL )
    {
        assert(action->action != NULL && strlen(action->action));
        strlcpy(line, action->action, sizeof(line));
        honeyd_varexpand(con, line, sizeof(line));
        /* Copy for print out */
        strlcpy(command, line, sizeof(line));
    }

    /* Setup a proxy connection, no need to fork a new process */
    if (action->status == PORT_PROXY)
    {
        int res;

        res = proxy_connect(hdr, cmd, action->aitop, line, con);
        if (res == -1)
            goto out;
        return;
    }

    /* Create arguments */
    p2 = line;
    for (i = 0; i < sizeof(argv) / sizeof(char *) - 1; i++)
    {
        if ((p = strsep(&p2, " ")) == NULL )
            break;
        if (strlen(p) == 0)
        {
            i--;
            continue;
        }

        argv[i] = p;
    }

    argv[i] = NULL;

    if (cmd_fork(hdr, cmd, tmpl, argv[0], argv, con) == -1)
    {
        syslog(LOG_WARNING, "malloc %s: %m", honeyd_contoa(hdr));
        goto err;
    }

    syslog(LOG_DEBUG, "Connection established: %s %s <-> %s",
           proto == IP_PROTO_TCP ? "tcp" : "udp", honeyd_contoa(hdr), command);
    return;

err: if (proto == IP_PROTO_TCP)
        tcp_connectfail(con);
out: syslog(LOG_DEBUG, "Connection established: %s %s",
                proto == IP_PROTO_TCP ? "tcp" : "udp", honeyd_contoa(hdr));
}

int tcp_send46(struct tcp_con *con, uint8_t flags, u_char *payload, u_int len,
               int addr_family)
{
    u_char *pkt;
    struct tcp_hdr *tcp;
    u_int iplen = 0;
    int window = 16000;
    int dontfragment = 0;
    char *options;
    uint16_t id = rand_uint16(honeyd_rand);
    struct spoof spoof;
    struct template *tmpl = con->tmpl;
    if (con->window)
        window = con->window;

    /*
     * The TCP personality will always set snd_una for us if necessary.
     * snd_una maybe 0 on RST segments.
     */
    if (tcp_personality(con, &flags, &window, &dontfragment, &id, &options)
            == -1)
    {
        /*
         * If we do not match a personality and sent a reset
         * segment then we do not want to include options.
         */
        if (flags & TH_RST)
        {
            options = NULL;
            window = con->window;
        }
        else if (flags & TH_SYN)
        {
            options = "m";
        }
    }

    /* Empty flags indicates packet drop */
    if (flags == 0)
        return (0);

    if (con->flags & TCP_TARPIT)
        window = 5;

    if ((flags & TH_SYN) && !con->window)
        con->window = window;

    /* Simple window tracking */
    if (window && con->rlen)
    {
        window -= con->rlen;
        if (window < 0)
            window = 0;
    }

    pkt = pool_alloc(pool_pkt);

    /*TODO: consider ipv6 extension header length, in case of ipv4 */
    if (addr_family != AF_INET6)
    {
        tcp = (struct tcp_hdr *) (pkt + IP_HDR_LEN);
    }
    else
    {
        tcp = (struct tcp_hdr *) (pkt + IP6_HDR_LEN);
    }

    tcp_pack_hdr(tcp, con->con_dport, con->con_sport, con->snd_una,
                 con->rcv_next, flags, window, 0);

    /* ET - options is non-NULL if a personality was found.  If a
     * personality was found, it means that this packet is a response
     * to an NMAP TCP test (not a Sequence number test, a weird flags test).
     * Therefore if options is not NULL, you have to add the options to
     * the response otherwise the reply packet will not have the complete
     * personality.  Of the seven NMAP TCP tests, only a couple may
     * return a packet with the SYN flag.  I needed to remove the
     * requirement of the SYN flag so that the other NMAP TCP tests would
     * have the personality TCP options. */

    if (options != NULL )
        tcp_personality_options(con, tcp, options);

    if (addr_family == AF_INET)
    {
        iplen = IP_HDR_LEN + (tcp->th_off << 2) + len;
    }
    else if (addr_family == AF_INET6)
    {
        /* TODO: add extension header length */
        iplen = IP6_HDR_LEN + (tcp->th_off << 2) + len;
    }

    if (tmpl != NULL )
        spoof = tmpl->spoof;
    else
        spoof = no_spoof;

    /* Src and Dst are reversed both for ip and tcp */
    if (addr_family == AF_INET)
    {
        ip_pack_hdr(pkt, 0, iplen, id, dontfragment ? IP_DF : 0, honeyd_ttl,
                    IP_PROTO_TCP, con->con_ipdst, con->con_ipsrc);

        memcpy(pkt + IP_HDR_LEN + (tcp->th_off << 2), payload, len);

        hooks_dispatch(IP_PROTO_TCP, HD_OUTGOING, &con->conhdr, pkt, iplen);

        honeyd_ip_send(pkt, iplen, spoof);
    }
    else if (addr_family == AF_INET6)
    {

        /*
         parameter 2,3 are experimental
         parameter 4 is the payload length
         parameter 5 is the type - in this case tcp
         parameter 6 is the hop limit
         */
        ip6_pack_hdr(pkt, 0, 0, iplen - IP6_HDR_LEN, IP_PROTO_TCP, honeyd_ttl,
                     con->con_ip6dst, con->con_ip6src);

        /* set the playload length by hand */
        //ip6 = pkt;
        //ip6->ip6_plen = htons(iplen - IP6_HDR_LEN);
        memcpy(pkt + IP6_HDR_LEN + (tcp->th_off << 2), payload, len);
        /* TODO: check if the hooks face any problems with ipv6 addresses */
        hooks_dispatch(IP_PROTO_TCP, HD_OUTGOING, &con->conhdr, pkt, iplen);

        honeyd_ip6_send(pkt, iplen, spoof);
    }

    return (len);
}

int tcp_send(struct tcp_con *con, uint8_t flags, u_char *payload, u_int len)
{
    return tcp_send46(con, flags, payload, len, con->addr_family);
}

void tcp_senddata46(struct tcp_con *con, uint8_t flags, int addr_family)
{
    int space, sent = 0;
    int needretrans = 0;

    do
    {
        space = TCP_MAX_INFLIGHT - TCP_BYTESINFLIGHT(con);
        if (space > TCP_MAX_SEND)
            space = TCP_MAX_SEND;
        if (con->plen - con->poff < space)
            space = con->plen - con->poff;

        /* Reduce the amount of data that we can send */
        if (space && (con->flags & TCP_TARPIT))
            space = 1;

        if (con->sentfin && !con->finacked)
            flags |= TH_FIN;
        if (con->plen > space)
            flags &= ~TH_FIN;

        /*
         * If we do not ack new data, and have nothing to send,
         * and do not need to send a FIN, stop sending.
         */
        if (space == 0 && con->last_acked == con->rcv_next && !(flags & TH_FIN))
            break;

        con->snd_una += con->poff;
        if (addr_family == AF_INET)
        {
            sent = tcp_send(con, flags, con->payload + con->poff, space);
        }
        else if (addr_family == AF_INET6)
        {
            sent = tcp_send(con, flags, con->payload + con->poff, space);
        }

        con->snd_una -= con->poff;
        con->poff += sent;

        /* Statistics */
        con->conhdr.sent += space;

        if (flags & TH_ACK)
            con->last_acked = con->rcv_next;

        if (con->flags & TCP_TARPIT)
            break;

    }
    while (sent && !con->dupacks);

    /*
     * We need to retransmit if we still have outstanding data or
     * our FIN did not get acked.
     */
    needretrans = con->poff || (con->sentfin && !con->finacked);

    if (needretrans && !evtimer_pending(&con->retrans_timeout, NULL))
    {
        if (!con->retrans_time)
            con->retrans_time = 1;
        generic_timeout(&con->retrans_timeout, con->retrans_time);
    }
}

void tcp_senddata(struct tcp_con *con, uint8_t flags)
{
    tcp_senddata46(con, flags, con->addr_family);
}

void tcp_sendfin46(struct tcp_con *con, int addr_family)
{
    con->sentfin = 1;
    if (addr_family == AF_INET)
    {
        tcp_senddata(con, TH_ACK);
    }
    else if (addr_family == AF_INET6)
    {
        tcp_senddata(con, TH_ACK);
    }

    switch (con->state)
    {
    case TCP_STATE_ESTABLISHED:
        con->state = TCP_STATE_FIN_WAIT_1;
        break;
    case TCP_STATE_CLOSE_WAIT:
        con->state = TCP_STATE_CLOSING;
        break;
    }
}

void tcp_sendfin(struct tcp_con *con)
{
    tcp_sendfin46(con, con->addr_family);
}

void icmp_send(struct template *tmpl, u_char *pkt, uint8_t tos, u_int iplen,
               uint16_t df, uint8_t ttl, int proto, ip_addr_t src, ip_addr_t dst,
               struct spoof spoof)
{
    struct ip_hdr ip;
    uint16_t ipid;

    /* Fake up IP hdr */
    ip.ip_src = dst;
    ip.ip_dst = src;
    ip.ip_hl = sizeof(ip) >> 2;
    ip.ip_len = 0;

    if (tmpl != NULL )
        ip_personality(tmpl, &ipid);
    else
        ipid = rand_uint16(honeyd_rand);

    ip_pack_hdr(pkt, tos, iplen, ipid, df ? IP_DF : 0, ttl, IP_PROTO_ICMP, src,
                dst);

    honeyd_ip_send(pkt, iplen, spoof);
}

void icmp_error_send(struct template *tmpl, struct addr *addr, uint8_t type,
                     uint8_t code, struct ip_hdr *rip, struct spoof spoof)
{
    u_char *pkt;
    u_int iplen;
    uint8_t tos = 0, df = 0, ttl = honeyd_ttl;
    int quotelen, riplen;

    quotelen = 40;

    if (!icmp_error_personality(tmpl, addr, rip, &df, &tos, &quotelen, &ttl))
        return;

    riplen = ntohs(rip->ip_len);
    if (riplen < quotelen)
        quotelen = riplen;

    iplen = IP_HDR_LEN + ICMP_HDR_LEN + 4 + quotelen;

    pkt = pool_alloc(pool_pkt);

    icmp_pack_hdr_quote(pkt + IP_HDR_LEN, type, code, 0, rip, quotelen);
    icmp_send(tmpl, pkt, tos, iplen, df ? IP_DF : 0, ttl, IP_PROTO_ICMP,
              addr->addr_ip, rip->ip_src, spoof);
}

/*
 * icmp_echo_reply
 * rip should be the ip_header pointing to an actual raw
 * packet (has payload in it so icmp can be extracted)
 *
 * This function changes the IP and ICMP header data (i.e.
 * the ICMP packet and its IP header) to match the OS you want.
 *
 * The code, ipid, tos, offset, and ttl parameters should
 * probably move inside this function so that the icmp_personality
 * can have control over them.
 *
 * We should create a structure that includes all possible ICMP
 * fields and just pass in that structure into icmp_personality
 * function and have a flag to indicate what ICMP message it is
 * and what parameters need to set to what value depend on the
 * OS we need to emulate.
 * e.g.
 if (!icmp_personality(addr, rip, &ICMP_STRUCT)
 return;
 *
 * param rip The raw ip packet in IP header form
 * param code ICMP Header REPLY echo code, OS dependent, 0 or !0
 * param ipid IP Header id, 0 or !0(RANDOM)
 * param tos IP Header type of service, 0 or !0(0xc0)
 * param offset IP Header DF bit and offset, 0 or 1(IP_DF)
 * param ttl IP header time to live, <65, <129, or <256
 * param payload ICMP Echo request payload, should not be null, use by
 * 		ping programs to determine RTT
 * param len Length of the payload to return
 */
void icmp_echo_reply(struct template *tmpl, struct ip_hdr *rip, uint8_t code,
                     uint8_t tos, uint16_t offset, uint8_t ttl, u_char *payload, u_int len,
                     struct spoof spoof)
{
    u_char *pkt;
    u_int iplen;
    struct icmp_msg_echo *icmp_echo;

    icmp_echo = (struct icmp_msg_echo *) ((u_char *) rip + (rip->ip_hl << 2)
                                          + ICMP_HDR_LEN);

    iplen = IP_HDR_LEN + ICMP_HDR_LEN + 4 + len;

    if (iplen < HONEYD_MTU)
        pkt = pool_alloc(pool_pkt);
    else
        pkt = pool_alloc_size(pool_pkt, iplen);

    icmp_pack_hdr_echo(pkt + IP_HDR_LEN, ICMP_ECHOREPLY, code,
                       ntohs(icmp_echo->icmp_id), ntohs(icmp_echo->icmp_seq), payload,
                       len);

    icmp_send(tmpl, pkt, tos, iplen, offset, ttl, IP_PROTO_ICMP, rip->ip_dst,
              rip->ip_src, spoof);
}

/*
 * We should create a structure that includes all possible ICMP
 * fields and just pass in that structure into icmp_personality
 * function and have a flag to indicate what ICMP message it is
 * and what parameters need to set to what value depend on the
 * OS we need to emulate.
 * e.g.
 if (!icmp_personality(addr, rip, &ICMP_STRUCT)
 return;

 * ICMP_TIMESTAMP REPLY,
 *
 * param rip The raw ip packet in IP header form
 * param icmp_rip icmp timestamp message, includes the
 * 	icmp header.
 * param ttl Time to live of the emulated OS (<65, <129, <256)
 */
void icmp_timestamp_reply(struct template *tmpl, struct ip_hdr *rip,
                          struct icmp_msg_timestamp* icmp_rip, uint8_t ttl, struct spoof spoof)
{
    u_char *pkt;
    u_int iplen;
    struct icmp_msg_timestamp icmp_time;
    uint8_t padding = 6;
    struct tm *now_tm;
    time_t now;
    uint32_t milliseconds;

    pkt = pool_alloc(pool_pkt);

    now = time(NULL );
    now_tm = localtime(&now);

    milliseconds = (now_tm->tm_hour * 60 * 60 + now_tm->tm_min * 60
                    + now_tm->tm_sec) * 1000;

    icmp_time.hdr.icmp_type = ICMP_TSTAMPREPLY, icmp_time.hdr.icmp_code = 0;
    icmp_time.icmp_id = icmp_rip->icmp_id;
    icmp_time.icmp_seq = icmp_rip->icmp_seq;

    /* For now just do the following */
    icmp_time.icmp_ts_orig = icmp_rip->icmp_ts_orig;
    icmp_time.icmp_ts_rx = icmp_rip->icmp_ts_orig + milliseconds;
    icmp_time.icmp_ts_tx = icmp_rip->icmp_ts_rx;

    iplen = IP_HDR_LEN + ICMP_HDR_LEN + 16 + padding;
    /* 6 bytes of 0 at the end, why? RedHat and Windows have 6 bytes of
     * padding to this type of message. I don't know yet why they do this.
     */

    memcpy(pkt + IP_HDR_LEN, &icmp_time, sizeof(icmp_time));
    icmp_send(tmpl, pkt, rip->ip_tos, iplen, rip->ip_off, ttl, IP_PROTO_ICMP,
              rip->ip_dst, rip->ip_src, spoof);
}

/*
 * ICMP_MASK_REPLY.

 * We should create a structure that includes all possible ICMP
 * fields and just pass in that structure into icmp_personality
 * function and have a flag to indicate what ICMP message it is
 * and what parameters need to set to what value depend on the
 * OS we need to emulate.
 * e.g.
 if (!icmp_personality(addr, rip, &ICMP_STRUCT)
 return;

 * param rip The raw ip packet in IP header form
 * param idseq id and seq of the icmp header, should be same
 * 	from the mask request icmp header.
 * param ttl time to live of OS simulated (<65, <129, or <255)
 * param mask mask of the emulated OS (i.e. 255.255.0.0)
 */
void icmp_mask_reply(struct template *tmpl, struct ip_hdr *rip,
                     struct icmp_msg_idseq *idseq, uint8_t ttl, uint32_t addrmask,
                     struct spoof spoof)
{
    u_char *pkt;
    u_int iplen;
    struct icmp_mesg_mask mask;

    pkt = pool_alloc(pool_pkt);

    iplen = IP_HDR_LEN + ICMP_HDR_LEN + 8;

    mask.hdr.icmp_type = ICMP_MASKREPLY;
    mask.hdr.icmp_code = ICMP_CODE_NONE;

    mask.icmp_id = idseq->icmp_id;
    mask.icmp_seq = idseq->icmp_seq;
    mask.icmp_mask = htonl(addrmask);

    memcpy(pkt + IP_HDR_LEN, &mask, sizeof(mask));
    icmp_send(tmpl, pkt, rip->ip_tos, iplen, rip->ip_off, ttl, IP_PROTO_ICMP,
              rip->ip_dst, rip->ip_src, spoof);
}

/*
 * We should create a structure that includes all possible ICMP
 * fields and just pass in that structure into icmp_personality
 * function and have a flag to indicate what ICMP message it is
 * and what parameters need to set to what value depend on the
 * OS we need to emulate.
 * e.g.
 if (!icmp_personality(addr, rip, &ICMP_STRUCT)
 return;

 * ICMP_INFO_REPLY
 *
 * param rip The raw ip packet in IP header form
 * param idseq id and seq of the icmp header, should be same
 * 	from the info request icmp header.
 * param ttl Time to live of the emulated OS (<65, <129, <256)
 */
void icmp_info_reply(struct template *tmpl, struct ip_hdr *rip,
                     struct icmp_msg_idseq *idseq, uint8_t ttl, struct spoof spoof)
{
    u_char *pkt;
    u_int iplen;
    struct icmp_msg_inforeply inforeply;

    pkt = pool_alloc(pool_pkt);

    iplen = IP_HDR_LEN + ICMP_HDR_LEN + 4;

    inforeply.hdr.icmp_type = ICMP_INFOREPLY;
    inforeply.hdr.icmp_code = ICMP_CODE_NONE;

    inforeply.idseq.icmp_id = idseq->icmp_id;
    inforeply.idseq.icmp_seq = idseq->icmp_seq;

    memcpy(pkt + IP_HDR_LEN, &inforeply, sizeof(inforeply));
    icmp_send(tmpl, pkt, rip->ip_tos, iplen, rip->ip_off, ttl, IP_PROTO_ICMP,
              rip->ip_dst, rip->ip_src, spoof);
}

/*
 * Sends an icmp6 package.
 * @param ip_payload_len the length of the icmp package
 */
void icmp6_send_pkt(const struct interface * inter, struct addr *src_eth,
                    struct addr *dst_eth, struct in6_addr *src_ip6,
                    struct in6_addr *dst_ip6, u_char * icmp_pkt, int icmp_pkt_len)
{

    struct ip6_hdr *ip6;


    /* ICMP_HDR_LEN should be 32 byte - just to test it */
    u_char *pkg = pool_alloc_size(pool_pkt,
                                  ETH_HDR_LEN + IP6_HDR_LEN + icmp_pkt_len); //[ETH_HDR_LEN+IP6_HDR_LEN+icmp_pkt_len];

    //eth_pack_hdr(pkg,dst_eth->addr_eth,src_eth->addr_eth,ETH_TYPE_IPV6);
    /*
     parameter 2,3 are experimental
     parameter 4 is the payload length
     parameter 5 is the type - in this case icmpv6
     parameter 6 is the hop limit
     */
    ip6_pack_hdr(pkg, 0, 0, icmp_pkt_len, IP_PROTO_ICMPV6, 255, *src_ip6,
                 *dst_ip6);

    /* copy the passed icmp package into the package to send */
    memcpy(pkg + IP6_HDR_LEN, icmp_pkt, icmp_pkt_len);

    /* calculate the cecksum */
    ip6 = (struct ip6_hdr *) (pkg);

    ip6_checksum(ip6, icmp_pkt_len + IP6_HDR_LEN);

    if (inter == NULL || src_eth == NULL || dst_eth == NULL )
    {
        honeyd_ip6_send(pkg, icmp_pkt_len + IP6_HDR_LEN, no_spoof);
    }
    else
    {
        /* deliver the packet directly */
        honeyd_deliver_ethernet6(inter, src_eth, dst_eth, ip6,
                                 icmp_pkt_len + IP6_HDR_LEN);
    }

    /* TODO: check if icmp_pkt is deleted properly in the calling functions */

    return;
}

void tcp_do_options(struct tcp_con *con, struct tcp_hdr *tcp, int isonsyn)
{
    u_char *p, *end;

    p = (u_char *) (tcp + 1);
    end = (u_char *) tcp + (tcp->th_off << 2);

    while (p < end)
    {
        struct tcp_opt opt, *tmp = (struct tcp_opt *) p;

        if (tmp->opt_type == TCP_OPT_NOP)
        {
            p++;
            continue;
        }
        else if (tmp->opt_type == TCP_OPT_EOL)
            break;

        if (p + tmp->opt_len > end)
            break;

        memcpy(&opt, tmp, tmp->opt_len);
        switch (opt.opt_type)
        {
        case TCP_OPT_MSS:
            if (!isonsyn)
            {
                con->mss = ntohs(opt.opt_data.mss);
            }
            break;
        case TCP_OPT_WSCALE:
            if (!isonsyn)
            {
                con->sawwscale = 1;
            }
            break;
        case TCP_OPT_TIMESTAMP:
            con->sawtimestamp = 1;
            con->echotimestamp = opt.opt_data.timestamp[0];
            break;
        default:
            break;
        }

        p += opt.opt_len;
        if (opt.opt_len < 1)
            break;
    }
}

void generic_timeout(struct event *ev, int seconds)
{
    struct timeval tv;

    timerclear(&tv);
    tv.tv_sec = seconds;
    evtimer_add(ev, &tv);
}

/* Checks that the sequence number is where we expect it to be */
#define TCP_CHECK_SEQ_OR_ACK	do { \
		int has_ack = tcp->th_flags & TH_ACK; \
		if (tcp->th_flags & TH_RST) { \
			if (th_seq != con->rcv_next) \
				goto drop; \
			goto close; \
		} \
		if (!has_ack) \
			goto drop; \
		if (TCP_SEQ_LT(th_ack, con->snd_una)) { \
			if (tcp->th_flags & TH_RST) \
				goto drop; \
		}\
		/* Don't accept out of order data */ \
		if (TCP_SEQ_GT(th_seq, con->rcv_next)) { \
			if (has_ack) \
				tcp_send(con, TH_ACK, NULL, 0); \
			goto drop; \
		} \
} while(0)

#define TCP_RECV_SEND_DATA	do { \
		/* Find new data: doff contains already acked data */ \
		if(addr_family==AF_INET)\
			dlen = ntohs(ip->ip_len) - (ip->ip_hl * 4) -(tcp->th_off * 4);\
		if(addr_family==AF_INET6)\
			dlen = ntohs(ip6->ip6_plen) -(tcp->th_off * 4);\
		doff = con->rcv_next - th_seq; \
		if (doff > dlen ||(doff == dlen && (tiflags & TH_FIN) == 0)) {\
			/* Need to ACK this segments */ \
			tiflags &= ~TH_FIN; \
			doff = dlen; \
		} \
		dlen -= doff; \
\
		con->conhdr.received += dlen; \
\
		if (con->plen || con->cmd_pfd > 0) { \
			int ackinc = 0; \
			dlen = tcp_add_readbuf(con, data + doff, dlen); \
\
			acked = th_ack - con->snd_una; \
			if (acked > con->plen) { \
				if (con->sentfin && acked == con->plen + 1){ \
					con->finacked = 1; \
					ackinc = 1; \
				} \
				acked = con->plen; \
			} \
			tcp_drain_payload(con, acked); \
			acked += ackinc; \
			if (con->cmd_pfd == -1 && con->plen <= TCP_MAX_SEND) \
				con->sentfin = 1; \
		} else if (con->cmd_pfd == -1) { \
			tcp_add_readbuf(con, data + doff, dlen); \
		} \
		if (con->sentfin) { \
			if (th_ack == con->snd_una + 1) { \
				acked = 1; \
				con->finacked = 1; \
			} \
		} \
		if (acked == 0 && con->poff) { \
			con->dupacks++; \
			if (con->dupacks >= 3) { \
				con->dupacks = 3; \
				con->poff = 0; \
			} \
		} else if (acked) { \
			con->retrans_time = 0; \
			evtimer_del(&con->retrans_timeout); \
			con->dupacks=0; \
		} \
} while (0)

void tcp_recv_cb46(struct template *tmpl, u_char *pkt, u_short pktlen,
                   int addr_family)
{
    char *comment = NULL;
    struct ip_hdr *ip = NULL;
    struct ip6_hdr * ip6 = NULL;
    struct tcp_hdr *tcp = NULL;
    struct tcp_con *con;
    struct action *action;
    uint32_t th_seq, th_ack;
    uint32_t acked = 0;
    uint16_t th_sum;
    u_char *data;
    u_int dlen = 0, doff;
    uint8_t tiflags, flags;

    if (addr_family == AF_INET)
    {
        ip = (struct ip_hdr *) pkt;
        tcp = (struct tcp_hdr *) (pkt + (ip->ip_hl << 2));
        data = (u_char *) (pkt + (ip->ip_hl * 4) + (tcp->th_off * 4));

        if (pktlen < (ip->ip_hl << 2) + TCP_HDR_LEN)
            return;

        honeyd_settcp(&honeyd_tmp, ip, tcp, 0);

    }
    else if (addr_family == AF_INET6)
    {
        ip6 = (struct ip6_hdr *) pkt;
        get_ip6_next_hdr((u_char **) &tcp, ip6, IP_PROTO_TCP);
        data = (u_char *) (pkt + IP6_HDR_LEN + (tcp->th_off * 4));

        honeyd_settcp6(&honeyd_tmp, ip6, tcp, 0);

    }
    else
    {
        syslog(LOG_DEBUG,
               "received tcp wrapped in packet with unknown address family");
        return;
    }

    /*
     * Check if we have a real connection header for this connection, so
     * that we can look at potential flags like local origination.
     */
    /* honeyd_settcp copies the tcp header information like addresses and ports
     into the honeyd_tmp connection structure */
    con = (struct tcp_con *) SPLAY_FIND(tree, &tcpcons, &honeyd_tmp.conhdr);

    /* call all the hooks callbacks */
    hooks_dispatch(IP_PROTO_TCP, HD_INCOMING,
                   con != NULL ? &con->conhdr : &honeyd_tmp.conhdr, pkt, pktlen);

    if (honeyd_block(tmpl, IP_PROTO_TCP, ntohs(tcp->th_dport)))
        goto justlog;

    /* Check the checksum the brutal way, until libdnet supports */
    th_sum = tcp->th_sum;
    if (addr_family == AF_INET)
    {
        ip_checksum(ip, pktlen);
    }
    else if (addr_family == AF_INET6)
    {
        ip6_checksum(ip6, pktlen);
    }
    if (th_sum != tcp->th_sum)
        goto justlog;

    /* find out what to do for the specific port/template */
    action = honeyd_port(tmpl, IP_PROTO_TCP, ntohs(tcp->th_dport));

    /* action->action contains the command to execute */
    //if(action->action!=NULL){
    //	syslog(LOG_DEBUG,"TCP Action: %s",action->action);
    //}
    honeyd_tmp.state =
    action == NULL || PORT_ISOPEN(action) ?
    TCP_STATE_LISTEN : TCP_STATE_CLOSED;

    tiflags = tcp->th_flags;
    /* if there is no existing connection? */
    if (con == NULL )
    {
        if (honeyd_tmp.state != TCP_STATE_LISTEN)
        {
            goto kill;
        }
        /* the first package has to have a syn bit set (handshake) */
        if ((tiflags & TH_SYN) == 0)
        {
            //syslog(LOG_DEBUG,"no syn");
            goto kill;
        }
        /* if one of the other flags has been set too (which is not supposed to happen)
         then drop the package, but let the personality engine check this too first,
         maybe some systems do replay to that kind of package */
        if (tiflags & ~TH_SYN & (TH_FIN | TH_RST | TH_PUSH | TH_ACK | TH_URG))
        {
            int win = 0, df = 0;
            uint16_t id;

            flags = TH_SYN | TH_ACK;
            if (tiflags & (TH_FIN | TH_RST))
                comment = " {Honeyd Scanner?}";

            /*
             * Some stacks might reply to a packet like
             * this.  So, check the personalities and see
             * what the flags say.
             */
            if (tcp_personality(&honeyd_tmp, &flags, &win, &df, &id, NULL )
                    == -1)
            {
                /*
                 * These flags normally cause a termination,
                 * so drop or reset the connection as we did
                 * not match a fingerprint.
                 */
                if (tiflags & (TH_RST | TH_ACK))
                    goto kill;
                tiflags &= ~TH_FIN;
            }

            /* Just drop the packet if reset flag is set */
            if (flags & TH_RST)
                goto kill;
        }

        syslog(LOG_DEBUG, "Connection request: tcp %s",
               honeyd_contoa(&honeyd_tmp.conhdr));

        /* Check if we should drop this SYN packet */
        if (tmpl != NULL && tmpl->drop_synrate)
        {
            uint16_t value;
            value = rand_uint16(honeyd_rand) % (100 * 100);
            if (value < tmpl->drop_synrate)
                goto justlog;
        }

        /* Out of memory is dealt with by killing the connection */
        /* tcp new also adds the connection to the "database" */
        if (addr_family != AF_INET6 && (con = tcp_new(ip, tcp, 0)) == NULL )
        {
            goto kill;
        }
        else if (addr_family == AF_INET6
                 && (con = tcp_new6(ip6, tcp, 0)) == NULL )
        {
            goto kill;
        }

        con->rcv_flags = tiflags;

        /* Check if this connection is a tar pit */
        if (action != NULL && (action->flags & PORT_TARPIT))
            con->flags |= TCP_TARPIT;

        tcp_do_options(con, tcp, 1);

        con->tmpl = template_ref(tmpl);
        con->rcv_next = ntohl(tcp->th_seq) + 1;
        con->snd_una = 0;

        con->state = TCP_STATE_LISTEN;
        tcp_send(con, TH_SYN | TH_ACK, NULL, 0);

        con->snd_una++;
        con->state = TCP_STATE_SYN_RECEIVED;

        generic_timeout(&con->conhdr.timeout, HONEYD_SYN_WAIT);

        /* Get initial value from personality */
        con->retrans_time = 3;
        generic_timeout(&con->retrans_timeout, con->retrans_time);

        return;
    }

    /*
     * Subsystems can remove ports on the fly - even when parts of the
     * 3-way handshake are in progress already.
     */

    if (action != NULL )
    {
        switch (action->status)
        {
        case PORT_RESET:
            goto dropwithreset;
        case PORT_BLOCK:
            goto drop;
        default:
            break;
        }
    }

    th_seq = ntohl(tcp->th_seq);
    th_ack = ntohl(tcp->th_ack);

    con->rcv_flags = tiflags;

    switch (con->state)
    {
    case TCP_STATE_SYN_SENT:
        if (tiflags & TH_RST)
            goto close;
        if (!(tiflags & TH_SYN))
            goto drop;
        if (!(tiflags & TH_ACK))
            goto drop;

        /* No simultaneous open allowed */
        if (th_ack != con->snd_una)
            goto dropwithreset;

        tcp_do_options(con, tcp, 0);

        con->rcv_next = th_seq + 1;
        tcp_send(con, TH_ACK, NULL, 0);

        con->state = TCP_STATE_ESTABLISHED;
        generic_connect(tmpl, &con->conhdr, &con->cmd, con);
        break;

    case TCP_STATE_SYN_RECEIVED:
        if (tiflags & TH_ACK)
        {
            if (tiflags & TH_SYN)
                goto dropwithreset;
            if (th_ack != con->snd_una)
                goto dropwithreset;
        }
        if (tiflags & TH_SYN)
        {
            if (th_seq != con->rcv_next - 1)
                goto dropwithreset;
            con->snd_una--;
            tcp_send(con, TH_SYN | TH_ACK, NULL, 0);

            con->snd_una++;
            return;
        }

        if (tiflags & TH_RST)
            goto close;
        if (!(tiflags & TH_ACK))
            goto drop;

        tcp_do_options(con, tcp, 0);

        /* Clear retransmit timeout */
        con->retrans_time = 0;
        evtimer_del(&con->retrans_timeout);

        connection_update(&tcplru, &con->conhdr);

        con->state = TCP_STATE_ESTABLISHED;
        generic_connect(tmpl, &con->conhdr, &con->cmd, con);
        break;

    case TCP_STATE_ESTABLISHED:
        TCP_CHECK_SEQ_OR_ACK
        ;

        TCP_RECV_SEND_DATA;

        tcp_do_options(con, tcp, 0);

        connection_update(&tcplru, &con->conhdr);

        if (tiflags & TH_FIN && !(con->flags & TCP_TARPIT))
        {
            if (con->cmd_pfd > 0)
            {
                if (con->rlen == 0)
                {
                    /*
                     * If we already transmitted all data,
                     * we can completely shutdown the write
                     * part of the connection.
                     */
                    shutdown(con->cmd_pfd, SHUT_WR);
                }
                else
                {
                    /*
                     * If we still have data to write to
                     * our child process, we need to delay
                     * the shutdown until later.
                     */
                    con->cmd.fdgotfin = 1;
                }
            }
            else
            {
                con->sentfin = 1;
            }
            con->state = TCP_STATE_CLOSE_WAIT;
            dlen++;
        }

        con->rcv_next += dlen;
        con->snd_una += acked;
        if (con->sentfin)
        {
            tcp_sendfin(con);
        }
        else
            tcp_senddata(con, TH_ACK);
        break;

    case TCP_STATE_CLOSE_WAIT:
        TCP_CHECK_SEQ_OR_ACK
        ;

        TCP_RECV_SEND_DATA;

        tcp_do_options(con, tcp, 0);

        connection_update(&tcplru, &con->conhdr);

        if (dlen)
            goto dropwithreset;
        con->snd_una += acked;
        tcp_senddata(con, TH_ACK);
        if (con->sentfin)
            con->state = TCP_STATE_CLOSING;
        break;

    case TCP_STATE_CLOSING:
        TCP_CHECK_SEQ_OR_ACK;

        TCP_RECV_SEND_DATA;

        tcp_do_options(con, tcp, 0);

        connection_update(&tcplru, &con->conhdr);

        con->snd_una += acked;
        if (con->finacked)
            goto closed;
        tcp_senddata(con, TH_ACK);
        break;

    case TCP_STATE_FIN_WAIT_1:
        TCP_CHECK_SEQ_OR_ACK
        ;

        TCP_RECV_SEND_DATA;

        tcp_do_options(con, tcp, 0);
        if (tiflags & TH_FIN && !(con->flags & TCP_TARPIT))
        {
            con->state = TCP_STATE_CLOSING;
            generic_timeout(&con->conhdr.timeout, HONEYD_CLOSE_WAIT);
            dlen++;
        }
        else
        {
            connection_update(&tcplru, &con->conhdr);
        }

        con->rcv_next += dlen;
        con->snd_una += acked;
        tcp_senddata(con, TH_ACK);
        break;
    }

    return;

kill: honeyd_log_probe(honeyd_logfp, IP_PROTO_TCP, &honeyd_tmp.conhdr,
                           pktlen, tcp->th_flags, comment);

    /* Do not kill on reset */
    if (tiflags & TH_RST)
        return;

    syslog(LOG_DEBUG, "Killing %s connection: tcp %s",
           (tcp->th_flags & TH_SYN) ? "attempted" : "unknown",
           honeyd_contoa(&honeyd_tmp.conhdr));

    /* Fake connection element */
    honeyd_tmp.rcv_next = ntohl(tcp->th_seq) + 1;
    honeyd_tmp.snd_una = ntohl(tcp->th_ack);
    honeyd_tmp.tmpl = tmpl;

    if (tiflags & TH_ACK)
        flags = TH_RST;
    else
        flags = TH_RST | TH_ACK;
    /*
     * The TCP personality matches, all the sequence numbers are
     * going to be taken care off via the Nmap fingerprint,
     * otherwise, we are going to fill in reasonable defaults.
     */
    if (tcp_personality_match(&honeyd_tmp, flags))
    {
        honeyd_tmp.rcv_next = ntohl(tcp->th_seq) + 1;
        honeyd_tmp.snd_una = ntohl(tcp->th_ack);
    }
    else if (tiflags & TH_ACK)
    {
        honeyd_tmp.rcv_next = 0;
        honeyd_tmp.snd_una = ntohl(tcp->th_ack);
    }
    else
    {
        flags = TH_RST | TH_ACK;
        honeyd_tmp.rcv_next = ntohl(tcp->th_seq) + 1;
        honeyd_tmp.snd_una = 0;
    }

    /*
     * Even though options processing does not make any sense on
     * RST segment, some stacks apparently do it anyway.
     */
    tcp_do_options(&honeyd_tmp, tcp, 1);

    tcp_send(&honeyd_tmp, flags, NULL, 0);

    return;

close: if (tiflags & TH_RST)
    {
        syslog(LOG_DEBUG, "Connection dropped by reset: tcp %s",
               honeyd_contoa(&con->conhdr));
    }
    goto free;

dropwithreset: syslog(LOG_DEBUG, "Connection dropped with reset: tcp %s",
                          honeyd_contoa(&con->conhdr));
    if ((tiflags & TH_RST) == 0)
    {
        tcp_send(con, TH_RST | TH_ACK, NULL, 0);
    }
free: tcp_free(con);
    return;
closed: syslog(LOG_DEBUG, "Connection closed: tcp %s",
                   honeyd_contoa(&con->conhdr));
    /* Forget about this connection */
    tcp_free(con);
drop: return;

justlog: honeyd_settcp(&honeyd_tmp, ip, tcp, 0);
    honeyd_log_probe(honeyd_logfp, IP_PROTO_TCP, &honeyd_tmp.conhdr, pktlen,
                     tcp->th_flags, comment);
}

void tcp_recv_cb(struct template *tmpl, u_char *pkt, u_short pktlen)
{
    tcp_recv_cb46(tmpl, pkt, pktlen, AF_INET);
}

void tcp_recv_cb6(struct template *tmpl, u_char *pkt, u_short pktlen)
{
    tcp_recv_cb46(tmpl, pkt, pktlen, AF_INET6);
}

int udp_send(struct udp_con *con, u_char *payload, u_int len)
{
    u_char *pkt;
    struct udp_hdr *udp;
    u_int iplen;
    uint16_t id = rand_uint16(honeyd_rand);
    int dontfragment = 0;
    struct spoof spoof;
    struct template *tmpl = con->tmpl;
    /* addr family of connection */
    int addr_family = AF_INET;

    if (con->conhdr.src_addr.addr_type == ADDR_TYPE_IP6)
    {
        addr_family = AF_INET6;
    }

    /* Statistics */
    con->conhdr.sent += len;

    if (addr_family == AF_INET)
        ip_personality(tmpl, &id);

    pkt = pool_alloc(pool_pkt);

    if (addr_family == AF_INET6)
    {
        /* TODO: check if we need to consider any extension headers here */
        udp = (struct udp_hdr *) (pkt + IP6_HDR_LEN);
        iplen = IP6_HDR_LEN + UDP_HDR_LEN + len;
    }
    else
    {
        udp = (struct udp_hdr *) (pkt + IP_HDR_LEN);
        iplen = IP_HDR_LEN + UDP_HDR_LEN + len;
    }

    udp_pack_hdr(udp, con->con_dport, con->con_sport, UDP_HDR_LEN + len);

    /* Src and Dst are reversed both for ip and tcp */
    if (addr_family == AF_INET6)
    {
        /*
         parameter 2,3 are experimental
         parameter 4 is the payload length
         parameter 5 is the type - in this case tcp
         parameter 6 is the hop limit
         */
        ip6_pack_hdr(pkt, 0, 0, iplen - IP6_HDR_LEN, IP_PROTO_UDP, honeyd_ttl,
                     con->con_ip6dst, con->con_ip6src);
        memcpy(pkt + IP6_HDR_LEN + UDP_HDR_LEN, payload, len);
    }
    else
    {
        ip_pack_hdr(pkt, 0, iplen, id, dontfragment ? IP_DF : 0, honeyd_ttl,
                    IP_PROTO_UDP, con->con_ipdst, con->con_ipsrc);

        memcpy(pkt + IP_HDR_LEN + UDP_HDR_LEN, payload, len);
    }

    if (tmpl)
        spoof = tmpl->spoof;
    else
        spoof = no_spoof;

    if (addr_family == AF_INET6)
        ip6_checksum(pkt, iplen);
    else
        ip_checksum(pkt, iplen);

    hooks_dispatch(IP_PROTO_UDP, HD_OUTGOING, &con->conhdr, pkt, iplen);

    if (addr_family == AF_INET6)
        honeyd_ip6_send(pkt, iplen, spoof);
    else
        honeyd_ip_send(pkt, iplen, spoof);

    generic_timeout(&con->conhdr.timeout, HONEYD_UDP_WAIT);

    return (len);
}

void udp_recv_cb46(struct template *tmpl, u_char *pkt, u_short pktlen,
                   int addr_family)
{
    struct ip_hdr *ip = NULL;
    struct ip6_hdr *ip6 = NULL;
    struct udp_hdr *udp = NULL;
    struct udp_con *con, honeyd_udp;
    struct addr addr;
    struct spoof spoof;

    uint16_t uh_sum;
    u_char *data = NULL;
    u_int dlen = 0;
    u_short portnum;

    if (addr_family == AF_INET)
    {
        ip = (struct ip_hdr *) pkt;
        udp = (struct udp_hdr *) (pkt + (ip->ip_hl << 2));

        if (pktlen < (ip->ip_hl << 2) + UDP_HDR_LEN)
            return;

    }
    else if (addr_family == AF_INET6)
    {
        ip6 = (struct ip6_hdr *) pkt;
        get_ip6_next_hdr((u_char **) &udp, ip6, IP_PROTO_UDP);
    }

    /*
     * Check if we have a real connection header for this connection, so
     * that we can look at potential flags like local origination.
     */
    honeyd_setudp(&honeyd_udp, ip, ip6, udp, 0, addr_family);
    con = (struct udp_con *) SPLAY_FIND(tree, &udpcons, &honeyd_udp.conhdr);

    if (addr_family == AF_INET)
    {
        hooks_dispatch(ip->ip_p, HD_INCOMING,
                       con != NULL ? &con->conhdr : &honeyd_udp.conhdr, pkt, pktlen);
    }

    if (addr_family == AF_INET)
    {
        data = (u_char *) (pkt + (ip->ip_hl * 4) + UDP_HDR_LEN);
        dlen = ntohs(ip->ip_len) - (ip->ip_hl << 2) - UDP_HDR_LEN;
    }
    else if (addr_family == AF_INET6)
    {
        data = ((u_char *) udp) + UDP_HDR_LEN;
        /* TODO: set the datalen by substracting the ext hdr len */
        dlen = ntohs(udp->uh_ulen) - UDP_HDR_LEN;
    }

    if (dlen != (ntohs(udp->uh_ulen) - UDP_HDR_LEN))
        return;

    portnum = ntohs(udp->uh_dport);
    if (honeyd_block(tmpl, IP_PROTO_UDP, portnum))
        goto justlog;

    /* Check the packet checksum, if no uh_sum is set, we ignore it */
    uh_sum = udp->uh_sum;
    if (addr_family == AF_INET6)
        ip6_checksum(ip6, pktlen);
    else
        ip_checksum(ip, pktlen);

    if ((uh_sum && uh_sum != udp->uh_sum))
        goto justlog;

    if (con == NULL )
    {
        struct action *action;
        action = honeyd_port(tmpl, IP_PROTO_UDP, portnum);

        /* Send unreachable on closed port */
        if (action == NULL || !PORT_ISOPEN(action))
        {
            syslog(LOG_DEBUG, "Connection to closed port: udp %s",
                   honeyd_contoa(&honeyd_udp.conhdr));
            goto closed;
        }

        /* Otherwise create a new udp connection */
        syslog(LOG_DEBUG, "Connection: udp %s",
               honeyd_contoa(&honeyd_udp.conhdr));

        /* Out of memory is dealt by having the port closed */
        if ((con = udp_new(ip, ip6, udp, 0, addr_family)) == NULL )
        {
            goto closed;
        }

        generic_connect(tmpl, &con->conhdr, &con->cmd, con);
    }

    /* Keep this state active */
    generic_timeout(&con->conhdr.timeout, HONEYD_UDP_WAIT);
    con->softerrors = 0;

    /* Statistics */
    con->conhdr.received += dlen;

    /* Add the data to the incoming buffers */
    udp_add_readbuf(con, data, dlen);
    return;

closed: if (addr_family == AF_INET)
    {
        honeyd_log_probe(honeyd_logfp, IP_PROTO_UDP, &honeyd_udp.conhdr, pktlen,
                         0, NULL );

        addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);

        /*
         * compute possible spoofed source for this error response to a UDP packet
         */
        if (tmpl)
            spoof = tmpl->spoof;
        else
            spoof = no_spoof;
        // compute_spoof(&spoof, tmpl, &tmpl->spoof, ip->ip_src, ip->ip_dst);
        print_spoof("udp_recv_cb after", spoof);
        icmp_error_send(tmpl, &addr, ICMP_UNREACH, ICMP_UNREACH_PORT, ip,
                        spoof);
    }
    else if (addr_family == AF_INET6)
    {
        addr_pack(&addr, ADDR_TYPE_IP6, IP6_ADDR_BITS, &ip6->ip6_dst,
                  IP6_ADDR_LEN);
        icmp6_error_send(&addr, ip6, ICMP6_DST_UNREACH,
                         ICMP6_DST_UNREACH_NOPORT);
    }
    return;

justlog: honeyd_setudp(&honeyd_udp, ip, ip6, udp, 0, addr_family);
    honeyd_log_probe(honeyd_logfp, IP_PROTO_UDP, &honeyd_udp.conhdr, pktlen, 0,
                     NULL );
}

void udp_recv_cb(struct template *tmpl, u_char *pkt, u_short pktlen)
{
    udp_recv_cb46(tmpl, pkt, pktlen, AF_INET);
}

void icmp_recv_cb(struct template *tmpl, u_char *pkt, u_short pktlen)
{
    struct ip_hdr *ip = NULL;
    struct icmp_hdr *icmp;
    struct icmp_msg_quote *icmp_quote;
    struct ip_hdr *rip, tmpip;
    struct udp_hdr *udp, tmpudp;
    struct udp_con *con, honeyd_udp;
    /* YM - ICMP Messages */
    struct icmp_msg_echo *icmp_echo;
    struct icmp_msg_timestamp *icmp_tstamp;
    struct icmp_msg_idseq *icmp_idseq;
    struct xp_fingerprint *xp_print = NULL; /* JVR */
    //struct tuple icmphdr;
    struct addr src, dst;
    struct spoof spoof;
    char asrc[100], adst[100];
    char osrc[100], odst[100];
    char ssrc[100], sdst[100];
    u_char *dat;
    uint16_t cksum;
    int dlen;

    ip = (struct ip_hdr *) pkt;

    if (pktlen < (ip->ip_hl << 2) + ICMP_HDR_LEN)
        return;

    icmp = (struct icmp_hdr *) (pkt + (ip->ip_hl << 2));

    //icmphdr.local = 0;
    //icmphdr.ip_src = ip->ip_src;
    //icmphdr.ip_dst = ip->ip_dst;
    //icmphdr.type = SOCK_RAW;
    //icmphdr.sport = icmp->icmp_type; /* XXX - horrible cludge */
    //icmphdr.dport = icmp->icmp_code;
    honeyd_log_icmp(honeyd_logfp, IP_PROTO_ICMP, ip, pktlen);

    /* We can block ICMP, too */
    if (tmpl && tmpl->icmp.status == PORT_BLOCK)
        return;

    if (tmpl != NULL && tmpl->person != NULL )
        xp_print = tmpl->person->xp_fprint;

    /* Without xprobe fingerprint, we understand only ECHO and UNREACH */
    if (xp_print == NULL )
    {
        if (!(icmp->icmp_type == ICMP_ECHO)
                && !(icmp->icmp_type == ICMP_UNREACH
                     && icmp->icmp_code == ICMP_UNREACH_PORT))
            return;
    }

    /* return if the checksum in incorrect */
    cksum = icmp->icmp_cksum;
    ip_checksum(ip, pktlen);
    if (cksum != icmp->icmp_cksum)
        return;

    dlen = pktlen - IP_HDR_LEN - ICMP_HDR_LEN;
    dlen -= 4;

    if (dlen < 0)
        return;

    /* AscII representation of original addresses */
    addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);
    addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
    addr_ntop(&src, osrc, sizeof(osrc));
    addr_ntop(&dst, odst, sizeof(odst));

    if (tmpl)
        spoof = tmpl->spoof;
    else
        spoof = no_spoof;
    addr_ntop(&spoof.new_src, ssrc, sizeof(ssrc));
    addr_ntop(&spoof.new_dst, sdst, sizeof(sdst));

    if (spoof.new_src.addr_type != ADDR_TYPE_NONE)
        snprintf(adst, sizeof(adst), "%s (was %s)", ssrc, odst);
    else
        snprintf(adst, sizeof(adst), "%s", odst);
    if (spoof.new_dst.addr_type != ADDR_TYPE_NONE)
        snprintf(asrc, sizeof(asrc), "%s (was %s)", sdst, osrc);
    else
        snprintf(asrc, sizeof(asrc), "%s", osrc);

    switch (icmp->icmp_type)
    {
    case ICMP_ECHO:
        icmp_echo = (struct icmp_msg_echo *) (icmp + 1);
        dat = (u_char *) (icmp_echo + 1);

        syslog(LOG_DEBUG, "Sending ICMP Echo Reply: %s -> %s", adst, asrc);
        if (xp_print)
        {
            /* ym: Use our own icmp echo reply function */
            icmp_echo_reply(tmpl, ip, xp_print->flags.icmp_echo_code,
                            xp_print->flags.icmp_echo_tos_bits ? ip->ip_tos : 0,
                            xp_print->flags.icmp_echo_df_bit ? IP_DF : 0,
                            xp_print->ttl_vals.icmp_echo_reply_ttl.ttl_val, dat, dlen,
                            spoof);
        }
        else
            icmp_echo_reply(tmpl, ip, ICMP_CODE_NONE, 0, 0, honeyd_ttl, dat,
                            dlen, spoof);
        break;

    case ICMP_UNREACH:
        /* Only port unreachable at the moment */
        icmp_quote = (struct icmp_msg_quote *) (icmp + 1);
        rip = (struct ip_hdr *) (&icmp_quote->icmp_ip);

        if (rip->ip_p != IP_PROTO_UDP)
            break;

        udp = (struct udp_hdr *) ((u_char *) rip + (ip->ip_hl << 2));
        tmpip.ip_src = rip->ip_dst;
        tmpip.ip_dst = rip->ip_src;
        tmpudp.uh_sport = udp->uh_dport;
        tmpudp.uh_dport = udp->uh_sport;
        honeyd_setudp(&honeyd_udp, &tmpip, NULL, &tmpudp, 0, AF_INET);

        /* Find matching state */
        con = (struct udp_con *) SPLAY_FIND(tree, &udpcons,
                                            &honeyd_udp.conhdr);
        if (con == NULL )
            break;

        con->softerrors++;
        syslog(LOG_DEBUG, "Received port unreachable: %s -> %s: errors %d",
               asrc, adst, con->softerrors);
        if (con->softerrors >= HONEYD_MAX_SOFTERRS)
            udp_free(con);

        break;

        /* YM: Add ICMP Timestamp reply capability */
    case ICMP_TSTAMP:
        /* Happens only if xp_print != NULL */
        if (xp_print->flags.icmp_timestamp_reply)
        {
            icmp_tstamp = (struct icmp_msg_timestamp *) ((u_char*) pkt
                    + (ip->ip_hl << 2));

            syslog(LOG_DEBUG, "Sending ICMP Timestamp Reply: %s -> %s", adst,
                   asrc);

            icmp_timestamp_reply(tmpl, ip, icmp_tstamp,
                                 xp_print->ttl_vals.icmp_timestamp_reply_ttl.ttl_val, spoof);
        }
        break;

        /* YM: Added ICMP Address Mask reply capability */
    case ICMP_MASK:
        /* Happens only if xp_print != NULL */
        if (xp_print->flags.icmp_addrmask_reply)
        {
            icmp_idseq = (struct icmp_msg_idseq *) (icmp + 1);

            syslog(LOG_DEBUG, "Sending ICMP Address Mask Reply: %s -> %s", adst,
                   asrc);

            icmp_mask_reply(tmpl, ip, icmp_idseq,
                            xp_print->ttl_vals.icmp_addrmask_reply_ttl.ttl_val,
                            HONEYD_ADDR_MASK, spoof);
        }
        break;

        /* YM: Added ICMP Information reply capability */
    case ICMP_INFO:
        /* Happens only if xp_print != NULL */
        if (xp_print->flags.icmp_info_reply)
        {
            icmp_idseq = (struct icmp_msg_idseq *) (icmp + 1);

            syslog(LOG_DEBUG, "Sending ICMP Info Reply: %s -> %s", adst, asrc);

            icmp_info_reply(tmpl, ip, icmp_idseq,
                            xp_print->ttl_vals.icmp_info_reply_ttl.ttl_val, spoof);
        }
        break;

    default:
        break;
    }
}

void honeyd_dispatch(struct template *tmpl, struct ip_hdr *ip, u_short iplen)
{
    struct tuple iphdr;

    iphdr.ip_src = ip->ip_src;
    iphdr.ip_dst = ip->ip_dst;
    iphdr.type = -1;

    /*
     * We define a hook here for packet interception -- plugins
     * can use it to do fun stuff with the packets.
     */

    switch (ip->ip_p)
    {
    case IP_PROTO_TCP:
        tcp_recv_cb(tmpl, (u_char *) ip, iplen);
        break;
    case IP_PROTO_UDP:
        udp_recv_cb(tmpl, (u_char *) ip, iplen);
        break;
    case IP_PROTO_ICMP:
        hooks_dispatch(ip->ip_p, HD_INCOMING, &iphdr, (u_char *) ip, iplen);
        icmp_recv_cb(tmpl, (u_char *) ip, iplen);
        break;
    default:
        hooks_dispatch(ip->ip_p, HD_INCOMING, &iphdr, (u_char *) ip, iplen);
        honeyd_log_probe(honeyd_logfp, ip->ip_p, &iphdr, iplen, 0, NULL );
        return;
    }
}

void honeyd_dispatch6(struct template *tmpl, struct ip6_hdr *ip6)
{

    u_char * next_hdr = NULL;
    /* ICMP6 */
    if (get_ip6_next_hdr(&next_hdr, ip6, IP_PROTO_ICMPV6) != -1)
    {
        icmp6_recv_cb(tmpl->inter, ip6, (struct icmp6_hdr*) next_hdr);
        return;
    }
    /* TCP */
    if (get_ip6_next_hdr(&next_hdr, ip6, IP_PROTO_TCP) != -1)
    {
        tcp_recv_cb6(tmpl, (u_char *) ip6, ntohs(ip6->ip6_plen) + IP6_HDR_LEN);
        return;
    }

    /* UDP */
    if (get_ip6_next_hdr(&next_hdr, ip6, IP_PROTO_UDP) != -1)
    {
        udp_recv_cb46(tmpl, (u_char *) ip6, ntohs(ip6->ip6_plen) + IP6_HDR_LEN,
                      AF_INET6);
        return;
    }
    syslog(LOG_DEBUG, "unknown packet type received, type: %u", ip6->ip6_nxt);
    return;

}

/*
 * Given the queue dependent delay time, we can get an estimate of
 * the queue length.  We do a kind of random early drop (RED) between
 * a delay time of low and high in ms.
 */

static __inline int honeyd_router_drop(struct link_drop *drop,
                                       struct timeval *tv)
{
    int msec;
    int low = drop->low;
    int high = drop->high;

    if (high == 0)
        return (0);

    /* See if we fall into the random bracket */
    msec = tv->tv_sec * 1000 + tv->tv_usec / 1000;
    if (msec <= low)
        return (0);
    if (msec >= high)
        return (1);

    msec -= low;

    if (rand_uint16(honeyd_rand) % (high - low) < msec)
        return (1);
    else
        return (0);
}

/*
 * Follow a packet through the routing table; starting with router gw.
 * Return:
 *	FW_INTERNAL - means that the packet needs to be received internally
 *	FW_EXTERNAL - means that the packet needs to be sent to the wire
 *	FW_DROP - means that the packet has been handled by dropping, etc.
 */

enum forward honeyd_route_packet46(struct ip_hdr *ip, struct ip6_hdr *ip6,
                                   u_int iplen, struct addr *gw, struct addr *addr, int *pdelay,
                                   int addr_family)
{
    struct router *r, *lastrouter = NULL;
    struct router_entry *rte = NULL;
    struct link_entry *link = NULL;
    struct template *tmpl;
    struct addr host;
    double packetloss = 1;
    int delay = 0, external = 0;

    char * solicited_node_prefix = "ff02::1:ff";
    if (addr != NULL
            && strncmp(addr_ntoa(addr), solicited_node_prefix,
                       strlen(solicited_node_prefix)) == 0)
    {
        return FW_INTERNAL;
    }

    host = *gw;
    r = router_find(&host);

    int ttl = (addr_family == AF_INET ? ip->ip_ttl : ip6->ip6_hlim);

    while (addr_cmp(&host, addr) != 0 && --ttl)
    {
        if ((rte = network_lookup(r->routes, addr)) == NULL )
        {
            if (r->flags & ROUTER_ISENTRY)
            {
                external = 1;
                break;
            }
            syslog(LOG_DEBUG, "No route to %s", addr_ntoa(addr));
            return (FW_DROP);
        }

        if (rte->gw != NULL && lastrouter == rte->gw)
            if (rte->type == ROUTE_TUNNEL)
                break;

        if (rte->type == ROUTE_LINK || rte->type == ROUTE_UNREACH)
            break;

        /* Get the attributes for this link */
        link = rte->link;

        if (link->latency)
            delay += link->latency;
        else
            delay += 3;

        if (link->bandwidth)
        {
            int ms = iplen * link->bandwidth / link->divider;
            struct timeval now, tv;
            gettimeofday(&now, NULL );

            if (timercmp(&now, &link->tv_busy, <))
            {
                /* Router is busy for a while */
                timersub(&link->tv_busy, &now, &tv);

                /* Opportunity to drop based on queue length */
                if (honeyd_router_drop(&link->red, &tv))
                    return (FW_DROP);

                delay += tv.tv_sec * 1000 + tv.tv_usec / 1000;
            }
            else
            {
                /* Router is busy now */
                link->tv_busy = now;
            }

            /* Construct router delay time */
            tv.tv_sec = ms / 1000;
            tv.tv_usec = (ms % 1000) * 1000;

            timeradd(&link->tv_busy, &tv, &link->tv_busy);

            delay += ms;
        }
        if (link->packetloss)
            packetloss *= 1 - ((double) link->packetloss / 10000.0);

        lastrouter = r;
        r = rte->gw;
        host = r->addr;
    }

    /* Calculate the packet loss rate */
    packetloss = (1 - packetloss) * 10000;
    if (rand_uint16(honeyd_rand) % 10000 < packetloss)
        return (FW_DROP);

    if (addr_family == AF_INET6)
    {
        ip6->ip6_hlim = ttl;
        if (!ip6->ip6_hlim)
        {
            syslog(LOG_DEBUG, "TTL exceeded for dst %s at gw %s",
                   addr_ntoa(addr), addr_ntoa(&host));
            tmpl = template_find(addr_ntoa(&host));
            honeyd_delay_packet6(tmpl, ip6, iplen, &host, NULL, delay, 0,
                                 no_spoof);
            return (FW_DROP);
        }
    }

    if (addr_family == AF_INET)
    {
        ip->ip_ttl = ttl;
        /* Send ICMP_TIMEXCEED from router address */
        if (!ttl)
        {
            struct spoof spoof = no_spoof;
            spoof.new_src = host;

            syslog(LOG_DEBUG, "TTL exceeded for dst %s at gw %s",
                   addr_ntoa(addr), addr_ntoa(&host));

            /*
             * We need to use the template of the host that will
             * send the ICMP error message.
             */
            tmpl = template_find_best(addr_ntoa(&host), ip, iplen);
            honeyd_delay_packet(tmpl, ip, iplen, &host, NULL, delay, 0, spoof);
            return (FW_DROP);
        }

        /* Send ICMP_UNREACH from router address */
        if (rte != NULL && rte->type == ROUTE_UNREACH)
        {
            syslog(LOG_DEBUG, "dst %s unreachable at gw %s", addr_ntoa(addr),
                   addr_ntoa(&host));

            /*
             * We need to use the template of the host that will
             * send the ICMP error message.
             */
            tmpl = template_find_best(addr_ntoa(&host), ip, iplen);
            honeyd_delay_packet(tmpl, ip, iplen, &host, NULL, delay,
                                DELAY_UNREACH, no_spoof);
            return (FW_DROP);
        }

        /* We need to tunnel this packet */
        if (rte != NULL && rte->type == ROUTE_TUNNEL)
        {
            honeyd_delay_packet(NULL, ip, iplen, &rte->tunnel_src,
                                &rte->tunnel_dst, delay, DELAY_TUNNEL, no_spoof);
            return (FW_DROP);
        }

        if (!external)
        {
            struct template *tmpl;

            /* Check if a template specific drop rate applies */
            tmpl = template_find_best(addr_ntoa(addr), ip, iplen);
            if (tmpl != NULL && tmpl->drop_inrate)
            {
                uint16_t value;
                value = rand_uint16(honeyd_rand) % (100 * 100);
                if (value < tmpl->drop_inrate)
                    return (FW_DROP);
            }
        }
    }
    /* The packet can be received; schedule it */

    *pdelay = delay;
    return (external ? FW_EXTERNAL : FW_INTERNAL);
}

enum forward honeyd_route_packet(struct ip_hdr *ip, u_int iplen,
                                 struct addr *gw, struct addr *addr, int *pdelay)
{
    return honeyd_route_packet46(ip, NULL, iplen, gw, addr, pdelay, AF_INET);
}

enum forward honeyd_route_packet6(struct ip6_hdr *ip6, u_int iplen,
                                  struct addr *gw, struct addr *addr, int *pdelay)
{
    return honeyd_route_packet46(NULL, ip6, iplen, gw, addr, pdelay, AF_INET6);
}

void honeyd_input(const struct interface *inter, struct ip_hdr *ip,
                  u_short iplen)
{
    extern struct network *reverse;
    struct template *tmpl = NULL;
    struct router *gw;
    struct addr gw_addr;
    struct router_entry *rte;
    enum forward res = FW_INTERNAL;
    int delay = 0, flags = 0;
    struct addr src, addr;

    addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
    if (!router_used)
    {
        /* Check if a template specific drop rate applies */
        tmpl = template_find_best(addr_ntoa(&addr), ip, iplen);

        if (tmpl != NULL && tmpl->drop_inrate)
        {
            uint16_t value;
            value = rand_uint16(honeyd_rand) % (100 * 100);
            if (value < tmpl->drop_inrate)
                return;
        }

        if (tmpl != NULL && tmpl->flags & TEMPLATE_EXTERNAL)
            flags |= DELAY_ETHERNET;
        honeyd_delay_packet(NULL, ip, iplen, NULL, NULL, delay, flags,
                            no_spoof);
        return;
    }

    addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);
    /* in case we have gre tunne package  */
    if (ip->ip_p == IP_PROTO_GRE)
    {
        uint16_t ipoff;

        /* Decapsulate GRE packet if it is legitimate */
        if ((rte = router_find_tunnel(&addr, &src)) == NULL )
        {
            syslog(LOG_DEBUG, "Unknown GRE packet from %s", addr_ntoa(&src));
            return;
        }

        /* Check for fragment GRE packets */
        ipoff = ntohs(ip->ip_off);
        if ((ipoff & IP_OFFMASK) || (ipoff & IP_MF))
        {
            if (ip_fragment(NULL, ip, iplen, &ip, &iplen) == -1)
                return;
            /*
             * If a packet was reassembled successfully, we can
             * just continue processing it.  All checks so far
             * are solely concerned with the IP header.
             */
        }

        if (gre_decapsulate(ip, iplen, &ip, &iplen) == -1)
            return;

        addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);
        /* Check that the source address is valid */
        if (!addr_contained(&rte->net, &src))
        {
            syslog(LOG_INFO, "Bad address %s injected into tunnel %s",
                   addr_ntoa(&src), addr_ntoa(&rte->net));
            return;
        }
        addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
    }

    if ((gw = network_lookup(reverse, &src)) != NULL )
    {
        gw_addr = gw->addr;
    }
    /* Find the correct entry router based on destination IP */
    else if ((gw = network_lookup(entry_routers_ip4, &addr)) != NULL )
    {
        gw_addr = gw->addr;
    }
    else
    {
        /* Pick the first one on the list */
        gw = entry_routers_ip4->data;
        gw_addr = gw->addr;
    }

    res = honeyd_route_packet(ip, iplen, &gw_addr, &addr, &delay);
    if (res == FW_DROP)
        return;

    /*
     * We want to prevent routing loops.  One good heuristic is to
     * drop all packets that we received from an interface and
     * that want to be routed out of an interface.  In the case of
     * ethernet, this is legitimate if we have external hosts
     * integrated into the routing topology.  In that case, we
     * send the packet out, if there is a routing loop, we are
     * going to receive it via loopback and drop it then.
     */

    if (res == FW_EXTERNAL)
    {
        if (inter != NULL
                && inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH)
        {
            syslog(LOG_DEBUG, "No route to %s", addr_ntoa(&addr));
            return;
        }
        else
            flags |= DELAY_EXTERNAL;
    }
    else
        tmpl = template_find_best(addr_ntoa(&addr), ip, iplen);

    if (tmpl != NULL && tmpl->flags & TEMPLATE_EXTERNAL)
        flags |= DELAY_ETHERNET;

    /* Delay the packet if necessary, otherwise deliver it directly */
    honeyd_delay_packet(NULL, ip, iplen, NULL, NULL, delay, flags, no_spoof);
}

void honeyd_input6(const struct interface *inter, struct ip6_hdr *ip6,
                   u_short iplen)
{
    extern struct network *reverse6;
    struct template *tmpl = NULL;
    struct router *gw;
    struct addr gw_addr;
    enum forward res = FW_INTERNAL;
    int delay = 0, flags = 0;
    struct addr src, addr;

    addr_pack(&addr, ADDR_TYPE_IP6, IP6_ADDR_BITS, &ip6->ip6_dst, IP6_ADDR_LEN);

    if (!router_used)
    {
        /* handle drop rate */
        tmpl = template_find(addr_ntoa(&addr));
        if (tmpl != NULL && tmpl->drop_inrate)
        {
            uint16_t value;
            value = rand_uint16(honeyd_rand) % (100 * 100);
            if (value < tmpl->drop_inrate)
                return;
        }

        if (tmpl != NULL && tmpl->flags & TEMPLATE_EXTERNAL) {
            flags |= DELAY_ETHERNET;
        }
        
        honeyd_delay_packet6(NULL, ip6, iplen, NULL, NULL, delay, flags, no_spoof);
        return;
    }

    addr_pack(&src, ADDR_TYPE_IP6, IP6_ADDR_BITS, &ip6->ip6_src, IP6_ADDR_LEN);

    if ((gw = network_lookup(reverse6, &src)) != NULL )
        gw_addr = gw->addr;
    /* Find the correct entry router based on destination IP */
    else if ((gw = network_lookup(entry_routers_ip6, &addr)) != NULL )
        gw_addr = gw->addr;
    else
    {
        /* Pick the first one on the list */
        gw = entry_routers_ip6->data;
        gw_addr = gw->addr;
    }

    res = honeyd_route_packet6(ip6, iplen, &gw_addr, &addr, &delay);
    if (res == FW_DROP)
        return;

    /*
     * We want to prevent routing loops.  One good heuristic is to
     * drop all packets that we received from an interface and
     * that want to be routed out of an interface.  In the case of
     * ethernet, this is legitimate if we have external hosts
     * integrated into the routing topology.  In that case, we
     * send the packet out, if there is a routing loop, we are
     * going to receive it via loopback and drop it then.
     */

    if (res == FW_EXTERNAL)
    {
        if (inter != NULL
                && inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH)
        {
            syslog(LOG_DEBUG, "No route to %s", addr_ntoa(&addr));
            return;
        }
        else
            flags |= DELAY_EXTERNAL;
    }
    else
        tmpl = template_find(addr_ntoa(&addr));

    if (tmpl != NULL && tmpl->flags & TEMPLATE_EXTERNAL)
        flags |= DELAY_ETHERNET;

    /* Delay the packet if necessary, otherwise deliver it directly */
    honeyd_delay_packet6(NULL, ip6, iplen, NULL, NULL, delay, flags, no_spoof);
}

/* this is the actual callback handler that processes a received package */
/* the first argument is the interface (last argument in dispatch) */
/* the second argument is the pcap header - has info about time and size etc. */
/* the third argument is a pointer to the first package byte */
void honeyd_recv_cb(u_char *ag, const struct pcap_pkthdr *pkthdr,
                    const u_char *pkt)
{
    const struct interface *inter = (const struct interface *) ag;
    struct ip_hdr *ip;
    struct addr addr;
    u_short iplen;
    struct eth_hdr *eth = (struct eth_hdr *) pkt;
    int is_etherpkt = 0;

    struct addr src;

    count_increment(stats_network.input_bytes, pkthdr->caplen);

    /* Check if we can receive arp traffic on this interface */
    if ((router_used || need_arp)
            && inter->if_ent.intf_link_addr.addr_type == ADDR_TYPE_ETH)
    {
        struct arp_req *req;
        struct addr eth_sha;

        /* Mark this packet as being delivered via ethernet */
        is_etherpkt = 1;

        /* Ignore our own packets */
        addr_pack(&eth_sha, ADDR_TYPE_ETH, ETH_ADDR_BITS, &eth->eth_src,
                  ETH_ADDR_LEN);
        if ((req = arp_find(&eth_sha)) != NULL && (req->flags & ARP_INTERNAL))
        {
            return;
        }

        /* process arp package */
        if (ntohs(eth->eth_type) == ETH_TYPE_ARP)
        {
            arp_recv_cb(ag, pkthdr, pkt);
            return;
        }
    }

    /* in case of ipv4 ... */
    if (ntohs(eth->eth_type) == ETH_TYPE_IP)
    {
        if (pkthdr->caplen < inter->if_dloff + IP_HDR_LEN)
            return;

        ip = (struct ip_hdr *) (pkt + inter->if_dloff);

        addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);
        /* cancel if we didnt receive the whole package */
        iplen = ntohs(ip->ip_len);
        if (pkthdr->caplen - inter->if_dloff < iplen)
        {
            return;
        }
        /* <<2 is like *4 because 4* ip_hl is the complete header length in bit
         - the actual header can't be bigger then the whole package  */

        if (ip->ip_hl << 2 > iplen)
        {
            return;
        }

        /* almost the same here */
        if (ip->ip_hl << 2 < sizeof(struct ip_hdr))
        {
            return;
        }

        /* Check if destination is  our own address - then we might ignore it */
        addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
        if (addr_cmp(&addr, &inter->if_ent.intf_addr) == 0)
        {
            /* Only accept packets for own address if they are GRE */
            if (!router_used || ip->ip_p != IP_PROTO_GRE)
                return;
        }

        /* Check for a DHCP server response */
        if (is_etherpkt && ip->ip_p == IP_PROTO_UDP)
        {
            struct udp_hdr *udp;
            /* get the udp package */
            udp = (struct udp_hdr *) ((u_char *) ip + (ip->ip_hl << 2));
            /* check if complete datagram is smaller then the headers */
            if (iplen < (ip->ip_hl << 2) + UDP_HDR_LEN)
                goto out;

            /* receive dh cp */
            if (ntohs(udp->uh_dport) == 68 && ntohs(udp->uh_sport) == 67)
            {
                dhcp_recv_cb(eth, ip, iplen);
                return;
            }
        }
out: honeyd_input(inter, ip, iplen);
        return;

    }
    else if (ntohs(eth->eth_type) == ETH_TYPE_IPV6)
    {
        honeyd_recv_cb6(ag, pkthdr, pkt);
    }
}

/* TODO: implement dhcpv6? */
void honeyd_recv_cb6(u_char *ag, const struct pcap_pkthdr *pkthdr,
                     const u_char *pkt)
{
    const struct interface *inter = (const struct interface *) ag;
    struct template *tmpl_from_dst = NULL, *tmpl_from_src = NULL;
    struct ip6_hdr * ip6;
    struct icmp6_hdr * icmp6 = NULL;
    struct addr src;
    char * template_name = malloc(INET6_ADDRSTRLEN);
    ip6 = (struct ip6_hdr*) (pkt + inter->if_dloff);
    
    /* get the source address */
    addr_pack(&src, ADDR_TYPE_IP6, IP6_ADDR_BITS, &ip6->ip6_src, IP6_ADDR_LEN);

    /* handle icmpv6 directly */
    get_ip6_next_hdr((u_char**) &icmp6, ip6, IPPROTO_ICMPV6);
    if (icmp6 != NULL && icmp6->icmp6_type == ND_ROUTER_ADVERT)
    {
        icmp6_recv_cb(inter, ip6, icmp6);
    }

    /* check if we have a template with the message's dst address */
    inet_ntop(AF_INET6, &ip6->ip6_dst, template_name, INET6_ADDRSTRLEN);
    tmpl_from_dst = template_find(template_name);
    free(template_name);

    /* ignore our own packets if internal routing is not enabled */
    tmpl_from_src = template_find(addr_ntoa(&src));
    if (!router_used && tmpl_from_src != NULL )
    {
        return;
    }


    /* if random mode is enabled and there is no existing template the maybe create one */
    if (tmpl_from_dst == NULL && tmpl_from_src == NULL && config.randomipv6mode)
    {
      const char *template_name = get_template_name_from_packet(ip6);
        if(template_name != NULL)
        {
           random_create_ipv6_template(template_name, inter, config.randomipv6_percentage, config.max_random_ipv6_hosts, honeyd_logfp);
        }
        tmpl_from_dst = template_find(template_name);
    }


    /* TODO: add some ip packet validations */ 
    
    if (tmpl_from_dst == NULL )
    {
        return;
    }
    else
    {
        honeyd_input6(inter, ip6, ip6->ip6_plen);
    }

}

void honeyd_sigchld(int fd, short what, void *arg)
{
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
    {
        /* Ignore the rrdtool driver for children accounting */
        if (honeyd_rrd_drv != NULL && honeyd_rrd_drv->pid == pid)
            continue;
        honeyd_nchildren--;
    }
}

void honeyd_signal(int fd, short what, void *arg)
{
    syslog(LOG_NOTICE, "exiting on signal %d", fd);
    honeyd_exit(0);
}

void honeyd_sighup(int fd, short what, void *arg)
{
    syslog(LOG_NOTICE, "rereading configuration on signal %d", fd);

    template_free_all(TEMPLATE_FREE_REGULAR);
    router_end();
    if (config.config != NULL )
        config_read(config.config);
}

void honeyd_sigusr(int fd, short what, void *arg)
{
    syslog(LOG_NOTICE, "rotating log files on signal %d", fd);

    honeyd_logend(honeyd_logfp);
    honeyd_logend(honeyd_servicefp);

    if (logfile != NULL )
        honeyd_logfp = honeyd_logstart(logfile);
    if (servicelog != NULL )
        honeyd_servicefp = honeyd_logstart(servicelog);
}

struct _unittest
{
    char *name;
    void (*cb)(void);
} unittests[] =
{
#ifdef HAVE_PYTHON
//	{ "pydataprocessing", pydataprocessing_test },
//	{ "pydatahoneyd", pydatahoneyd_test },
#endif
//	{ "rrdtool", rrdtool_test },
//	{ "ethernet", ethernet_test },
//	{ "interface", interface_test },
    { "network", network_test },
    { "icmpv6", icmp6_test },
//	{ "template", template_test },
    { NULL, NULL }
};

void unittest(void)
{
    struct _unittest *ut;
    fprintf(stderr, "Running unittests ...\n");
    for (ut = unittests; ut->name != NULL ; ut++)
    {
        fprintf(stderr, " ---- %s TEST ---- \n", ut->name);
        (*ut->cb)();
        fprintf(stderr, " ---- %s OK ---- \n", ut->name);
    }
    fprintf(stderr, "All unitests are OK\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    extern int interface_dopoll;
    struct event sigterm_ev, sigint_ev, sighup_ev, sigchld_ev, sigusr_ev;
    char *dev[HONEYD_MAX_INTERFACES];
    char **orig_argv;
    struct addr stats_dst;
    u_short stats_port = 0;
    char *stats_username = NULL;
    char *stats_password = NULL;
    int want_unittest = 0;
    int setrand = 0;
    int i, c, orig_argc, ninterfaces = 0;
    FILE *fp;

    fprintf(stderr, "Honeyd V%s Copyright (c) 2002-2007 Niels Provos\n",
            VERSION);

    orig_argc = argc;
    orig_argv = argv;
    while ((c = getopt_long(argc, argv, "VPTdc:i:p:x:a:u:g:f:l:s:0:R:h?",
                            honeyd_long_opts, NULL )) != -1)
    {
        char *ep;
        switch (c)
        {
        case 'Y':
            honeyd_rrdtool_path = optarg;
            break;

        case 'A':
            honeyd_webserver_address = optarg;
            break;

        case 'W':
            honeyd_webserver_port = atoi(optarg);
            if (honeyd_webserver_port == 0)
            {
                fprintf(stderr, "Bad port number: %s\n", optarg);
                usage();
            }
            break;
        case 'X':
            honeyd_webserver_root = optarg;
            break;
        case 'T':
            want_unittest = 1;
            break;
        case 'R':
            /* For regression testing */
            setrand = atoi(optarg);
            break;
        case 'c':
        {
            /* just for reporting */
            char line[1024], *p = line;
            char *address;
            char *strport;
            char *name;
            char *password;

            strlcpy(line, optarg, sizeof(line));

            if ((address = strsep(&p, ":")) == NULL )
                usage();
            if ((strport = strsep(&p, ":")) == NULL )
                usage();
            if ((name = strsep(&p, ":")) == NULL )
                usage();
            if ((password = strsep(&p, ":")) == NULL )
                usage();
            if (p != NULL && *p != '\0')
                usage();

            /* check if string can be converted to network format */
            if (addr_pton(address, &stats_dst) == -1)
            {
                fprintf(stderr, "Bad destination address %s\n", address);
                usage();
            }
            if ((stats_port = atoi(strport)) == 0)
            {
                fprintf(stderr, "Bad destination port %s\n", strport);
                usage();
            }

            stats_username = strdup(name);
            stats_password = strdup(password);
        }
        break;
        case 'u':
            honeyd_uid = strtoul(optarg, &ep, 10);
            honeyd_needsroot = -1;
            if (optarg[0] == '\0' || *ep != '\0')
            {
                fprintf(stderr, "Bad uid %s\n", optarg);
                usage();
            }
            break;
        case 'g':
            honeyd_gid = strtoul(optarg, &ep, 10);
            honeyd_needsroot = -1;
            if (optarg[0] == '\0' || *ep != '\0')
            {
                fprintf(stderr, "Bad gid %s\n", optarg);
                usage();
            }
            break;
        case 'V':
            honeyd_show_version = 1;
            break;
        case 'P':
            interface_dopoll = 1;
            break;
        case 'd':
            honeyd_debug++;
            break;
        case 'i':
            if (ninterfaces >= HONEYD_MAX_INTERFACES)
                errx(1, "Too many interfaces specified");
            dev[ninterfaces++] = optarg;
            break;
        case 'f':
            config.config = optarg;
            break;
        case 'l':
            logfile = optarg;
            break;
        case 's':
            servicelog = optarg;
            break;
        case 'x':
            config.xprobe = optarg;
            break;
        case 'a':
            config.assoc = optarg;
            break;
        case 'p':
            config.pers = optarg;
            break;
        case '0':
            config.osfp = optarg;
            break;
        case 0:
            /* long option handled -- skip this one. */
            break;
        default:
            /* print usage */
            usage();
            /* not reached */
        }
    }

    if (honeyd_show_version)
    {
        printf("Honeyd Version %s\n", VERSION);
        exit(0);
    }
    if (honeyd_show_usage)
    {
        usage();
        /* not reached */
    }
    if (honeyd_show_include_dir)
    {
        printf("%s\n", PATH_HONEYDINCLUDE);
        exit(0);
    }
    if (honeyd_show_data_dir)
    {
        printf("%s\n", PATH_HONEYDDATA);
        exit(0);
    }

    argc -= optind;
    argv += optind;

    if ((honeyd_rand = rand_open()) == NULL )
        err(1, "rand_open");
    /* We need reproduceable random numbers for regression testing */
    if (setrand)
        rand_set(honeyd_rand, &setrand, sizeof(setrand));

    /* disables event methods that don't work for bpf */
    interface_prevent_init();

    /* Initalize libevent */
    event_init();

    /* Three priorities - UI connections always get a better priority */
    event_priority_init(3);

    syslog_init(orig_argc, orig_argv);

    /* Initalize pool allocator */
    pool_pkt = pool_init(HONEYD_MTU);
    pool_delay = pool_init(sizeof(struct delay));

    /* Initialize honeyd's callback hooks */
    hooks_init();

    tagging_init();
    arp_init();
    ndp_init();
    multicast_init();
    interface_initialize(honeyd_recv_cb);
    config_init();
    router_init();
    plugins_config_init();
    randomipv6_init();

    if (stats_username != NULL )
    {
        stats_init();
        stats_init_collect(&stats_dst, stats_port, stats_username,
                           stats_password);
    }

    /* this is basically just tree/queues initialization */
    personality_init();
    xprobe_personality_init();
    associations_init();

    /* Xprobe2 fingerprints */
    if ((fp = fopen(config.xprobe, "r")) == NULL )
        err(1, "fopen(%s)", config.xprobe);
    if (xprobe_personality_parse(fp) == -1)
        errx(1, "parsing xprobe personality file failed");
    fclose(fp);

    /* Association between xprobe and nmap fingerprints */
    if ((fp = fopen(config.assoc, "r")) == NULL )
        err(1, "fopen(%s)", config.assoc);
    if (parse_associations(fp) == -1)
        errx(1, "parsing associations file failed");
    fclose(fp);

    /* Nmap fingerprints */
    if ((fp = fopen(config.pers, "r")) == NULL )
        err(1, "fopen(%s)", config.pers);
    if (personality_parse(fp) == -1)
        errx(1, "parsing personality file failed");
    fclose(fp);

    /* PF OS fingerprints */
    if (honeyd_osfp_init(config.osfp) == -1)
        errx(1, "reading OS fingerprints failed");

    /* record start time and increse number of file descriptors etc. */
    honeyd_init();

    if (want_unittest)
        unittest();

    /* find available ip file descriptor */
    if ((honeyd_ip = ip_open()) == NULL )
    {
        /*
         * We ignore this error if a user just wants to verify
         * the configuration - some configs will not load without
         * this call succeeding.
         */
        if (!honeyd_verify_config)
            err(1, "ip_open");
    }

    if (honeyd_verify_config)
    {
        extern int interface_verify_config;

        /* Make sure that we do not open interfaces for real */
        interface_verify_config = 1;
    }

    /* Initialize the specified interfaces */
    /* argc is 1 if you directly pass a network parameter like
     honeyd 192.168.1.0, which is contained in argv, all other
     parameters get removed from argc and argv  */
    if (ninterfaces == 0)
        /* if you pass NULL pcap tries to find an interface */
        interface_init(NULL, argc, argc ? argv : NULL );
    else
    {
        for (i = 0; i < ninterfaces; i++)
            interface_init(dev[i], argc, argc ? argv : NULL );
    }

#ifdef HAVE_PYTHON
    /* Python support must be started before reading the configuration. */
    pyextend_init();

    /* Start our web server */
    if (!honeyd_verify_config && honeyd_is_webserver_enabled())
        pyextend_webserver_init(
            honeyd_webserver_address,
            honeyd_webserver_port,
            honeyd_webserver_root);
#endif

    /* Reads in the ethernet codes and indexes them for use in config */
    ethernetcode_init();

    /* Read main configuration file */
    if (config.config != NULL )
        config_read(config.config);

    /* Just verify the configuration - exit with success */
    if (honeyd_verify_config)
        errx(0, "parsing configuration file successful");

    /* Attach the UI interface */
    ui_init();

    /*
     * We must initialize the plugins after the config file
     * has been read, as the plugins may query config settings!
     */
    plugins_init();

    ip_fragment_init();
    ip6_fragment_init();

#ifdef HAVE_PYTHON
    /* Fix permissions of the webserver directories if requested */
    if (honeyd_webserver_fix_permissions)
        pyextend_webserver_fix_permissions(honeyd_webserver_root,
                                           honeyd_uid, honeyd_gid);
#endif

    /* Create PID file, we might not be able to remove it */
    unlink(PIDFILE);
    if ((fp = fopen(PIDFILE, "w")) == NULL )
        err(1, "fopen");

    /* Start Honeyd in the background if necessary */
    if (!honeyd_debug)
    {
        setlogmask(LOG_UPTO(LOG_INFO));

        fprintf(stderr, "Honeyd starting as background process\n");
        if (daemon(1, 0) < 0)
        {
            unlink(PIDFILE);
            err(1, "daemon");
        }
    }

    fprintf(fp, "%d\n", getpid());
    fclose(fp);

    chmod(PIDFILE, 0644);

    // Drop privileges if we do not need them
    if (honeyd_needsroot <= 0)
    {
        cmd_droppriv(honeyd_uid, honeyd_gid);

        syslog(LOG_NOTICE, "Demoting process privileges to uid %u, gid %u",
               honeyd_uid, honeyd_gid);
    }
    else
    {
        syslog(LOG_WARNING, "Running with root privileges.");
    }

    /*
     * Check that this version of Honeyd does not have any critical
     * security holes.
     */

    if (!honeyd_disable_update)
        update_check();

#ifdef HAVE_PYTHON
    /* Verify that the webserver space is setup correctly */
    if (honeyd_is_webserver_enabled())
        pyextend_webserver_verify_setup(honeyd_webserver_root);
    else
        syslog(LOG_INFO, "Internal webserver has been disabled.");
#endif

    /* Setup signal handler */
    if (signal(SIGPIPE, SIG_IGN ) == SIG_ERR )
    {
        perror("signal");
        return (-1);
    }

    /* 3rd parameter is the event handler */
    signal_set(&sigint_ev, SIGINT, honeyd_signal, NULL);
    signal_add(&sigint_ev, NULL);
    signal_set(&sigterm_ev, SIGTERM, honeyd_signal, NULL);
    signal_add(&sigterm_ev, NULL);
    signal_set(&sigchld_ev, SIGCHLD, honeyd_sigchld, NULL);
    signal_add(&sigchld_ev, NULL);
    signal_set(&sighup_ev, SIGHUP, honeyd_sighup, NULL);
    signal_add(&sighup_ev, NULL);
    signal_set(&sigusr_ev, SIGUSR1, honeyd_sigusr, NULL);
    signal_add(&sigusr_ev, NULL);

    /* Start logging via rrd */
    if (honeyd_rrdtool_path != NULL && strlen(honeyd_rrdtool_path))
        honeyd_rrd_start(honeyd_rrdtool_path);

    /* Potential dependency on the timestamp used for rrdtool */
    count_init();

    if (logfile != NULL )
        honeyd_logfp = honeyd_logstart(logfile);
    if (servicelog != NULL )
        honeyd_servicefp = honeyd_logstart(servicelog);


    event_dispatch();

    syslog(LOG_ERR, "Kqueue does not recognize bpf filedescriptor.");
    return (0);
}

/*
 * Enables the ipv6 random mode with a certain percentage.
 * If the random mode is enabled, then for a certain number of
 * request (random percentage) a template is generated dynamically.
 * Function is called by the config parser
 */
void enable_ipv6_random_mode(float random_percentage,
                             unsigned long long max_random_hosts)
{
    if (max_random_hosts != 0)
    {
        config.max_random_ipv6_hosts = max_random_hosts;
    }
    config.randomipv6mode = 1;
    config.randomipv6_percentage = random_percentage;
    syslog(LOG_DEBUG, "random ipv6 mode enabled with factor %f",
           random_percentage);
}

/*
 * Determine if Honeyd should automatically demote the user id it is
 * going to use.
 */

void honeyd_use_uid(uid_t uid)
{
    if (!honeyd_needsroot && uid != honeyd_uid)
        honeyd_needsroot = 1;
}

void honeyd_use_gid(gid_t gid)
{
    if (!honeyd_needsroot && gid != honeyd_gid)
        honeyd_needsroot = 1;
}
