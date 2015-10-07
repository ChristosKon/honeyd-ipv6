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
#include <sys/tree.h>
#include <sys/queue.h>
#include <dnet.h>
#include <event.h>
#include <pcap.h>
#include <string.h>
#include "syslog.h"
#include "err.h"

#include "honeyd.h"
#include "template.h"
#include "randomipv6.h"
#include "bloom.h"

#include <netinet/icmp6.h>
#include "icmp6.h"

#include <arpa/inet.h>


BLOOM *blocked_addr_bloom_filter;
int number_of_collisions = 0;

void init_blocked_addr_bloom_filter()
{
    blocked_addr_bloom_filter = bloom_create(40000000);
    if (!blocked_addr_bloom_filter)
    {
        errx(1,"could not create bloom filter!");
    }
}

void randomipv6_init()
{
    init_blocked_addr_bloom_filter();
}

int is_randomly_accepted(float randomipv6_percentage)
{
    /*
     * Use random to check if we want to create a new template
     * User can set a value between 0.0 and 1.0
     */
    int random_value;
    random_value = rand() % (int)(1.0/randomipv6_percentage);
    if(random_value==0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

char *get_template_name_from_packet(struct ip6_hdr *ip6) 
{
    struct icmp6_hdr *icmp6;
    u_char *tcp=NULL,*udp=NULL;
    char *template_name = NULL;
    int use_ip6_dst_address = 0;
    /* in case of a neighbor solicitation get the solicited address */
    get_ip6_next_hdr((u_char**) &icmp6, ip6, IPPROTO_ICMPV6);
    if (icmp6 != NULL && icmp6->icmp6_type==ND_NEIGHBOR_SOLICIT)
    {
      template_name = get_solicited_addr_as_str(icmp6);
    } 
   

    /* in case of tcp, udp or an echo request */
    get_ip6_next_hdr((u_char**) &tcp, ip6, IPPROTO_TCP);
    get_ip6_next_hdr((u_char**) &udp, ip6, IPPROTO_UDP);
    use_ip6_dst_address = tcp!=NULL || udp!=NULL || (icmp6 != NULL && icmp6->icmp6_type==ICMP6_ECHO_REQUEST);
    if(use_ip6_dst_address)
    {
      template_name = (char *)malloc(INET6_ADDRSTRLEN);
      if (template_name == NULL) {
        syslog(LOG_DEBUG, "could not allocate enough memory for template name");
        return NULL;
      } else {
        inet_ntop(AF_INET6,&ip6->ip6_dst,template_name,INET6_ADDRSTRLEN);
      }
   }

  /* get target ip in case of tcp or udp */

  return template_name;
}

void create_template(char *template_name, const struct interface *inter,FILE *logfp)
{
    struct template *default_template=NULL,*new_template=NULL;
    syslog(LOG_DEBUG,"create template for %s to handle dynamic request",template_name);
    
    if(logfp != NULL) {
      fprintf(logfp,"create template for %s to handle dynamic request\n",template_name);
    }
    /* get the random default template */
    char *a = RANDOM_IPV6_DEFAULT_TEMPLATE;
    default_template = template_find(a);

    /* insert the template */
    if(default_template!=NULL)
    {
        new_template = template_clone(template_name, default_template,inter,0);

        if(new_template != NULL)
        {
            template_insert(new_template);
        }
        else
        {
            syslog(LOG_DEBUG,"cloning template failed, cancel dynamic template creation");
        }

    }
    else
    {
        syslog(LOG_DEBUG,"could not find a default template, cancel dynamic template creation");
    }
}

/*
 * Creates an IPv6 template - used to create on-demand ipv6 templates based
 * on received neighbor solicitations. It does not create a template if the
 * requested address is the host address. The function uses the percentage
 * configured in the config file (ipv6randommode) to decide whether to create
 * a template or not. Therefore, calling this function does not necessarily
 * create a new template. It also does not create more templates than allowed.
 * Once the function decides not to create a certain template it will never
 * again create a template with the requested address (consistency).
 * Returns 1 if a template was created.
 */
int random_create_ipv6_template(const char *template_name, const struct interface *inter,float randomipv6_percentage,unsigned long long max_random_ipv6_hosts, FILE *logfp)
{
    static long dynamically_created_templates = 0;//remember number of templates we created dynamically

    /* check if we are allowed to create more templates */
    if(max_random_ipv6_hosts != 0 && dynamically_created_templates>=max_random_ipv6_hosts)
    {
        syslog(LOG_DEBUG,"reached max number of allowed dynamically created templates, cancel creation for %s",template_name);
        fprintf(logfp, "reached max number of allowed dynamically created templates, cancel creation for %s\n",template_name);
        return 0;
    }


    syslog(LOG_DEBUG,"check if address belongs to rejected addresses");
    if(bloom_check(blocked_addr_bloom_filter,template_name))
    {
        syslog(LOG_DEBUG, "probably blocked address %s requested...",template_name);
        return 0;
    }

    syslog(LOG_DEBUG,"check if randomly accept address");
    if(is_randomly_accepted(randomipv6_percentage))
    {
        create_template(template_name,inter,logfp);
        dynamically_created_templates++;
        return 1;
    }
    else
    {
        syslog(LOG_DEBUG,"%s added to blocked addresses...",template_name);
        fprintf(logfp, "added address %s to blocked addresses\n",template_name);
        /* add entry to the blocked list */
        bloom_add(blocked_addr_bloom_filter,template_name);
        return 0;
    }



}



/*
 * Keeps the address from being generated.
 */
void exclude_addr_from_generator(char * addr_str)
{
    if(addr_str == NULL)
    {
        syslog(LOG_DEBUG,"cannot block NULL address");
        return;
    }

    if(bloom_check(blocked_addr_bloom_filter,addr_str))
    {
        number_of_collisions++;
    }

    //syslog(LOG_DEBUG,"blocking %s...",addr_str);
    bloom_add(blocked_addr_bloom_filter,addr_str);
}



void generate_mock_blocked_entries(int number_of_mocked_entries)
{
    syslog(LOG_DEBUG,"generating mock blocked entries...");
    int i;
    struct addr blocked_addr;
    addr_aton("2001:db8::3",&blocked_addr);
    for(i=0; i<number_of_mocked_entries; i++)
    {
        blocked_addr.addr_data32[3]++;
        exclude_addr_from_generator(addr_ntoa(&blocked_addr));
    }
    syslog(LOG_DEBUG,"finished generating mock blocked entries with %d collisions.",number_of_collisions);
}
