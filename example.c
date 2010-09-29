/*
 Copyright (c) 2007 - 2010 RIPE NCC - All Rights Reserved
 
 Permission to use, copy, modify, and distribute this software and its
 documentation for any purpose and without fee is hereby granted, provided
 that the above copyright notice appear in all copies and that both that
 copyright notice and this permission notice appear in supporting
 documentation, and that the name of the author not be used in advertising or
 publicity pertaining to distribution of the software without specific,
 written prior permission.
 
 THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO EVENT SHALL
 AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
 DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 
Parts of this code have been engineered after analiyzing GNU Zebra's
source code and therefore might contain declarations/code from GNU
Zebra, Copyright (C) 1999 Kunihiro Ishiguro. Zebra is a free routing
software, distributed under the GNU General Public License. A copy of
this license is included with libbgpdump.

Author: Dan Ardelean (dan@ripe.net)
*/

#include "bgpdump_lib.h"
#include <time.h>

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

    void process(BGPDUMP_ENTRY *entry);
    void show_attr(attributes_t *attr);
    void show_prefixes(int count,struct prefix *prefix);
#ifdef BGPDUMP_HAVE_IPV6
    void show_v6_prefixes(int count, struct prefix *prefix);
#endif

int main(int argc, char **argv) {  
    BGPDUMP *my_dump;
    BGPDUMP_ENTRY *my_entry=NULL;

    if(argc>1) {
	my_dump=bgpdump_open_dump(argv[1]);
    } else {
	my_dump=bgpdump_open_dump("dumps/updates.20020701.0032");
    }

    if(my_dump==NULL) {
	printf("Error opening dump file ...\n");
	exit(1);
    }

    do {
//fprintf(stdout, "Offset: %d\n", gztell(my_dump->f));
	my_entry=bgpdump_read_next(my_dump);
	if(my_entry!=NULL) {
	    process(my_entry);
	    bgpdump_free_mem(my_entry);
	}
    } while(my_dump->eof==0);

    bgpdump_close_dump(my_dump);
//fprintf(stderr, "%s: OK=%d, BAD=%d (%f%% OK)\n", my_dump->filename, my_dump->parsed_ok, my_dump->parsed - my_dump->parsed_ok, (float) my_dump->parsed_ok / my_dump->parsed * 100);
    
 return 0;
}

char *bgp_state_name[] = {
    "Unknown",
    "IDLE",
    "CONNECT",
    "ACTIVE",
    "OPEN_SENT",
    "OPEN_CONFIRM",
    "ESTABLISHED",
    NULL
};

char *bgp_message_types[] = {
    "Unknown",
    "Open",
    "Update/Withdraw",
    "Notification",
    "Keepalive"
};

char *notify_codes[] = {
    "Unknown",
    "Message Header Error",
    "OPEN Message Error",
    "UPDATE Message Error",
    "Hold Timer Expired",
    "Finite State Machine Error",
    "Cease"
};

char *notify_subcodes[][12] = {
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
    /* Message Header Error */
    {
	"None",
 	"Connection Not Synchronized",
	"Bad Message Length",
	"Bad Message Type",
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL 
    },
    /* OPEN Message Error */
    {
	"None",
	"Unsupported Version Number",
	"Bad Peer AS",
	"Bad BGP Identifier",
	"Unsupported Optional Parameter",
	"Authentication Failure",
	"Unacceptable Hold Time",
	NULL, NULL, NULL, NULL, NULL
    },
    /* UPDATE Message Error */
    {
	"None",
	"Malformed Attribute List",
	"Unrecognized Well-known Attribute",
	"Missing Well-known Attribute",
	"Attribute Flags Error",
	"Attribute Length Error",
	"Invalid ORIGIN Attribute",
	"AS Routing Loop",
	"Invalid NEXT_HOP Attribute",
	"Optional Attribute Error",
	"Invalid Network Field",
	"Malformed AS_PATH"
    },
    /* Hold Timer Expired */
    { "None", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
    /* Finite State Machine Error */
    { "None", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
    /* Cease */
    { "None", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }

};

void process(BGPDUMP_ENTRY *entry) {
    char prefix[BGPDUMP_ADDRSTRLEN], peer_ip[BGPDUMP_ADDRSTRLEN];
    char source_ip[BGPDUMP_ADDRSTRLEN], destination_ip[BGPDUMP_ADDRSTRLEN];
    struct mp_nlri *mp_announce, *mp_withdraw;
    int i, code, subcode;
	BGPDUMP_TABLE_DUMP_V2_PREFIX *e;

if(entry->type == BGPDUMP_TYPE_ZEBRA_BGP && entry->subtype == BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE && entry->body.zebra_message.type == BGP_MSG_KEEPALIVE) return;
if(entry->type == BGPDUMP_TYPE_ZEBRA_BGP && entry->subtype == BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE && entry->body.zebra_message.type == BGP_MSG_OPEN) return;
if(entry->type == BGPDUMP_TYPE_ZEBRA_BGP && entry->subtype == BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE && entry->body.zebra_message.type == BGP_MSG_NOTIFY) return;
if(entry->type == BGPDUMP_TYPE_ZEBRA_BGP && entry->subtype == BGPDUMP_SUBTYPE_ZEBRA_BGP_STATE_CHANGE && entry->length == 8) return;

    printf("TIME            : %s",asctime(gmtime(&entry->time)));
    printf("LENGTH          : %u\n", entry->length);
    switch(entry->type) {
	case BGPDUMP_TYPE_MRTD_TABLE_DUMP:
	    if(entry->subtype == AFI_IP) {
		strcpy(prefix, inet_ntoa(entry->body.mrtd_table_dump.prefix.v4_addr));
		strcpy(peer_ip, inet_ntoa(entry->body.mrtd_table_dump.peer_ip.v4_addr));
#ifdef BGPDUMP_HAVE_IPV6
	    } else if(entry->subtype == AFI_IP6) {
		inet_ntop(AF_INET6, &entry->body.mrtd_table_dump.prefix.v6_addr, prefix,
			  sizeof(prefix));
		inet_ntop(AF_INET6, &entry->body.mrtd_table_dump.peer_ip.v6_addr, peer_ip,
			  sizeof(peer_ip));
#endif
	    } else {
		*prefix = '\0';
		*peer_ip = '\0';
	    }
	    printf("TYPE            : BGP Table Dump Entry\n");
	    printf("    VIEW        : %d\n",entry->body.mrtd_table_dump.view);
	    printf("    SEQUENCE    : %d\n",entry->body.mrtd_table_dump.sequence);
	    printf("    PREFIX      : %s/%d\n",prefix,entry->body.mrtd_table_dump.mask);
	    printf("    STATUS      : %d\n",entry->body.mrtd_table_dump.status);
	    printf("    UPTIME      : %s",asctime(gmtime(&entry->body.mrtd_table_dump.uptime)));
	    printf("    PEER IP     : %s\n",peer_ip);
	    printf("    PEER AS     : %u\n",entry->body.mrtd_table_dump.peer_as);
    	show_attr(entry->attr);
	    break;

	case BGPDUMP_TYPE_TABLE_DUMP_V2:

		e = &entry->body.mrtd_table_dump_v2_prefix;

	    if(e->afi == AFI_IP) {
			strcpy(prefix, inet_ntoa(e->prefix.v4_addr));
#ifdef BGPDUMP_HAVE_IPV6
	    } else if(e->afi == AFI_IP6) {
			inet_ntop(AF_INET6, &e->prefix.v6_addr, prefix, INET6_ADDRSTRLEN);
#endif
	    } else {
			printf("Error: BGP table dump version 2 entry with unknown subtype\n");
			break;
	    }

		for(i = 0; i < e->entry_count; i++){
			if(i){
    			printf("\nTIME            : %s",asctime(gmtime(&entry->time)));
    			printf("LENGTH          : %u\n", entry->length);
			}


    		printf("TYPE            : BGP Table Dump version 2 Entry\n");
    		printf("    SEQUENCE    : %d\n",e->seq);
    		printf("    PREFIX      : %s/%d\n",prefix,e->prefix_length);

			if(e->entries[i].peer->afi == AFI_IP){
				inet_ntop(AF_INET, &e->entries[i].peer->peer_ip, peer_ip, INET6_ADDRSTRLEN);
#ifdef BGPDUMP_HAVE_IPV6
			} else if (e->entries[i].peer->afi == AFI_IP6){
				inet_ntop(AF_INET6, &e->entries[i].peer->peer_ip, peer_ip, INET6_ADDRSTRLEN);
#endif
			} else {
				sprintf(peer_ip, "N/A, unsupported AF");
			}
    		printf("    PEER IP     : %s\n",peer_ip);
    		printf("    PEER AS     : %u\n",e->entries[i].peer->peer_as);

   			show_attr(e->entries[i].attr);
		}

	    break;

	case BGPDUMP_TYPE_ZEBRA_BGP:
	    printf("TYPE            : Zebra BGP \n");
		if(entry->body.zebra_message.address_family == AFI_IP) {
		    strcpy(source_ip, inet_ntoa(entry->body.zebra_message.source_ip.v4_addr));
		    strcpy(destination_ip, inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr));
#ifdef BGPDUMP_HAVE_IPV6
		} else if(entry->body.zebra_message.address_family == AFI_IP6) {
		    inet_ntop(AF_INET6, &entry->body.zebra_message.source_ip.v6_addr, source_ip,
			      sizeof(source_ip));
		    inet_ntop(AF_INET6, &entry->body.zebra_message.destination_ip.v6_addr, destination_ip,
			      sizeof(destination_ip));
#endif
		} else {
		    *source_ip = '\0';
		    *destination_ip = '\0';
		}
	    switch(entry->subtype) {
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_AS4:
		    printf("SUBTYPE         : Zebra BGP Message");
		    if(entry->subtype == BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_AS4) {
		      printf(" (32-bit ASN)\n");
		    } else {
		      printf("\n");
		    }
		    printf("    SOURCE_AS   : %u\n",entry->body.zebra_message.source_as);
		    printf("    DEST_AS     : %u\n",entry->body.zebra_message.destination_as);
		    printf("    INTERFACE   : %d\n",entry->body.zebra_message.interface_index);
		    printf("    SOURCE_IP   : %s\n",source_ip);
		    printf("    DEST_IP     : %s\n",destination_ip);

		    if(entry->body.zebra_message.type > sizeof(bgp_message_types) / sizeof(bgp_message_types[0]))
			printf("MESSAGE TYPE    : Unknown\n");
		    else
			printf("MESSAGE TYPE    : %s\n", bgp_message_types[entry->body.zebra_message.type]);

		    switch(entry->body.zebra_message.type) {
			case BGP_MSG_UPDATE:
			    printf("WITHDRAW        :\n");
			    show_prefixes(entry->body.zebra_message.withdraw_count,entry->body.zebra_message.withdraw);
#ifdef BGPDUMP_HAVE_IPV6
			    if(entry->attr->mp_info &&
			       (mp_withdraw = MP_IPV6_WITHDRAW(entry->attr->mp_info)) != NULL) {
				show_v6_prefixes(mp_withdraw->prefix_count, mp_withdraw->nlri);
			    }
#endif
			    printf("ANNOUNCE        :\n");
			    show_prefixes(entry->body.zebra_message.announce_count,entry->body.zebra_message.announce);
#ifdef BGPDUMP_HAVE_IPV6
			    if(entry->attr->mp_info &&
			       (mp_announce = MP_IPV6_ANNOUNCE(entry->attr->mp_info)) != NULL) {
				show_v6_prefixes(mp_announce->prefix_count, mp_announce->nlri);
			    }
#endif
			    break;
			case BGP_MSG_KEEPALIVE:
			    /* Nothing to do */
			    break;
			case BGP_MSG_OPEN:
			    printf("    VERSION     : %d\n",entry->body.zebra_message.version);
			    printf("    MY_ASN      : %u\n",entry->body.zebra_message.my_as);
			    printf("    HOLD_TIME   : %d\n",entry->body.zebra_message.hold_time);
			    printf("    ROUTER_ID   : %s\n",inet_ntoa(entry->body.zebra_message.bgp_id));
			    printf("    OPTION_LEN  : %d\n",entry->body.zebra_message.opt_len);
			    printf("    OPTION_DATA :");
			    for(i = 0; i < entry->body.zebra_message.opt_len; i++) {
				printf(" %02x", entry->body.zebra_message.opt_data[i]);
			    }
			    printf("\n");
			    break;
			case BGP_MSG_NOTIFY:
			    code = entry->body.zebra_message.error_code;
			    subcode = entry->body.zebra_message.sub_error_code;

			    printf("    CODE        : %d", code);
			    if(code >= sizeof(notify_codes) / sizeof(notify_codes[0]))
				printf(" (Unknown)\n");
			    else
				printf(" (%s)\n", notify_codes[code]);

			    printf("    SUBCODE     : %d", subcode);
			    if(code >= sizeof(notify_codes) / sizeof(notify_codes[0]) ||
			       subcode >= sizeof(notify_subcodes[0]) / sizeof(notify_subcodes[0][0]) ||
			       notify_subcodes[code][subcode] == NULL)
				printf(" (Unknown)\n");
			    else
				printf(" (%s)\n", notify_subcodes[code][subcode]);

			    printf("    DATA        :");
			    for(i = 0; i < entry->body.zebra_message.notify_len; i++) {
				printf(" %02x", entry->body.zebra_message.notify_data[i]);
			    }
			    printf("\n");
			    break;
			default:
			    break;
		    }
		    break;

		case BGPDUMP_SUBTYPE_ZEBRA_BGP_STATE_CHANGE:
		    printf("SUBTYPE         : Zebra BGP State Change\n");
		    printf("    SOURCE_AS   : %u\n",entry->body.zebra_state_change.source_as);
		    printf("    DEST_AS     : %u\n",entry->body.zebra_state_change.destination_as);
		    printf("    INTERFACE   : %d\n",entry->body.zebra_state_change.interface_index);
		    printf("    SOURCE_IP   : %s\n",source_ip);
		    printf("    DEST_IP     : %s\n",destination_ip);
		    printf("    OLD_STATE   : %s\n",bgp_state_name[entry->body.zebra_state_change.old_state]);
		    printf("    NEW_STATE   : %s\n",bgp_state_name[entry->body.zebra_state_change.new_state]);
    		show_attr(entry->attr);
		    break;

		default:
		    printf("SUBTYPE         : Unknown %d\n", entry->subtype);
	    }
    	show_attr(entry->attr);
	    break;
	default:
	    printf("TYPE            : Unknown %d\n", entry->type);
    	show_attr(entry->attr);
	    
    }
    printf("\n");
}

void show_attr(attributes_t *attr) {
    int have_nexthop = 0;
    printf("ATTRIBUTES      :\n");
    
    if(attr != NULL) {
	    printf("   ATTR_LEN     : %d\n",attr->len);

	    if( (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGIN) ) !=0 )		printf("   ORIGIN       : %d\n",attr->origin);
	    else printf("   ORIGIN       : N/A\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AS_PATH) ) !=0)		printf("   ASPATH       : %s\n",attr->aspath->str);
	    else printf("   ASPATH       : N/A\n");

	    printf("   NEXT_HOP     : ");
	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP) ) !=0) {
		have_nexthop = 1;
		printf("%s", inet_ntoa(attr->nexthop));
	    }

#ifdef BGPDUMP_HAVE_IPV6
	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)) &&
	         MP_IPV6_ANNOUNCE(attr->mp_info) != NULL) {
		char addr[INET6_ADDRSTRLEN];
		struct mp_nlri *mp_nlri = MP_IPV6_ANNOUNCE(attr->mp_info);
		u_int8_t len = mp_nlri->nexthop_len;

		if(have_nexthop)
		    printf(" ");

		have_nexthop = 1;
		printf("%s", inet_ntop(AF_INET6, &mp_nlri->nexthop, addr, sizeof(addr)));
		if(len == 32)
		    printf(" %s", inet_ntop(AF_INET6, &mp_nlri->nexthop_local, addr, sizeof(addr)));
	    }
#endif

	    printf(have_nexthop ? "\n" : "N/A\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) !=0)	printf("   MED          : %d\n",attr->med);
	    else printf("   MED          : N/A\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) !=0)		printf("   LOCAL_PREF   : %d\n",attr->local_pref);
	    else printf("   LOCAL_PREF   : N/A\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE) ) !=0)	printf("   ATOMIC_AGREG : Present\n");
	    else printf("   ATOMIC_AGREG : N/A\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR) ) !=0)		printf("   AGGREGATOR   : %s AS%u\n",inet_ntoa(attr->aggregator_addr),attr->aggregator_as);
	    else printf("   AGGREGATOR   : N/A\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	printf("   COMMUNITIES  : %s\n",attr->community->str);
	    else printf("   COMMUNITIES  : N/A\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEW_AS_PATH) ) !=0) {
		printf("   NEW_ASPATH   : %s\n",attr->new_aspath->str);
	    	printf("   OLD_ASPATH   : %s\n",attr->old_aspath->str);
	    }

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEW_AGGREGATOR) ) !=0)	printf("   NEW_AGGREGTR : %s AS%u\n",inet_ntoa(attr->new_aggregator_addr),attr->new_aggregator_as);
    }
}

void show_prefixes(int count,struct prefix *prefix) {
    int i;
    for(i=0;i<count;i++)
	printf("      %s/%d\n",inet_ntoa(prefix[i].address.v4_addr),prefix[i].len);
}

#ifdef BGPDUMP_HAVE_IPV6
void show_v6_prefixes(int count, struct prefix *prefix) {
    int i;
    char str[INET6_ADDRSTRLEN];

    for(i=0;i<count;i++){
	inet_ntop(AF_INET6, &prefix[i].address.v6_addr, str, sizeof(str));
	printf("      %s/%d\n",str, prefix[i].len);
    }
}
#endif
