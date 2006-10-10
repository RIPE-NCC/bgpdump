static const char RCSID[] = "$Id$";
/*

Copyright (c) 2002                      RIPE NCC


All Rights Reserved

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

*/

/* 

Parts of this code have been engineered after analiyzing GNU Zebra's
source code and therefore might contain declarations/code from GNU
Zebra, Copyright (C) 1999 Kunihiro Ishiguro. Zebra is a free routing
software, distributed under the GNU General Public License. A copy of
this license is included with libbgpdump.

*/


/*
-------------------------------------------------------------------------------
Module Header
Filename          : bgdump_lib.c
Author            : Dan Ardelean (dan@ripe.net)
Date              : 02-SEP-2002
Revision          : 
Revised           : 
Description       : Library implementation
Language Version  : C
OSs Tested        : Linux 2.2.19
To Do             : 
-------------------------------------------------------------------------------
*/

#include "bgpdump_lib.h"
#include "bgpdump_mstream.h"

#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <syslog.h>

#include <zlib.h>
#include <assert.h>

static    int process_mrtd_bgp(struct mstream *s,BGPDUMP_ENTRY *entry);
static    int process_mrtd_table_dump(struct mstream *s,BGPDUMP_ENTRY *entry);
static    int process_zebra_bgp(struct mstream *s,BGPDUMP_ENTRY *entry);
static    int process_zebra_bgp_state_change(struct mstream *s,BGPDUMP_ENTRY *entry);
    
static    int process_zebra_bgp_message(struct mstream *s,BGPDUMP_ENTRY *entry, size_t asn_len);
static    int process_zebra_bgp_message_update(struct mstream *s,BGPDUMP_ENTRY *entry);
static    int process_zebra_bgp_message_open(struct mstream *s,BGPDUMP_ENTRY *entry);
static    int process_zebra_bgp_message_notify(struct mstream *s,BGPDUMP_ENTRY *entry);

static    int process_zebra_bgp_entry(struct mstream *s,BGPDUMP_ENTRY *entry);
static    int process_zebra_bgp_snapshot(struct mstream *s,BGPDUMP_ENTRY *entry);

static    void process_attr_init(BGPDUMP_ENTRY *entry);
static    void process_attr_read(struct mstream *s, struct attr *attr, size_t asn_len, struct zebra_incomplete *incomplete);
static    void process_attr_aspath_string(struct aspath *as, size_t len);
static    char aspath_delimiter_char (u_char type, u_char which);
static    void process_attr_community_string(struct community *com);

static    void process_mp_announce(struct mstream *s, struct mp_info *info, int len, struct zebra_incomplete *incomplete);
static    void process_mp_withdraw(struct mstream *s, struct mp_info *info, int len, struct zebra_incomplete *incomplete);
static    u_int16_t read_prefix_list(struct mstream *s, int len, u_int16_t af, struct prefix **prefixarray, struct zebra_incomplete *incomplete);

static    as_t read_asn(struct mstream *s, as_t *asn, size_t len);

#if defined(linux)
static    size_t strlcat(char *dst, const char *src, size_t size);
#endif

BGPDUMP *bgpdump_open_dump(char *filename) {
    BGPDUMP *this_dump=NULL;
    gzFile *f;

    this_dump = malloc(sizeof(BGPDUMP));

    if((filename == NULL) || (strcmp(filename, "-") == 0)) {
	/* dump from stdin */
	f = gzdopen(0, "r");
	strcpy(this_dump->filename, "[STDIN]");
    } else {
	f = gzopen(filename, "r");
	strcpy(this_dump->filename, filename);
    }
    
    if(f == NULL) {
	free(this_dump);
	return NULL;
    }
    
    this_dump->f = f;
    this_dump->eof=0;
    this_dump->parsed = 0;
    this_dump->parsed_ok = 0;

    return this_dump;
}

void bgpdump_close_dump(BGPDUMP *dump) {
    if(dump!=NULL) 
	gzclose(dump->f);
}

BGPDUMP_ENTRY*	bgpdump_read_next(BGPDUMP *dump) {
    BGPDUMP_ENTRY *this_entry=NULL;    
    struct mstream s;
    u_char *buffer;
    int ok=0;
    int bytes_read;

    this_entry = malloc(sizeof(BGPDUMP_ENTRY));

    bytes_read = gzread(dump->f, this_entry, 12);

    if(bytes_read != 12) {
	if(bytes_read > 0) {
	    /* Malformed record */
	    dump->parsed++;
	    syslog(LOG_ERR,
		   "bgpdump_read_next: incomplete MRT header (%d bytes read, expecting 12)",
		   bytes_read);
	}
	/* Nothing more to read, quit */
	free(this_entry);
	dump->eof=1; 
	return(NULL);
    }

    dump->parsed++;

    /* Intel byte ordering stuff ... */
    this_entry->type=ntohs(this_entry->type);
    this_entry->subtype=ntohs(this_entry->subtype);
    this_entry->time=ntohl(this_entry->time);
    this_entry->length=ntohl(this_entry->length);

    this_entry->attr=NULL;

    buffer = malloc(this_entry->length);
    bytes_read = gzread(dump->f, buffer, this_entry->length);
    if(bytes_read != this_entry->length) { 
	syslog(LOG_ERR,
	       "bgpdump_read_next: incomplete dump record (%d bytes read, expecting %d)",
	       bytes_read, this_entry->length);
	free(this_entry); 
	free(buffer);
	dump->eof=1;
	return(NULL);
    }
        

    ok=0;
    mstream_init(&s,buffer,this_entry->length);

    switch(this_entry->type) {
	case BGPDUMP_TYPE_MRTD_BGP:		
		break;
	case BGPDUMP_TYPE_MRTD_TABLE_DUMP:	
		ok = process_mrtd_table_dump(&s,this_entry); 
		break;
	case BGPDUMP_TYPE_ZEBRA_BGP:
		ok = process_zebra_bgp(&s,this_entry); 
		break;
    }

    free(buffer);
    if(ok) {
	dump->parsed_ok++;
    } else {
	bgpdump_free_mem(this_entry);
	return NULL;
    }
    return this_entry;
}

void bgpdump_free_mp_info(struct mp_info *info) {
    u_int16_t afi;
    u_int8_t safi;

    for(afi = 1; afi < BGPDUMP_MAX_AFI; afi++) {
	for(safi = 1; safi < BGPDUMP_MAX_SAFI; safi++) {
	    if(info->announce[afi][safi])
		free(info->announce[afi][safi]);
	    if(info->withdraw[afi][safi])
		free(info->withdraw[afi][safi]);
	}
    }

	free(info);
}

void bgpdump_free_mem(BGPDUMP_ENTRY *entry) {
    u_int16_t i;

    if(entry!=NULL) {
	if(entry->attr != NULL) {
	    if(entry->attr->aspath != NULL) {
		if(entry->attr->aspath->data != NULL)
		    free(entry->attr->aspath->data);

		if(entry->attr->aspath->str != NULL)
		    free(entry->attr->aspath->str);

		free(entry->attr->aspath);
	    }
	    
	    if(entry->attr->community != NULL) {
		if(entry->attr->community->val != NULL)
		    free(entry->attr->community->val);

		if(entry->attr->community->str != NULL)
		    free(entry->attr->community->str);

		free(entry->attr->community);
	    }

	    if(entry->attr->data != NULL)
		free(entry->attr->data);

	    if(entry->attr->mp_info != NULL)
		bgpdump_free_mp_info(entry->attr->mp_info);

	    if (entry->attr->unknown_num) {
		for (i = 0; i < entry->attr->unknown_num; i++)
		    free(entry->attr->unknown[i].raw);
		free(entry->attr->unknown);
	    }

	    free(entry->attr);
	}


	switch(entry->type) {
	    case BGPDUMP_TYPE_MRTD_TABLE_DUMP:	
		break;
	    case BGPDUMP_TYPE_ZEBRA_BGP:
		switch(entry->subtype) {
		    case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE:
			switch(entry->body.zebra_message.type) {
			    case BGP_MSG_UPDATE:
				if(entry->body.zebra_message.withdraw != NULL)
				    free(entry->body.zebra_message.withdraw);
    				if(entry->body.zebra_message.announce != NULL)
				    free(entry->body.zebra_message.announce);
				break;
			    case BGP_MSG_NOTIFY:
				if(entry->body.zebra_message.notify_data)
				    free(entry->body.zebra_message.notify_data);
				break;
			    case BGP_MSG_OPEN:
				if(entry->body.zebra_message.opt_data)
				    free(entry->body.zebra_message.opt_data);
				break;
			}
			break;
		}
		break;
	}

	free(entry);
    }
}

int process_mrtd_bgp(struct mstream *s,BGPDUMP_ENTRY *entry) {    
    syslog(LOG_WARNING, "process_mrtd_bgp: record type not implemented");
    return 0;
}

int process_mrtd_table_dump(struct mstream *s,BGPDUMP_ENTRY *entry) {
    int afi = entry->subtype;

    mstream_getw(s,&entry->body.mrtd_table_dump.view);
    mstream_getw(s,&entry->body.mrtd_table_dump.sequence);
    switch(afi) {
	case AFI_IP:
	    mstream_get_ipv4(s, &entry->body.mrtd_table_dump.prefix.v4_addr.s_addr);
	    break;
#ifdef BGPDUMP_HAVE_IPV6
	case AFI_IP6:
	    mstream_get(s, &entry->body.mrtd_table_dump.prefix.v6_addr.s6_addr, 16);
	    break;
#endif
	default:
	    syslog(LOG_WARNING, "process_mrtd_table_dump: unknown AFI %d",  afi);
	    return 0;
    }
    mstream_getc(s,&entry->body.mrtd_table_dump.mask);
    mstream_getc(s,&entry->body.mrtd_table_dump.status);
    mstream_getl(s,(u_int32_t *)&entry->body.mrtd_table_dump.uptime);
    if(afi == AFI_IP)
	mstream_get_ipv4(s, &entry->body.mrtd_table_dump.peer_ip.v4_addr.s_addr);
#ifdef BGPDUMP_HAVE_IPV6
    else if(afi == AFI_IP6)
	mstream_get(s, &entry->body.mrtd_table_dump.peer_ip.v6_addr.s6_addr, 16);
#endif

    read_asn(s,&entry->body.mrtd_table_dump.peer_as, ASN16_LEN);

    process_attr_init(entry);
    process_attr_read(s, entry->attr, ASN16_LEN, NULL);

    return 1;
}

int process_zebra_bgp(struct mstream *s,BGPDUMP_ENTRY *entry) {
    switch(entry->subtype) {
	case BGPDUMP_SUBTYPE_ZEBRA_BGP_STATE_CHANGE:
	    return process_zebra_bgp_state_change(s, entry);
	case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE:
	    return process_zebra_bgp_message(s, entry, ASN16_LEN);
	case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE32:
	    return process_zebra_bgp_message(s, entry, ASN32_LEN);
	case BGPDUMP_SUBTYPE_ZEBRA_BGP_ENTRY:
	    return process_zebra_bgp_entry(s,entry);
	case BGPDUMP_SUBTYPE_ZEBRA_BGP_SNAPSHOT:
	    return process_zebra_bgp_snapshot(s, entry);
	default:
	    syslog(LOG_WARNING, "process_zebra_bgp: unknown subtype %d", entry->subtype);
	    return 0;
    }
}


int 
process_zebra_bgp_state_change(struct mstream *s,BGPDUMP_ENTRY *entry) {
    read_asn(s, &entry->body.zebra_state_change.source_as, ASN16_LEN);
    read_asn(s, &entry->body.zebra_state_change.destination_as, ASN16_LEN);

    /* Work around Zebra dump corruption.
     * N.B. I don't see this in quagga 0.96.4 any more. Is it fixed? */
    if (entry->length == 8) {
	syslog(LOG_NOTICE,
	       "process_zebra_bgp_state_change: 8-byte state change (zebra bug?)");

	mstream_getw(s,&entry->body.zebra_state_change.old_state);
	mstream_getw(s,&entry->body.zebra_state_change.new_state);

	/* Fill in with dummy values */
	entry->body.zebra_state_change.interface_index = 0;
	entry->body.zebra_state_change.address_family = AFI_IP;
	entry->body.zebra_state_change.source_ip.v4_addr.s_addr = 0;
	entry->body.zebra_state_change.destination_ip.v4_addr.s_addr = 0;

   	return 1;
    }

    mstream_getw(s,&entry->body.zebra_state_change.interface_index);
    mstream_getw(s,&entry->body.zebra_state_change.address_family);

    switch(entry->body.zebra_state_change.address_family) {
	case AFI_IP:
	    if(entry->length != 20) {
		syslog(LOG_WARNING, "process_zebra_bgp_state_change: bad length %d",
		       entry->length);
		return 0;
	    }

	    mstream_get_ipv4(s,&entry->body.zebra_state_change.source_ip.v4_addr.s_addr);
	    mstream_get_ipv4(s,&entry->body.zebra_state_change.destination_ip.v4_addr.s_addr);
	    break;
#ifdef BGPDUMP_HAVE_IPV6
	case AFI_IP6:
	    if(entry->length != 44) {
		syslog(LOG_WARNING, "process_zebra_bgp_state_change: bad length %d",
		       entry->length);
		return 0;
	    }

	    mstream_get(s, &entry->body.zebra_state_change.source_ip.v6_addr.s6_addr, 16);
	    mstream_get(s, &entry->body.zebra_state_change.destination_ip.v6_addr.s6_addr, 16);
	    break;
#endif
	default:
	    syslog(LOG_WARNING, "process_zebra_bgp_state_change: unknown AFI %d",
		   entry->body.zebra_state_change.address_family);
	    return 0;
    }
    mstream_getw(s,&entry->body.zebra_state_change.old_state);
    mstream_getw(s,&entry->body.zebra_state_change.new_state);

    return 1;
}

int process_zebra_bgp_message(struct mstream *s,BGPDUMP_ENTRY *entry, size_t asn_len) {
    u_char marker[16]; /* BGP marker */

    entry->body.zebra_message.asn_len = asn_len;
    read_asn(s, &entry->body.zebra_message.source_as, asn_len);
    read_asn(s, &entry->body.zebra_message.destination_as, asn_len);
    mstream_getw(s,&entry->body.zebra_message.interface_index);
    mstream_getw(s,&entry->body.zebra_message.address_family);

    /* Initialize announce and withdraw arrays: if there is a
     * parse error, they will not be free()d, and we will not segfault. */
    entry->body.zebra_message.withdraw = NULL;
    entry->body.zebra_message.announce = NULL;

    entry->body.zebra_message.opt_len = 0;
    entry->body.zebra_message.opt_data = NULL;
    entry->body.zebra_message.notify_len = 0;
    entry->body.zebra_message.notify_data = NULL;

    switch(entry->body.zebra_message.address_family) {
	case AFI_IP:
	    mstream_get_ipv4(s,&entry->body.zebra_message.source_ip.v4_addr.s_addr);
	    mstream_get_ipv4(s,&entry->body.zebra_message.destination_ip.v4_addr.s_addr);
	    mstream_get (s, marker, 16);
	    break;
#ifdef BGPDUMP_HAVE_IPV6
	case AFI_IP6:
	    mstream_get(s,&entry->body.zebra_message.source_ip.v6_addr.s6_addr, 16);
	    mstream_get(s,&entry->body.zebra_message.destination_ip.v6_addr.s6_addr, 16);
	    mstream_get (s, marker, 16);
	    break;
#endif
	case 0xFFFF:
	    /* Zebra doesn't dump ifindex or src/dest IPs in OPEN
	     * messages. Work around it. */
	    if (entry->body.zebra_message.interface_index == 0xFFFF) {
		memset(marker, 0xFF, 4);
		mstream_get (s, marker + 4, 12);
		entry->body.zebra_message.interface_index = 0;
		entry->body.zebra_message.address_family = AFI_IP;
		entry->body.zebra_message.source_ip.v4_addr.s_addr = 0;
		entry->body.zebra_message.destination_ip.v4_addr.s_addr = 0;
		break;
	    }
	    /* Note fall through! If we don't recognize this type of data corruption, we say
	     * the address family is unsupported (since FFFF is not a valid address family) */
	default:			
	    /* unsupported address family */
	    syslog(LOG_WARNING, "process_zebra_bgp_message: unsupported AFI %d",
		   entry->body.zebra_message.address_family);
	    return 0;
    }

    if(memcmp(marker, "\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377", 16) != 0) {
	/* bad marker... ignore packet */
	syslog(LOG_WARNING, 
	       "bgp_message: bad marker: %02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x",
	       marker[0],marker[1],marker[2],marker[3],marker[4],marker[5],marker[6],marker[7],
	       marker[8],marker[9],marker[10],marker[11],marker[12],marker[13],marker[14],marker[15]);
	return 0;
    }

    mstream_getw (s,&entry->body.zebra_message.size);
    mstream_getc (s,&entry->body.zebra_message.type);

    entry->body.zebra_message.cut_bytes = entry->body.zebra_message.size - 19 - mstream_can_read(s);
    
    switch(entry->body.zebra_message.type) {    
	case BGP_MSG_OPEN:
	    return process_zebra_bgp_message_open(s,entry);
	case BGP_MSG_UPDATE:
	    return process_zebra_bgp_message_update(s,entry);
	case BGP_MSG_NOTIFY:
	    return process_zebra_bgp_message_notify(s,entry);
	case BGP_MSG_KEEPALIVE:
	    /* Nothing to do */
	    return 1;
	case BGP_MSG_ROUTE_REFRESH_01:
	    /* Not implemented yet */
	    syslog(LOG_WARNING, "bgp_message: MSG_ROUTE_REFRESH_01 not implemented yet");
	    return 0;
	case BGP_MSG_ROUTE_REFRESH:
	    /* Not implemented yet */
	    syslog(LOG_WARNING, "bgp_message: MSG_ROUTE_REFRESH not implemented yet");
	    return 0;
	default:
	    syslog(LOG_WARNING, "bgp_message: unknown BGP message type %d",
		   entry->body.zebra_message.type);
	    return 0;
    }
}

int process_zebra_bgp_message_notify(struct mstream *s, BGPDUMP_ENTRY *entry) {
    mstream_getc(s, &entry->body.zebra_message.error_code);
    mstream_getc(s, &entry->body.zebra_message.sub_error_code);
    entry->body.zebra_message.notify_len = entry->body.zebra_message.size - 21;

    if(entry->body.zebra_message.notify_len > 0) {
	entry->body.zebra_message.notify_data = malloc(entry->body.zebra_message.notify_len);
	mstream_get(s, entry->body.zebra_message.notify_data, entry->body.zebra_message.notify_len);
    }

    return 1;
}

int process_zebra_bgp_message_open(struct mstream *s, BGPDUMP_ENTRY *entry) {
    mstream_getc(s, &entry->body.zebra_message.version);
    mstream_getw(s, &entry->body.zebra_message.my_as);
    mstream_getw(s, &entry->body.zebra_message.hold_time);
    mstream_get_ipv4(s, &entry->body.zebra_message.bgp_id.s_addr);
    mstream_getc(s, &entry->body.zebra_message.opt_len);

    if(entry->body.zebra_message.opt_len) {
	entry->body.zebra_message.opt_data = malloc(entry->body.zebra_message.opt_len);
	mstream_get(s, entry->body.zebra_message.opt_data, entry->body.zebra_message.opt_len);
    }

    return 1;
}

int process_zebra_bgp_message_update(struct mstream *s, BGPDUMP_ENTRY *entry) {
    int withdraw_len;
    int announce_len;
    int attr_pos;

    entry->body.zebra_message.incomplete.orig_len = 0;

    withdraw_len = mstream_getw(s, NULL);
    entry->body.zebra_message.withdraw_count =
	read_prefix_list(s, withdraw_len, AFI_IP, &entry->body.zebra_message.withdraw,
			 &entry->body.zebra_message.incomplete);

    /* Where are we? */
    attr_pos = s->position;

    process_attr_init(entry);
    process_attr_read(s, entry->attr, entry->body.zebra_message.asn_len, &entry->body.zebra_message.incomplete);

    /* Get back in sync in case there are malformed attributes */
    s->position = attr_pos + entry->attr->len + 2;
    if(s->position > s->len) s->position = s->len;

    announce_len = entry->body.zebra_message.size - 23 - withdraw_len - entry->attr->len;
    entry->body.zebra_message.announce_count =
	read_prefix_list(s, announce_len, AFI_IP, &entry->body.zebra_message.announce,
			 &entry->body.zebra_message.incomplete);

    return 1;
}

int process_zebra_bgp_entry(struct mstream *s, BGPDUMP_ENTRY *entry) {
    syslog(LOG_WARNING, "process_zebra_bgp_entry: record type not implemented yet");
    return 0;
}

int process_zebra_bgp_snapshot(struct mstream *s, BGPDUMP_ENTRY *entry) {
    syslog(LOG_WARNING, "process_zebra_bgp_snapshot: record type not implemented yet");
    return 0;
}

void process_attr_init(BGPDUMP_ENTRY *entry) {

    entry->attr = malloc(sizeof(struct attr));
    
    entry->attr->refcnt			= 0;
    entry->attr->flag			= 0;
    entry->attr->origin			= -1;
    entry->attr->nexthop.s_addr		= -1;
    entry->attr->med			= -1;
    entry->attr->local_pref		= -1;
    entry->attr->aggregator_as		= -1;
    entry->attr->aggregator_addr.s_addr	= -1;
    entry->attr->weight			= -1;
    entry->attr->cluster		= NULL;

    entry->attr->aspath			= NULL;
    entry->attr->community		= NULL;
    entry->attr->transit		= NULL;

    entry->attr->mp_info		= NULL;    
    entry->attr->len			= 0;
    entry->attr->data			= NULL;

    entry->attr->unknown_num = 0;
    entry->attr->unknown = NULL;

    entry->attr->new_aspath		= NULL;
    entry->attr->new_aggregator_as	= -1;
}

void process_attr_read(struct mstream *s, struct attr *attr, size_t asn_len, struct zebra_incomplete *incomplete) {
    u_char	flag;
    u_char	type;
    u_int32_t	len, end;
    u_int32_t	truelen;
    struct unknown_attr *unknown;
    
    mstream_getw(s, &attr->len);
    attr->data=malloc(attr->len);

    /* Check the attributes are not truncated */
    if(attr->len > mstream_can_read(s)) {
	truelen = mstream_can_read(s);
	memset(attr->data + truelen, 0, attr->len - truelen);
    } else {
	truelen = attr->len;
    }
    memcpy(attr->data, &s->start[s->position], truelen);

    end = s->position + truelen;
    
    while(s->position < end) {
	mstream_getc(s,&flag);
	mstream_getc(s,&type);
	
	if(flag & BGP_ATTR_FLAG_EXTLEN) 
	    len=mstream_getw(s,NULL);
	else
	    len=mstream_getc(s,NULL);
	
	switch(type) {
	    case BGP_ATTR_ORIGIN:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);
		mstream_getc(s,&attr->origin);
		break;	    
	    case BGP_ATTR_AS_PATH:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);
		attr->aspath		= malloc(sizeof(struct aspath));
		attr->aspath->refcnt	= 0;
		attr->aspath->length	= len;
		attr->aspath->count	= 0;
		attr->aspath->data	= malloc(len);
		mstream_get(s,attr->aspath->data,len);
		attr->aspath->str	= NULL;
		process_attr_aspath_string(attr->aspath, asn_len);
		break;
	    case BGP_ATTR_NEXT_HOP:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);
		mstream_get_ipv4(s,&attr->nexthop.s_addr);
		break;
	    case BGP_ATTR_MULTI_EXIT_DISC:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
		mstream_getl(s,&attr->med);
		break;
	    case BGP_ATTR_LOCAL_PREF:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
		mstream_getl(s,&attr->local_pref);
		break;
	    case BGP_ATTR_ATOMIC_AGGREGATE:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);
		break;
	    case BGP_ATTR_AGGREGATOR:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);
		read_asn(s, &attr->aggregator_as, asn_len);
		mstream_get_ipv4(s,&attr->aggregator_addr.s_addr);
		break;
	    case BGP_ATTR_COMMUNITIES:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
		attr->community		= malloc(sizeof(struct community));
		attr->community->refcnt = 0;
		attr->community->size	= len / 4;
		attr->community->val	= malloc(len);
		mstream_get(s,attr->community->val,len);
		attr->community->str	= NULL;
		process_attr_community_string(attr->community);
		break;
	    case BGP_ATTR_MP_REACH_NLRI:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_MP_REACH_NLRI);
		if(attr->mp_info == NULL) {
		    attr->mp_info = malloc(sizeof(struct mp_info));
		    memset(attr->mp_info, 0, sizeof(struct mp_info));
		}
		process_mp_announce(s, attr->mp_info, len, incomplete);
		break;
	    case BGP_ATTR_MP_UNREACH_NLRI:
		attr->flag = attr->flag | ATTR_FLAG_BIT (BGP_ATTR_MP_UNREACH_NLRI);
		if(attr->mp_info == NULL) {
		    attr->mp_info = malloc(sizeof(struct mp_info));
		    memset(attr->mp_info, 0, sizeof(struct mp_info));
		}
		process_mp_withdraw(s, attr->mp_info, len, incomplete);
		break;
	    default:
		/* Unknown attribute. Save as is */
		attr->unknown_num++;
		attr->unknown = realloc(attr->unknown, attr->unknown_num * sizeof(struct unknown_attr));

		/* Pointer to the unknown attribute we want to fill in */
		unknown = attr->unknown + attr->unknown_num - 1;

		/* Work around bogus attribute lengths */
		if(s->position + len > end)
		    unknown->real_len = end - s->position;
		else
		    unknown->real_len = len;

		unknown->flag = flag;
		unknown->type = type;
		unknown->len = len;

		unknown->raw = malloc(unknown->real_len + ((flag & BGP_ATTR_FLAG_EXTLEN) ? 4 : 3));

		unknown->raw[0] = flag;
		unknown->raw[1] = type;

		if(flag & BGP_ATTR_FLAG_EXTLEN) {
		    unknown->raw[2] = (len & 0xFF00) >> 8;
		    unknown->raw[3] = len & 0xFF;
		    mstream_get(s, unknown->raw + 4, unknown->real_len);
		} else {
		    unknown->raw[2] = len;
		    mstream_get(s, unknown->raw + 3, unknown->real_len);
		}
		break;
	}
    }
}

void process_attr_aspath_string(struct aspath *as, size_t asn_len) {
  int space;
  u_char type;
  void *pnt;
  void *end;
  struct assegment *assegment;
  int str_size = ASPATH_STR_DEFAULT_LEN;
  int str_pnt;
  char *str_buf;
  int count = 0;

  /* Empty aspath. */
  if (as->length == 0)
    {
      str_buf = malloc(1);
      str_buf[0] = '\0';
      as->count = count;
      as->str = str_buf;
      return;
    }

  /* Set default value. */
  space = 0;
  type = AS_SEQUENCE;

  /* Set initial pointer. */
  pnt = as->data;
  end = pnt + as->length;

  str_buf = malloc(str_size);
  str_pnt = 0;

  assegment = (struct assegment *) pnt;

  while (pnt < end)
    {
      int i;
      int estimate_len;

      /* For fetch value. */
      assegment = (struct assegment *) pnt;

      /* Check AS type validity. */
      if ((assegment->type != AS_SET) && 
	  (assegment->type != AS_SEQUENCE) &&
	  (assegment->type != AS_CONFED_SET) && 
	  (assegment->type != AS_CONFED_SEQUENCE))
	{
	  free(str_buf);
	  str_buf=malloc(strlen(ASPATH_STR_ERROR)+1);
	  strcpy(str_buf,ASPATH_STR_ERROR);
	  as->count=0;
	  as->str = str_buf;
	  return;
	}

      /* Check AS length. */
      if ((pnt + (assegment->length * asn_len) + AS_HEADER_SIZE) > end)
	{
	  free(str_buf);
	  str_buf=malloc(strlen(ASPATH_STR_ERROR)+1);
	  strcpy(str_buf,ASPATH_STR_ERROR);
	  as->count=0;
	  as->str = str_buf;
	  return;
	}

      /* Buffer length check. */
      estimate_len = ((assegment->length * 6) + 4);
      
      /* String length check. */
      while (str_pnt + estimate_len >= str_size)
	{
	  str_size *= 2;
	  str_buf = realloc (str_buf, str_size);
	}

      /* If assegment type is changed, print previous type's end
         character. */
      if (type != AS_SEQUENCE)
	str_buf[str_pnt++] = aspath_delimiter_char (type, AS_SEG_END);
      if (space)
	str_buf[str_pnt++] = ' ';

      if (assegment->type != AS_SEQUENCE)
	str_buf[str_pnt++] = aspath_delimiter_char (assegment->type, AS_SEG_START);

      space = 0;

      /* Increment count - ignoring CONFED SETS/SEQUENCES */
      if (assegment->type != AS_CONFED_SEQUENCE
	  && assegment->type != AS_CONFED_SET)
	{
	  if (assegment->type == AS_SEQUENCE)
	    count += assegment->length;
	  else if (assegment->type == AS_SET)
	    count++;
	}

      for (i = 0; i < assegment->length; i++)
	{
	  int len;
	  as_t asn;
	  int asn_pos;

	  if (space)
	    {
	      if (assegment->type == AS_SET
		  || assegment->type == AS_CONFED_SET)
		str_buf[str_pnt++] = ',';
	      else
		str_buf[str_pnt++] = ' ';
	    }
	  else
	    space = 1;

	  asn_pos = i * asn_len;
	  switch(asn_len) {
	    case ASN16_LEN:
	      asn = ntohs (*(u_int16_t *) (assegment->data + asn_pos));
	      break;
	    case ASN32_LEN:
	      asn = ntohl (*(u_int32_t *) (assegment->data + asn_pos));
	      break;
	  }

	  len = sprintf (str_buf + str_pnt, "%s", print_asn(asn));
	  str_pnt += len;
	}

      type = assegment->type;
      pnt += (assegment->length * asn_len) + AS_HEADER_SIZE;
    }

  if (assegment->type != AS_SEQUENCE)
    str_buf[str_pnt++] = aspath_delimiter_char (assegment->type, AS_SEG_END);

  str_buf[str_pnt] = '\0';

  as->count = count;
  as->str = malloc(strlen(str_buf)+1);
  strcpy(as->str,str_buf);
  free(str_buf);
}

char aspath_delimiter_char (u_char type, u_char which) {
  int i;
  struct
  {
    int type;
    char start;
    char end;
  } aspath_delim_char [] =
    {
      { AS_SET,             '{', '}' },
      { AS_SEQUENCE,        ' ', ' ' },
      { AS_CONFED_SET,      '[', ']' },
      { AS_CONFED_SEQUENCE, '(', ')' },
      { 0 }
    };

  for (i = 0; aspath_delim_char[i].type != 0; i++)
    {
      if (aspath_delim_char[i].type == type)
	{
	  if (which == AS_SEG_START)
	    return aspath_delim_char[i].start;
	  else if (which == AS_SEG_END)
	    return aspath_delim_char[i].end;
	}
    }
  return ' ';
}


void process_attr_community_string(struct community *com) {

  char buf[BUFSIZ];
  int i;
  u_int32_t comval;
  u_int16_t as;
  u_int16_t val;

  memset (buf, 0, BUFSIZ);

  for (i = 0; i < com->size; i++) 
    {
      memcpy (&comval, com_nthval (com, i), sizeof (u_int32_t));
      comval = ntohl (comval);
      switch (comval) 
	{
	case COMMUNITY_NO_EXPORT:
	  strlcat (buf, " no-export", BUFSIZ);
	  break;
	case COMMUNITY_NO_ADVERTISE:
	  strlcat (buf, " no-advertise", BUFSIZ);
	  break;
	case COMMUNITY_LOCAL_AS:
	  strlcat (buf, " local-AS", BUFSIZ);
	  break;
	default:
	  as = (comval >> 16) & 0xFFFF;
	  val = comval & 0xFFFF;
	  snprintf (buf + strlen (buf), BUFSIZ - strlen (buf), 
		    " %d:%d", as, val);
	  break;
	}
    }

    com->str = malloc(strlen(buf)+1);
    strcpy(com->str, buf);
}

void process_mp_announce(struct mstream *s, struct mp_info *info, int len, struct zebra_incomplete *incomplete) {
	u_int16_t afi;
	u_int8_t safi;
	u_int8_t num_snpa;
	u_int8_t snpa_len;
	struct mp_nlri *mp_nlri;

	mstream_getw(s, &afi);
	mstream_getc(s, &safi);
	len -= 3;

	/* Do we know about this address family? */
	if(afi > BGPDUMP_MAX_AFI || safi > BGPDUMP_MAX_SAFI) {
		syslog(LOG_WARNING, "process_mp_announce: unknown AFI,SAFI %d,%d!",
		       afi, safi);
		mstream_get(s, NULL, len);
		return;
	}

	/* If there are 2 NLRI's for the same protocol, fail but don't burn and die */
	if(info->announce[afi][safi] != NULL) {
		syslog(LOG_WARNING,
		       "process_mp_announce: update contains more than one MP_NLRI with AFI,SAFI %d,%d!",
		       afi, safi);
		mstream_get(s, NULL, len);
		return;
	}

	/* Allocate structure */
	mp_nlri = malloc(sizeof(struct mp_nlri));
	memset(mp_nlri, 0, sizeof(struct mp_nlri));
	info->announce[afi][safi] = mp_nlri;

	/* Get next hop */
	mstream_getc(s, &mp_nlri->nexthop_len);
	len--;

	switch(afi) {
		case AFI_IP:
		    mstream_get_ipv4(s, &mp_nlri->nexthop.v4_addr.s_addr);
		    mstream_get(s, NULL, mp_nlri->nexthop_len - 4);
		    break;
#ifdef BGPDUMP_HAVE_IPV6
		case AFI_IP6:
		    if(mp_nlri->nexthop_len != 32 && mp_nlri->nexthop_len != 16) {
			syslog(LOG_WARNING, "process_mp_announce: unknown MP nexthop length %d",
			       mp_nlri->nexthop_len);
			mstream_get(s, NULL, len);
			return;
		    }
		    /* Get global nexthop */
		    mstream_get(s, &mp_nlri->nexthop.v6_addr, 16);
		    /* Is there also a link-local address? */
		    if(mp_nlri->nexthop_len == 32)
			mstream_get(s, &mp_nlri->nexthop_local.v6_addr.s6_addr, 16);
		    break;
#endif
	}
	len -= mp_nlri->nexthop_len;

	/* Skip over SNPAs */
	mstream_getc(s, &num_snpa);
	len--;

	if(num_snpa) {
		syslog(LOG_WARNING, "process_mp_announce: MP_NLRI contains SNPAs, skipped");

		while(num_snpa > 0) {
			snpa_len = mstream_getc(s, NULL);
			mstream_get(s, NULL, snpa_len);
			len -= snpa_len;
			num_snpa--;
		}
	}

	/* Read prefixes */
	mp_nlri->prefix_count = read_prefix_list(s, len, afi, &mp_nlri->nlri, incomplete);
}

void process_mp_withdraw(struct mstream *s, struct mp_info *info, int len, struct zebra_incomplete *incomplete) {
	u_int16_t afi;
	u_int8_t safi;
	struct mp_nlri *mp_nlri;

	mstream_getw(s, &afi);
	mstream_getc(s, &safi);
	len -= 3;

	/* Do we know about this address family? */
	if(afi > BGPDUMP_MAX_AFI || safi > BGPDUMP_MAX_SAFI) {
		syslog(LOG_WARNING, "process_mp_withdraw: unknown AFI,SAFI %d,%d!",
		       afi, safi);
		mstream_get(s, NULL, len);
		return;
	}

	/* If there are 2 NLRI's for the same protocol, fail but don't burn and die */
	if(info->withdraw[afi][safi] != NULL) {
		syslog(LOG_WARNING,
		       "process_mp_withdraw: update contains more than one MP_NLRI with AFI,SAFI %d,%d!",
		       afi, safi);
		mstream_get(s, NULL, len);
		return;
	}

	/* Allocate structure */
	mp_nlri = malloc(sizeof(struct mp_nlri));
	memset(mp_nlri, 0, sizeof(struct mp_nlri));
	info->withdraw[afi][safi] = mp_nlri;

	mp_nlri->prefix_count = read_prefix_list(s, len, afi, &mp_nlri->nlri, incomplete);
}

u_int16_t read_prefix_list(struct mstream *s, int len, u_int16_t afi,
                           struct prefix **prefixarray, struct zebra_incomplete *incomplete) {
	u_int8_t p_len;
	u_int8_t p_bytes;
	u_int16_t count = 0;
	struct prefix *prefixes = *prefixarray;

	if(afi > BGPDUMP_MAX_AFI) {
		syslog(LOG_WARNING, "read_prefix_list: unknown AFI %d", afi);
		mstream_get(s, NULL, len);
		*prefixarray = NULL;
		return 0;
	}

	while(len > 0 && mstream_can_read(s) > 0) {
		/* Prefix length in bits */
		p_len = mstream_getc(s,NULL); len--;
		/* In bytes */
		p_bytes = p_len / 8; if(p_len % 8 !=0) p_bytes++;

		/* Truncated prefix list? */
		if(mstream_can_read(s) < p_bytes) {
		    if(incomplete) {
			/* Put prefix in incomplete structure */
			memset(&incomplete->prefix, 0, sizeof(struct prefix));
			incomplete->afi = afi;
			incomplete->orig_len = p_len;
			incomplete->prefix.len = mstream_can_read(s) * 8;
			mstream_get(s, &incomplete->prefix.address, mstream_can_read(s));
		    } else {
			/* Just skip over it */
			mstream_get(s, NULL, mstream_can_read(s));
		    }
		    /* In either case, don't put it in the prefix array */
		    break;
		}

		/* Reallocate prefix array to add room for one more prefix*/
		prefixes = realloc(prefixes, (count+1) * sizeof(struct prefix));

		/* Fill new prefix with zeros, set prefix length */
		memset(&prefixes[count],0,sizeof(struct prefix));
		prefixes[count].len = p_len;

		/* Copy prefix */
		mstream_get(s, &prefixes[count].address, p_bytes);

		len = len - p_bytes;
		count++;
	}
	*prefixarray = prefixes;
	return count;
}

static as_t read_asn(struct mstream *s, as_t *asn, size_t len) {
	u_int16_t asn16;

	assert(len == sizeof(u_int32_t) || len == sizeof(u_int16_t));

	switch(len) {
		case sizeof(u_int32_t):
			return mstream_getl(s, asn);
		case sizeof(u_int16_t):
			mstream_getw(s, &asn16);
			if(asn)
				*asn = asn16;
			return asn16;
		default:
			syslog(LOG_ERR, "read_asn: wrong ASN length %d!", len);
			mstream_get(s, NULL, len);
			return -1;
	}
}

static char *print_asn(as_t asn) {
	static char asn_str[strlen("65535:65535") + 1];
	if(asn >> 16) {
		sprintf(asn_str, "%d.%d", (asn >> 16) & 0xFFFF, asn & 0xFFFF);
	} else {
		sprintf(asn_str, "%d", asn);
	}
	return asn_str;
}

#if defined(linux)
size_t strlcat(char *dst, const char *src, size_t size) {
  if (strlen (dst) + strlen (src) >= size)
    return -1;

  strcat (dst, src);

  return (strlen(dst));
}
#endif
