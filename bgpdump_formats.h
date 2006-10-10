/* $Id$ */
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
Filename          : bgpdump_formats.h
Author            : Dan Ardelean (dan@ripe.net)
Date              : 02-SEP-2002
Revision          : 
Revised           : 
Description       : Basic BGP dump structures/declarations
Language Version  : C
OSs Tested        : Linux 2.2.19
To Do             : 
-------------------------------------------------------------------------------
*/

#ifndef _BGPDUMP_FORMATS_H
#define _BGPDUMP_FORMATS_H

#include "bgpdump.h"
#include "bgpdump_attr.h"

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>

/* type and subtypes values */
#define BGPDUMP_TYPE_MRTD_BGP			5
#define BGPDUMP_SUBTYPE_MRTD_BGP_NULL		0
#define BGPDUMP_SUBTYPE_MRTD_BGP_PREFUPDATE	1
#define BGPDUMP_SUBTYPE_MRTD_BGP_UPDATE		2
#define BGPDUMP_SUBTYPE_MRTD_BGP_STATE_CHANGE	3
#define BGPDUMP_SUBTYPE_MRTD_BGP_SYNC		4
#define BGPDUMP_SUBTYPE_MRTD_BGP_OPEN		129
#define BGPDUMP_SUBTYPE_MRTD_BGP_NOTIFICATION	131
#define BGPDUMP_SUBTYPE_MRTD_BGP_KEEPALIVE	132
#define BGPDUMP_SUBTYPE_MRTD_BGP_ROUT_REFRESH	133

#define BGPDUMP_TYPE_MRTD_TABLE_DUMP		12
#define BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP	1
#define BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6	2

/* Zebra record types */
#define BGPDUMP_TYPE_ZEBRA_BGP			16 /* MSG_PROTOCOL_BGP4MP */
#define BGPDUMP_SUBTYPE_ZEBRA_BGP_STATE_CHANGE	0  /* BGP4MP_STATE_CHANGE */
#define BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE	1  /* BGP4MP_MESSAGE */
#define BGPDUMP_SUBTYPE_ZEBRA_BGP_ENTRY		2  /* BGP4MP_ENTRY */
#define BGPDUMP_SUBTYPE_ZEBRA_BGP_SNAPSHOT	3  /* BGP4MP_SNAPSHOT */
#define BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE32	4  /* BGP4MP_MESSAGE_32BIT_AS */

/* BGP state - defined in RFC1771 */
#define BGP_STATE_IDLE		1
#define BGP_STATE_CONNECT	2
#define BGP_STATE_ACTIVE	3
#define BGP_STATE_OPENSENT	4
#define BGP_STATE_OPENCONFIRM	5
#define BGP_STATE_ESTABLISHED	6

/* BGP message types */
#define	BGP_MSG_OPEN		           1
#define	BGP_MSG_UPDATE		           2
#define	BGP_MSG_NOTIFY		           3
#define	BGP_MSG_KEEPALIVE	           4
#define BGP_MSG_ROUTE_REFRESH_01           5
#define BGP_MSG_ROUTE_REFRESH	         128

struct prefix {
    BGPDUMP_IP_ADDRESS	address;
    u_char		len;
};

typedef struct struct_BGPDUMP_MRTD_MESSAGE {
    u_int16_t		source_as;
    struct in_addr	source_ip;
    u_int16_t		destination_as;
    struct in_addr	destination_ip;
    u_char		*bgp_message;
} BGPDUMP_MRTD_MESSAGE;

typedef struct struct_BGPDUMP_MRTD_TABLE_DUMP {
    u_int16_t		view;
    u_int16_t		sequence;
    BGPDUMP_IP_ADDRESS	prefix;
    u_char		mask;
    u_char		status;
    time_t		uptime;
    BGPDUMP_IP_ADDRESS	peer_ip;
    as_t		peer_as;
    u_int16_t		attr_len;
} BGPDUMP_MRTD_TABLE_DUMP;

/* For Zebra BGP4MP_STATE_CHANGE */
typedef struct struct_BGPDUMP_ZEBRA_STATE_CHANGE {
    as_t		source_as;
    as_t		destination_as;
    u_int16_t		interface_index;
    u_int16_t		address_family;
    BGPDUMP_IP_ADDRESS	source_ip;
    BGPDUMP_IP_ADDRESS	destination_ip;
    u_int16_t		old_state;
    u_int16_t		new_state;
} BGPDUMP_ZEBRA_STATE_CHANGE;

struct zebra_incomplete {
    u_int16_t afi;
    u_int8_t orig_len;
    struct prefix prefix;
};

/* For Zebra BGP4MP_MESSAGE */
typedef struct struct_BGPDUMP_ZEBRA_MESSAGE {
    /* Zebra header */
    as_t		source_as;
    as_t		destination_as;
    u_int16_t		interface_index;
    u_int16_t		address_family;
    BGPDUMP_IP_ADDRESS	source_ip;
    BGPDUMP_IP_ADDRESS	destination_ip;

    /* Does this message use 16-bit or 32-bit AS numbers? */
    size_t		asn_len;

    /* BGP packet header fields */
    u_int16_t		size;
    u_char		type;

    /* For OPEN packets */
    u_char	version;
    u_int16_t	my_as;
    u_int16_t	hold_time;
    struct	in_addr bgp_id;
    u_char	opt_len;
    u_char	*opt_data;

    /* For UPDATE packets */
    u_int16_t		withdraw_count;
    u_int16_t		announce_count;
    struct prefix	*withdraw;
    struct prefix	*announce;

    /* For corrupt update dumps */
    u_int16_t cut_bytes;
    struct zebra_incomplete incomplete;

    /* For NOTIFY packets */
    u_char error_code;
    u_char sub_error_code;
    u_int16_t notify_len;
    u_char *notify_data;

} BGPDUMP_ZEBRA_MESSAGE;

/* For Zebra BGP4MP_ENTRY */
typedef struct struct_BGPDUMP_ZEBRA_ENTRY {
    u_int16_t	view;
    u_int16_t	status;
    time_t	time_last_change;
    u_int16_t	address_family;
    u_char	SAFI;
    u_char	next_hop_len;
    u_char	prefix_length;
    u_char	*address_prefix;
    u_int16_t	attribute_length;
    u_int16_t	empty;
    u_char	*bgp_atribute;
} BGPDUMP_ZEBRA_ENTRY;

/* For Zebra BGP4MP_SNAPSHOT */
typedef struct struct_BGPDUMP_ZEBRA_SNAPSHOT {
    u_int16_t	view;
    u_int16_t	file;
} BGPDUMP_ZEBRA_SNAPSHOT;

typedef union union_BGPDUMP_BODY {
	BGPDUMP_MRTD_MESSAGE		mrtd_message;
	BGPDUMP_MRTD_TABLE_DUMP		mrtd_table_dump;
	BGPDUMP_ZEBRA_STATE_CHANGE	zebra_state_change;
	BGPDUMP_ZEBRA_MESSAGE		zebra_message;
	BGPDUMP_ZEBRA_ENTRY		zebra_entry;
	BGPDUMP_ZEBRA_SNAPSHOT		zebra_snapshot;
} BGPDUMP_BODY;

/* The MRT header. Common to all records. */
typedef struct struct_BGPDUMP_ENTRY {
    time_t		time;
    u_int16_t		type;
    u_int16_t		subtype;
    u_int32_t		length;
    struct attr		*attr;
    BGPDUMP_BODY 	body;
} BGPDUMP_ENTRY;

#endif
