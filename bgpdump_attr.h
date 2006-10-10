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
Filename          : bgdump_attr.h
Author            : Dan Ardelean (dan@ripe.net)
Date              : 02-SEP-2002
Revision          : 
Revised           : 
Description       : BGP attributes header file
Language Version  : C
OSs Tested        : Linux 2.2.19
To Do             : 
-------------------------------------------------------------------------------
*/

#ifndef _BGPDUMP_ATTR_H
#define _BGPDUMP_ATTR_H

#include "bgpdump.h"

/* BGP Attribute flags. */
#define BGP_ATTR_FLAG_OPTIONAL  0x80	/* Attribute is optional. */
#define BGP_ATTR_FLAG_TRANS     0x40	/* Attribute is transitive. */
#define BGP_ATTR_FLAG_PARTIAL   0x20	/* Attribute is partial. */
#define BGP_ATTR_FLAG_EXTLEN    0x10	/* Extended length flag. */

/* BGP attribute type codes.  */
#define BGP_ATTR_ORIGIN                    1
#define BGP_ATTR_AS_PATH                   2
#define BGP_ATTR_NEXT_HOP                  3
#define BGP_ATTR_MULTI_EXIT_DISC           4
#define BGP_ATTR_LOCAL_PREF                5
#define BGP_ATTR_ATOMIC_AGGREGATE          6
#define BGP_ATTR_AGGREGATOR                7
#define BGP_ATTR_COMMUNITIES               8
#define BGP_ATTR_ORIGINATOR_ID             9
#define BGP_ATTR_CLUSTER_LIST             10
#define BGP_ATTR_DPA                      11
#define BGP_ATTR_ADVERTISER               12
#define BGP_ATTR_RCID_PATH                13
#define BGP_ATTR_MP_REACH_NLRI            14
#define BGP_ATTR_MP_UNREACH_NLRI          15
#define BGP_ATTR_EXT_COMMUNITIES          16

/* Flag macro */
#define ATTR_FLAG_BIT(X)  (1 << ((X) - 1))

/* BGP ASPATH attribute defines */
#define AS_HEADER_SIZE        2	 

#define AS_SET             1
#define AS_SEQUENCE        2
#define AS_CONFED_SEQUENCE 3
#define AS_CONFED_SET      4

#define AS_SEG_START 0
#define AS_SEG_END 1

#define ASPATH_STR_DEFAULT_LEN 32
#define ASPATH_STR_ERROR       "! Error !"

/* BGP COMMUNITY attribute defines */

#define COMMUNITY_NO_EXPORT             0xFFFFFF01
#define COMMUNITY_NO_ADVERTISE          0xFFFFFF02
#define COMMUNITY_NO_EXPORT_SUBCONFED   0xFFFFFF03
#define COMMUNITY_LOCAL_AS              0xFFFFFF03

#define com_nthval(X,n)  ((X)->val + (n))

/* MP-BGP address families */
#ifdef BGPDUMP_HAVE_IPV6
#define AFI_IP 1
#define AFI_IP6 2
#define BGPDUMP_MAX_AFI AFI_IP6
#else
#define AFI_IP 1
#define BGPDUMP_MAX_AFI AFI_IP
#endif

#define SAFI_UNICAST		1
#define SAFI_MULTICAST		2
#define SAFI_UNICAST_MULTICAST	3
#define BGPDUMP_MAX_SAFI SAFI_UNICAST_MULTICAST

struct unknown_attr
{
	u_int16_t	real_len;
	u_int8_t	flag;
	u_int8_t	type;
	u_int16_t	len;
	u_char *	raw;
};

struct attr
{
  /* Reference count of this attribute. */
  unsigned long refcnt;

  /* Flag of attribute is set or not. */
  u_int32_t flag;

  /* Attributes. */
  u_char 		origin;
  struct in_addr 	nexthop;
  u_int32_t 		med;
  u_int32_t 		local_pref;
  as_t 			aggregator_as;
  struct in_addr 	aggregator_addr;
  u_int32_t 		weight;
  struct in_addr 	originator_id;
  struct cluster_list	*cluster;

  struct aspath 	*aspath;
  struct community 	*community;
  struct ecommunity 	*ecommunity;
  struct transit 	*transit;
  
  /* libbgpdump additions */
  
  struct mp_info	*mp_info;
  u_int16_t		len;
  caddr_t		data;

  u_int16_t		unknown_num;
  struct unknown_attr	*unknown;

  struct aspath 	*new_aspath;
  as_t			new_aggregator_as;
};

struct community 
{
  unsigned long 	refcnt;
  int 			size;
  u_int32_t 		*val;
  char			*str;
};

struct cluster_list
{
  unsigned long		refcnt;
  int			length;
  struct in_addr 	*list;
};

struct transit
{
  unsigned long 	refcnt;
  int 			length;
  u_char 		*val;
};

struct aspath 
{
  unsigned long 	refcnt;
  int 			length;
  int 			count;
  caddr_t 		data;
  char 			*str;
};

struct assegment
{
  u_char type;
  u_char length;
  char data[0];
};

struct mp_info {
  /* AFI and SAFI start from 1, so the arrays must be 1-based */
  struct mp_nlri	*withdraw[BGPDUMP_MAX_AFI+1][BGPDUMP_MAX_SAFI+1];
  struct mp_nlri	*announce[BGPDUMP_MAX_AFI+1][BGPDUMP_MAX_SAFI+1];
};

#ifdef BGPDUMP_HAVE_IPV6
#define MP_IPV6_ANNOUNCE(m) ((m)->announce[AFI_IP6][SAFI_UNICAST])
#define MP_IPV6_WITHDRAW(m) ((m)->withdraw[AFI_IP6][SAFI_UNICAST])
#endif

struct mp_nlri {
  u_char		nexthop_len;

  BGPDUMP_IP_ADDRESS	nexthop;
  BGPDUMP_IP_ADDRESS 	nexthop_local;

  u_int16_t		prefix_count;
  struct prefix		*nlri;
};

#endif /* _BGPDUMP_ATTR_H */