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

Original Author: Dan Ardelean (dan@ripe.net)
*/

#ifndef _BGPDUMP_LIB_H
#define _BGPDUMP_LIB_H

#include <stdio.h>

#define BGPDUMP_HAVE_IPV6

#include "bgpdump_attr.h"
#include "bgpdump_formats.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BGPDUMP_MAX_FILE_LEN	1024
#define BGPDUMP_MAX_AS_PATH_LEN	2000

// if you include cfile_tools.h, include it first
#ifndef _CFILE_TOOLS_DEFINES
typedef struct _CFRFILE CFRFILE;
#endif

typedef struct struct_BGPDUMP {
    CFRFILE	*f;
    int		f_type;
    int		eof;
    char	filename[BGPDUMP_MAX_FILE_LEN];
    int		parsed;
    int		parsed_ok;
    BGPDUMP_TABLE_DUMP_V2_PEER_INDEX_TABLE *table_dump_v2_peer_index_table;
} BGPDUMP;

/* prototypes */

BGPDUMP *bgpdump_open_dump(const char *filename);
void	bgpdump_close_dump(BGPDUMP *dump);
BGPDUMP_ENTRY*	bgpdump_read_next(BGPDUMP *dump);
void	bgpdump_free_mem(BGPDUMP_ENTRY *entry);
char    *bgpdump_version(void);
int     is_addpath(BGPDUMP_ENTRY *entry);

#ifdef __cplusplus
}
#endif

#endif
