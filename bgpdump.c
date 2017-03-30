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

Original Author: Shufu Mao(msf98@mails.tsinghua.edu.cn) 
*/

#include "bgpdump-config.h"
#include "bgpdump_lib.h"
#include "util.h"

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>

static void process(BGPDUMP_ENTRY *entry);
static void process_bgpdump_mrtd_bgp(BGPDUMP_ENTRY *entry);
static void show_ipv4_address(struct in_addr ip);
static void show_attr(attributes_t *attr);
static void show_prefixes(int count,struct prefix *prefix, int addpath);
static void table_line_announce_1(struct mp_nlri *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
static void table_line_announce(struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
static void mrtd_table_line_withdraw(struct prefix *prefix, int count, BGPDUMP_ENTRY *entry, char *time_str);
static void mrtd_table_line_announce(struct prefix *prefix, int count, BGPDUMP_ENTRY *entry, char *time_str);
static void table_line_withdraw(struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
static void table_line_mrtd_route(BGPDUMP_MRTD_TABLE_DUMP *route,BGPDUMP_ENTRY *entry);
static void table_line_dump_v2_prefix(BGPDUMP_TABLE_DUMP_V2_PREFIX *e,BGPDUMP_ENTRY *entry);
static char *describe_origin(int origin);
static int  bgp4mp_message_direction_receive(BGPDUMP_ENTRY *entry);

#ifdef BGPDUMP_HAVE_IPV6
    void show_prefixes6(int count,struct prefix *prefix, int addpath);
    static void table_line_withdraw6(struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
    static void table_line_announce6(struct mp_nlri *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
#endif

static void show_line_prefix(const char* format, const char* time_str, const char* type);

/* If no aspath was present as a string in the packet, return an empty string
 * so everything stays machine parsable */
static char *attr_aspath(attributes_t *a) {
    if(a->flag & ATTR_FLAG_BIT(BGP_ATTR_AS_PATH) && a->aspath && a->aspath->str) {
        return a->aspath->str;
    }
    return "";
}

/* Helper function to return the direction of a BGP4MP_MESSAGE
 * returns true if it is a received message, false if it is a sent message */
static int bgp4mp_message_direction_receive(BGPDUMP_ENTRY *entry) {
	switch(entry->subtype) {
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_LOCAL:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_AS4_LOCAL:
			return 0;
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_AS4:
		default:
			return 1;
	}
}

/* Helper function that returns the format of a BGP4MP_MESSAGE as a string:
 - BGP4MP (Standard)
 - BGP4MP_ET (Extended Header)
 - BGP4MP_LOCAL (Local)
 - BGP4MP_ET_LOCAL (Local and Extended Header)
 - BGP4MP_AP (Standard, Additional Paths)
 - BGP4MP_ET_AP (Extended Header, Additional Paths)
 - BGP4MP_LOCAL_AP (Local, Additional Paths)
 - BGP4MP_ET_LOCAL_AP (Local, Extended Header, Additional Paths)
 */
static const char* get_bgp4mp_format(BGPDUMP_ENTRY *entry) {
    if (entry->type == BGPDUMP_TYPE_ZEBRA_BGP_ET && !bgp4mp_message_direction_receive(entry)) {
        if (is_addpath(entry)) {
            return "BGP4MP_ET_LOCAL_AP";
        } else {
            return "BGP4MP_ET_LOCAL";
        }
    } else if (entry->type == BGPDUMP_TYPE_ZEBRA_BGP_ET) {
        if (is_addpath(entry)) {
            return "BGP4MP_ET_AP";
        } else {
            return "BGP4MP_ET";
        }
    } else if (!bgp4mp_message_direction_receive(entry)) {
        if (is_addpath(entry)) {
            return "BGP4MP_LOCAL_AP";
        } else {
            return "BGP4MP_LOCAL";
        }
    } else if (is_addpath(entry)) {
        return "BGP4MP_AP";
    } else {
        return "BGP4MP";
    }
}

static const char* get_bgp_state_name(u_int16_t state) {

    const char *bgp_state_name[] = {
        "Unknown",
        "Idle",
        "Connect",
        "Active",
        "Opensent",
        "Openconfirm",
        "Established",
        /* not defined in RFC 6396 but quagga puts them into update files */
        "Clearing",
        "Deleted",
        NULL
    };

    if (state && state >= (sizeof(bgp_state_name)) / (sizeof(*bgp_state_name))) {
        return "Unknown";
    } else {
        return bgp_state_name[state];
    }
}

static int mode=0;
static int timetype=0;
static int show_packet_index = 0;
static int show_large_comms = 0;
static int packet_index = 0;

static const char USAGE[] = "\
bgpdump version " PACKAGE_VERSION "\n\
Usage: bgpdump [-m|-M] [-t dump|-t change] [-O <output-file>] <input-file>\n\
bgpdump translates binary MRT files (possibly compressed) into readable output\n\
Output mode:\n\
    -H         multi-line, human-readable (the default)\n\
    -m         one-line per entry with unix timestamps\n\
    -M         one-line per entry with human readable timestamps\n\
    (there are other differences between -m and -M)\n\
\n\
Common options:\n\
    -O <file>  output to <file> instead of STDOUT\n\
    -s         log to syslog (the default)\n\
    -v         log to STDERR\n\
    -q         quiet\n\
\n\
Options for -m and -M modes:\n\
    -t dump    timestamps for RIB dumps reflect the time of the dump (the default)\n\
    -t change  timestamps for RIB dumps reflect the last route modification\n\
    -p         show packet index at second position\n\
    -l         show large communities field after regular communities\n\
\n\
Special options:\n\
    -T         run unit tests and exit\n\
\n";

extern char *optarg;
extern int optind;

int main(int argc, char *argv[]) {
    
    int c;
    int fd;
    bool usage_error = false;
    bool use_syslog = true;
    bool quiet = false;
 
    log_to_stderr();
    
    while ((c=getopt(argc,argv,"if:o:t:mMHO:svTplq"))!=-1)
	switch(c)
	{
       case 'H':
                mode=0;
                break;
	case 'm':
                mode=1;
                break;
	case 'M':
                mode=2;
                break;
	case 't':
                if(strcmp(optarg,"dump")==0){
                    timetype=0;
                } else if(strcmp(optarg,"change")==0){
                    timetype=1;
                } else {
                    printf("unknown -t option\n");
                    exit(1);
                }
                break;
        case 'O':
                fprintf(stderr, "redirecting output to '%s'\n", optarg); 
                fd = open(optarg, O_WRONLY|O_CREAT, 0666);
                if(fd < 0 || 0 > dup2(fd, STDOUT_FILENO)) {
                        perror("can't open output file");
                        exit(1);
                }
                break;
        case 's':
                use_syslog = true;
                break;
        case 'v':
                use_syslog = false;
                break;
        case 'i':
        case 'f':
        case 'o':
                warn("ignoring option '-%c'", c);
                break;
        case 'T':
                test_fmt_ip();
                test_utils();
                exit(0);
        case 'p':
                show_packet_index = 1;
                break;
        case 'l':
                show_large_comms = 1;
                break;
        case 'q':
                quiet = true;
                break;

        case '?':
        default:
                usage_error = true;
	}
    argc -= optind;
    argv += optind;
    
    if(use_syslog) {
        if(!quiet)
            debug("logging to syslog");
        log_to_syslog();
    }
    
    if(usage_error || argc != 1) {
        if(argc != 1)
            err("you must supply exactly one file to process");
        fprintf(stderr, "%s", USAGE);
        exit(1);        
    }

    // more efficient then line buffering
    //    static char buffer[16000];
    //    setbuffer(stdout, buffer, sizeof buffer);
    
    BGPDUMP *my_dump = bgpdump_open_dump(argv[0]);
    if(! my_dump)
        return 1;
    
    do {
        BGPDUMP_ENTRY *my_entry = bgpdump_read_next(my_dump);
	if(my_entry) {
	    process(my_entry);
	    bgpdump_free_mem(my_entry);
            packet_index++;
	}
    } while(my_dump->eof==0);

    bgpdump_close_dump(my_dump);
    
    return 0;
}

void process(BGPDUMP_ENTRY *entry) {

	struct tm *date;
	char time_str[128];
	char time_str2[128];
	char time_str_fixed[128];
    char prefix[BGPDUMP_ADDRSTRLEN];
    char *bgp4mp_format;
    char *bgp4mp_subtype_format;
    int len;
	
	date=gmtime(&entry->time);
	time2str(date,time_str_fixed);
    
    if (mode == 1) {
        // Timestamp mode
        len = sprintf(time_str, "%lld", (long long)entry->time);
    } else {
        len = time2str(date,time_str);
    }
    // Appending microseconds to time_str if needed
    if (entry->type == BGPDUMP_TYPE_ZEBRA_BGP_ET) {
        sprintf(time_str + len, ".%06ld", entry->ms);
    }
    
	if (mode==0)
	{
		printf("TIME: %s\n", time_str);
	}	
    //printf("TIME: %s",asctime(gmtime(&entry->time)));
    //printf("LENGTH          : %u\n", entry->length);
    switch(entry->type) {
	case BGPDUMP_TYPE_MRTD_TABLE_DUMP:
	     if(mode==0){
	        const char *prefix_str = NULL;
		switch(entry->subtype){
#ifdef BGPDUMP_HAVE_IPV6
	    	case BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6:
	    		printf("TYPE: TABLE_DUMP/INET6\n");
			prefix_str = fmt_ipv6(entry->body.mrtd_table_dump.prefix,prefix);
		break;

	    	case BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6_32BIT_AS:
	    		printf("TYPE: TABLE_DUMP/INET6_32BIT_AS\n");
			prefix_str = fmt_ipv6(entry->body.mrtd_table_dump.prefix,prefix);
		break;

#endif
		case BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP:
			printf("TYPE: TABLE_DUMP/INET\n");
			prefix_str = inet_ntoa(entry->body.mrtd_table_dump.prefix.v4_addr);
		break;

		case BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP_32BIT_AS:
			printf("TYPE: TABLE_DUMP/INET_32BIT_AS\n");
			prefix_str = inet_ntoa(entry->body.mrtd_table_dump.prefix.v4_addr);
		break;

		default:
			printf("Error: unknown table type %d\n", entry->subtype);
		return;

		}
		printf("VIEW: %d\n",entry->body.mrtd_table_dump.view);
	    	printf("SEQUENCE: %d\n",entry->body.mrtd_table_dump.sequence);
	    	printf("PREFIX: %s/%d\n",prefix_str,entry->body.mrtd_table_dump.mask);
	    	printf("FROM:");
		switch(entry->subtype)
		{
#ifdef BGPDUMP_HAVE_IPV6
		case BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6:
		case BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6_32BIT_AS:

			fmt_ipv6(entry->body.mrtd_table_dump.peer_ip,prefix);
			printf("%s ",prefix);
			break;
#endif
		case BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP:
		case BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP_32BIT_AS:
			if (entry->body.mrtd_table_dump.peer_ip.v4_addr.s_addr != 0x00000000L)
		    		printf("%s ",inet_ntoa(entry->body.mrtd_table_dump.peer_ip.v4_addr));
			else
				printf("N/A ");

		}
		printf("AS%u\n",entry->body.mrtd_table_dump.peer_as);

		//printf("FROM: %s AS%d\n",inet_ntoa(entry->body.mrtd_table_dump.peer_ip.v4_addr),entry->body.mrtd_table_dump.peer_as);
	 	//time2str(localtime(&entry->body.mrtd_table_dump.uptime),time_str2);
		time2str(gmtime(&entry->body.mrtd_table_dump.uptime),time_str2);
		printf("ORIGINATED: %s\n",time_str2); 	
		if (entry->attr && entry->attr->len)
				    	show_attr(entry->attr);

		printf("STATUS: 0x%x\n",entry->body.mrtd_table_dump.status);
	    
		
		//printf("    UPTIME      : %s",asctime(gmtime(&entry->body.mrtd_table_dump.uptime)));
	    //printf("    PEER IP     : %s\n",inet_ntoa(entry->body.mrtd_table_dump.peer_ip));
	    //printf("    PEER IP     : %s\n",inet_ntoa(entry->body.mrtd_table_dump.peer_ip.v4_addr));
	    //printf("    PEER AS     : %d\n",entry->body.mrtd_table_dump.peer_as);
	     }
	     else if (mode ==1 || mode ==2) // -m -M
	     {
	        table_line_mrtd_route(&entry->body.mrtd_table_dump,entry);	     
	     }
	    break;

	case BGPDUMP_TYPE_TABLE_DUMP_V2:
		if(mode == 0){

			char peer_ip[BGPDUMP_ADDRSTRLEN];
			//char time_str[30];
			int i;
            int addpath = is_addpath(entry);

			BGPDUMP_TABLE_DUMP_V2_PREFIX *e;
			e = &entry->body.mrtd_table_dump_v2_prefix;

			if(e->afi == AFI_IP){
				strncpy(prefix, inet_ntoa(e->prefix.v4_addr), BGPDUMP_ADDRSTRLEN);
#ifdef BGPDUMP_HAVE_IPV6
			} else if(e->afi == AFI_IP6){
				fmt_ipv6(e->prefix, prefix);
#endif
			}

			for(i = 0; i < e->entry_count; i++){
				// This is slightly nasty - as we want to print multiple entries
				// for multiple peers, we may need to print another TIME ourselves
				if(i) printf("\nTIME: %s\n",time_str_fixed);
				if(e->afi == AFI_IP){
                    if (addpath)
    				    printf("TYPE: TABLE_DUMP_V2/IPV4_UNICAST_ADDPATH\n");
                    else  
    				    printf("TYPE: TABLE_DUMP_V2/IPV4_UNICAST\n");
#ifdef BGPDUMP_HAVE_IPV6
				} else if(e->afi == AFI_IP6){
                    if (addpath)
    				    printf("TYPE: TABLE_DUMP_V2/IPV6_UNICAST_ADDPATH\n");
                    else
    				    printf("TYPE: TABLE_DUMP_V2/IPV6_UNICAST\n");
#endif
				}
	    		printf("PREFIX: %s/%d",prefix, e->prefix_length);
                if (addpath)
                    printf(" PATH_ID: %u", e->entries[i].path_id);
                printf("\n");
    			printf("SEQUENCE: %d\n",e->seq);

				if(e->entries[i].peer->afi == AFI_IP){
					fmt_ipv4(e->entries[i].peer->peer_ip, peer_ip);
#ifdef BGPDUMP_HAVE_IPV6
				} else if (e->entries[i].peer->afi == AFI_IP6){
					fmt_ipv6(e->entries[i].peer->peer_ip, peer_ip);
#endif
				} else {
					sprintf(peer_ip, "[N/A, unsupported AF]");
				}
    			printf("FROM: %s AS%u\n", peer_ip, e->entries[i].peer->peer_as);
				time_t time_temp = (time_t)((e->entries[i]).originated_time);
				time2str(gmtime(&time_temp),time_str);
				printf("ORIGINATED: %s\n",time_str); 	
				if (e->entries[i].attr && e->entries[i].attr->len)
			    	show_attr(e->entries[i].attr);
			}
		} else if (mode==1 || mode==2) { // -m -M
                    table_line_dump_v2_prefix(&entry->body.mrtd_table_dump_v2_prefix,entry);	     
		}
	    break;

        case BGPDUMP_TYPE_MRTD_BGP:
            process_bgpdump_mrtd_bgp(entry);
            break;
	    
	case BGPDUMP_TYPE_ZEBRA_BGP:
    case BGPDUMP_TYPE_ZEBRA_BGP_ET:

        if (entry->type == BGPDUMP_TYPE_ZEBRA_BGP) {
            bgp4mp_format = "BGP4MP";
        } else {
            bgp4mp_format = "BGP4MP_ET";
        }

        int addpath = is_addpath(entry);
	    
	    switch(entry->subtype) 
	    {
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_AS4:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_LOCAL:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_AS4_LOCAL:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_ADDPATH:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_AS4_ADDPATH:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_LOCAL_ADDPATH:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE_AS4_LOCAL_ADDPATH:

            if (addpath) {
                if (bgp4mp_message_direction_receive(entry))
                    bgp4mp_subtype_format = "MESSAGE_ADDPATH";
                else
                    bgp4mp_subtype_format = "MESSAGE_LOCAL_ADDPATH";
            } else {
                if (bgp4mp_message_direction_receive(entry))
                    bgp4mp_subtype_format = "MESSAGE";
                else
                    bgp4mp_subtype_format = "MESSAGE_LOCAL";
            }


		    switch(entry->body.zebra_message.type) 
		    {
			case BGP_MSG_UPDATE:
			   if (mode ==0)
		    	   {

                printf("TYPE: %s/%s/Update\n", bgp4mp_format, bgp4mp_subtype_format);

				if (entry->body.zebra_message.source_as)
			        {
					printf("FROM:");
					switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							fmt_ipv6(entry->body.zebra_message.source_ip,prefix);
							printf(" %s ",prefix);
							break;
#endif
						case AFI_IP:
						default:
							if (entry->body.zebra_message.source_ip.v4_addr.s_addr != 0x00000000L)
		    						printf(" %s ",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr));
							else
								printf(" N/A ");
					}
					printf("AS%u\n",entry->body.zebra_message.source_as);
                                }
				if (entry->body.zebra_message.destination_as)
				{
					printf("TO:");
					switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							fmt_ipv6(entry->body.zebra_message.destination_ip,prefix);
							printf(" %s ",prefix);
							break;
#endif
						case AFI_IP:
						default:
							if (entry->body.zebra_message.destination_ip.v4_addr.s_addr != 0x00000000L)
		    						printf(" %s ",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr));
							else
								printf(" N/A ");
					}	
		    			printf("AS%u\n",entry->body.zebra_message.destination_as);
				}
				if (entry->attr && entry->attr->len)
				    	show_attr(entry->attr);
				if (entry->body.zebra_message.cut_bytes)
				{
					u_int16_t cutted,idx;
					u_int8_t buf[128];
					
					printf("   INCOMPLETE PACKET: %d bytes cutted\n",entry->body.zebra_message.cut_bytes);
					printf("   INCOMPLETE PART: ");
					if (entry->body.zebra_message.incomplete.orig_len)
					{
					 	cutted=entry->body.zebra_message.incomplete.prefix.len/8+1;
						buf[0]=entry->body.zebra_message.incomplete.orig_len;
						memcpy(buf+1,&entry->body.zebra_message.incomplete.prefix.address,cutted-1);
						
						for (idx=0;idx<cutted;idx++)
						{
							if (buf[idx]<0x10)
								printf("0%x ",buf[idx]);
							else
								printf("%x ",buf[idx]);
						}
					}
					printf("\n");
				}
                               if(! entry->attr)
                                   return;
				if ((entry->body.zebra_message.withdraw_count) || (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI))) 
				{
#ifdef BGPDUMP_HAVE_IPV6
					if ((entry->body.zebra_message.withdraw_count)||(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count) ||(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count) )

#else
					if ((entry->body.zebra_message.withdraw_count)||(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count))

#endif				
						printf("WITHDRAW\n");
					if (entry->body.zebra_message.withdraw_count)
                        
                            // old style
			    			show_prefixes(entry->body.zebra_message.withdraw_count,entry->body.zebra_message.withdraw, addpath);

                            // MP
                                        if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count)
                                                show_prefixes(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->nlri, addpath);
                                
                                        if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count)
                                                show_prefixes(entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->nlri, addpath);

                                        if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count)
                                                show_prefixes(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->nlri, addpath);

#ifdef BGPDUMP_HAVE_IPV6
                                        if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count)
                                                show_prefixes6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->nlri, addpath);
                                
                                        if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count)
                                                show_prefixes6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->nlri, addpath);

                                        if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count)
                                                show_prefixes6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->nlri, addpath);
#endif
				}
				if ( (entry->body.zebra_message.announce_count) || (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI))) 
				{
					printf("ANNOUNCE\n");
			    		if (entry->body.zebra_message.announce_count)
                            
                            // old style
			    			show_prefixes(entry->body.zebra_message.announce_count,entry->body.zebra_message.announce, addpath);

                            // MP
                                        if (entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->prefix_count)
                                                show_prefixes(entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nlri, addpath);
                                
                                        if (entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->prefix_count)
                                                show_prefixes(entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nlri, addpath);

                                        if (entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count)
                                                show_prefixes(entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nlri, addpath);

#ifdef BGPDUMP_HAVE_IPV6
                                        if (entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->prefix_count)
                                                show_prefixes6(entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nlri, addpath);
                                
                                        if (entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->prefix_count)
                                                show_prefixes6(entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nlri, addpath);

                                        if (entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count)
                                                show_prefixes6(entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nlri, addpath);
#endif					
				}
			   }
			   else if (mode == 1  || mode == 2) //-m -M
			   {
				if ((entry->body.zebra_message.withdraw_count) || (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI)))
				{

                    // old style
					table_line_withdraw(entry->body.zebra_message.withdraw,entry->body.zebra_message.withdraw_count,entry,time_str);
                    
                    // MP
                                        if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count)
                                                table_line_withdraw(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count,entry,time_str);	

                                        if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count)
                                                table_line_withdraw(entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count,entry,time_str);
                                        
                                        if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count)
                                                table_line_withdraw(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count,entry,time_str);

#ifdef BGPDUMP_HAVE_IPV6						
                                        if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count)
                                                table_line_withdraw6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count,entry,time_str);	
                                        
                                        if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count)
                                                table_line_withdraw6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count,entry,time_str);
                                        
                                        if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count)
                                                table_line_withdraw6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count,entry,time_str);
#endif	
                        
				}
				if ( (entry->body.zebra_message.announce_count) || (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)))
				{
                    // old style
					table_line_announce(entry->body.zebra_message.announce,entry->body.zebra_message.announce_count,entry,time_str);

                    // MP
                                        if (entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->prefix_count)
                                                table_line_announce_1(entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST],entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->prefix_count,entry,time_str);	
                                        if (entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->prefix_count)
                                                table_line_announce_1(entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST],entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->prefix_count,entry,time_str);
                                        if (entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count)
                                                table_line_announce_1(entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST],entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count,entry,time_str);
#ifdef BGPDUMP_HAVE_IPV6						
                                        if (entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->prefix_count)
                                                table_line_announce6(entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST],entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->prefix_count,entry,time_str);	
                                        if (entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->prefix_count)
                                                table_line_announce6(entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST],entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->prefix_count,entry,time_str);
                                        if (entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count)
                                                table_line_announce6(entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST],entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count,entry,time_str);
#endif
					
				}  
			   }
			   break;
		    
			case BGP_MSG_OPEN:
			    if (mode != 0)
				    break;

                printf("TYPE: %s/%s/Open\n", bgp4mp_format, bgp4mp_subtype_format);

			    if (entry->body.zebra_message.source_as)
			    {
				printf("FROM:");
				switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							fmt_ipv6(entry->body.zebra_message.source_ip,prefix);
							printf(" %s ",prefix);
							break;
#endif
						case AFI_IP:
						default:
							if (entry->body.zebra_message.source_ip.v4_addr.s_addr != 0x00000000L)
		    						printf(" %s ",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr));
							else
								printf(" N/A ");
					}
				printf("AS%u\n",entry->body.zebra_message.source_as);
			    }
			    if (entry->body.zebra_message.destination_as)
			    {
				printf("TO:");
				switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							fmt_ipv6(entry->body.zebra_message.destination_ip,prefix);
							printf(" %s ",prefix);
							break;
#endif
						case AFI_IP:
						default:
							if (entry->body.zebra_message.destination_ip.v4_addr.s_addr != 0x00000000L)
		    						printf(" %s ",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr));
							else
								printf(" N/A ");
					}
		    		printf("AS%u\n",entry->body.zebra_message.destination_as);
                            }

			    printf("VERSION: %d\n",entry->body.zebra_message.version);
			    printf("AS: %u\n",entry->body.zebra_message.my_as);
			    printf("HOLD_TIME: %d\n",entry->body.zebra_message.hold_time);
			    printf("ID: %s\n",inet_ntoa(entry->body.zebra_message.bgp_id));
			    printf("OPT_PARM_LEN: %d\n",entry->body.zebra_message.opt_len);
			    break;
			
			case BGP_MSG_NOTIFY:
			    if (mode != 0)
				    break;

                printf("TYPE: %s/%s/Notify\n", bgp4mp_format, bgp4mp_subtype_format);

			    if (entry->body.zebra_message.source_as)
			    {
				printf("FROM:");
				switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							fmt_ipv6(entry->body.zebra_message.source_ip,prefix);
							printf(" %s ",prefix);
							break;
#endif
						case AFI_IP:
						default:
							if (entry->body.zebra_message.source_ip.v4_addr.s_addr != 0x00000000L)
		    						printf(" %s ",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr));
							else
								printf(" N/A ");
					}
				printf("AS%u\n",entry->body.zebra_message.source_as);
	                    }
			    if (entry->body.zebra_message.destination_as)
		            {
				printf("TO:");
				switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							fmt_ipv6(entry->body.zebra_message.destination_ip,prefix);
							printf(" %s ",prefix);
							break;
#endif
						case AFI_IP:
						default:
							if (entry->body.zebra_message.destination_ip.v4_addr.s_addr != 0x00000000L)
		    						printf(" %s ",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr));
							else
								printf(" N/A ");
					}
		    		printf("AS%u\n",entry->body.zebra_message.destination_as);
                            }

		            switch (entry->body.zebra_message.error_code)
			    {
			    case 	1:
				    printf("    ERROR CODE  : 1 (Message Header Error)\n");
				    switch(entry->body.zebra_message.sub_error_code)
				    {
				    case	1:
					    printf("    SUB ERROR   : 1 (Connection Not Synchronized)\n");
					    break;
					    
				    case	2:
					    printf("    SUB ERROR   : 2 (Bad Message Length)\n");
					    break;

				    case	3:
					    printf("    SUB ERROR   : 3 (Bad Message Type)\n");
					    break;
					    
				    default:
					    printf("    SUB ERROR   : %d\n",entry->body.zebra_message.sub_error_code);
					    break;
			            }
				    break;
			    case	2:
                                    printf("    ERROR CODE  : 2 (OPEN Message Error)\n");
				    switch(entry->body.zebra_message.sub_error_code)
				    {
				    case	1:
					    printf("    SUB ERROR   : 1 (Unsupported Version Number)\n");
					    break;
					    
				    case	2:
					    printf("    SUB ERROR   : 2 (Bad Peer AS)\n");
					    break;

				    case	3:
					    printf("    SUB ERROR   : 3 (Bad BGP Identifier)\n");
					    break;
			           
				    case	4:
					    printf("    SUB ERROR   : 4 (Unsupported Optional Parameter)\n");
					    break;

				    case	5:
					    printf("    SUB ERROR   : 5 (Authentication Failure)\n");
					    break;

				    case	6:
					    printf("    SUB ERROR   : 6 (Unacceptable Hold Time)\n");
					    break;
					    
				    default:
					    printf("    SUB ERROR   : %d\n",entry->body.zebra_message.sub_error_code);
					    break;
			            }
				    break;
			    case	3:
				    printf("    ERROR CODE  : 3 (UPDATE Message Error)\n");
				    switch(entry->body.zebra_message.sub_error_code)
				    {
				    case	1:
					    printf("    SUB ERROR   : 1 (Malformed Attribute List)\n");
					    break;
					    
				    case	2:
					    printf("    SUB ERROR   : 2 (Unrecognized Well-known Attribute)\n");
					    break;

				    case	3:
					    printf("    SUB ERROR   : 3 (Missing Well-known Attribute)\n");
					    break;
			           
				    case	4:
					    printf("    SUB ERROR   : 4 (Attribute Flags Error)\n");
					    break;

				    case	5:
					    printf("    SUB ERROR   : 5 (Attribute Length Error)\n");
					    break;

				    case	6:
					    printf("    SUB ERROR   : 6 (Invalid ORIGIN Attribute)\n");
					    break;
				
				    case	7:
					    printf("    SUB ERROR   : 7 (AS Routing Loop)\n");
					    break;
					    
				    case	8:
					    printf("    SUB ERROR   : 8 (Invalid NEXT-HOP Attribute)\n");
					    break;

				    case	9:
					    printf("    SUB ERROR   : 9 (Optional Attribute Error)\n");
					    break;
			           
				    case	10:
					    printf("    SUB ERROR   : 10 (Invalid Network Field)\n");
					    break;

				    case	11:
					    printf("    SUB ERROR   : 11 (Malformed AS-PATH)\n");
					    break;
	    
				    default:
					    printf("    SUB ERROR   : %d\n",entry->body.zebra_message.sub_error_code);
					    break;
			            }
				    break;
			    case	4:
				    printf("    ERROR CODE  : 4 (Hold Timer Expired)\n");
				    break;
			    case	5:
				    printf("    ERROR CODE  : 5 (Finite State Machine Error)\n");
				    break;
			    case	6:
                                    printf("    ERROR CODE  : 6 (Cease)\n");
				    break;
			    default:
				    printf("    ERROR CODE  : %d\n",entry->body.zebra_message.error_code);	
				    break;
					    
			    }
			    break;
			    
			case BGP_MSG_KEEPALIVE:
			    	if ( mode != 0)
					break;

                printf("TYPE: %s/%s/Keepalive\n", bgp4mp_format, bgp4mp_subtype_format);

				if (entry->body.zebra_message.source_as)
				{
					printf("FROM:");
					switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							fmt_ipv6(entry->body.zebra_message.source_ip,prefix);
							printf(" %s ",prefix);
							break;
#endif
						case AFI_IP:
						default:
							if (entry->body.zebra_message.source_ip.v4_addr.s_addr != 0x00000000L)
		    						printf(" %s ",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr));
							else
								printf(" N/A ");
					}
					printf("AS%u\n",entry->body.zebra_message.source_as);
				}
				if (entry->body.zebra_message.destination_as)
				{
					printf("TO:");
					switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							fmt_ipv6(entry->body.zebra_message.destination_ip,prefix);
							printf(" %s ",prefix);
							break;
#endif
						case AFI_IP:
						default:
							if (entry->body.zebra_message.destination_ip.v4_addr.s_addr != 0x00000000L)
		    						printf(" %s ",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr));
							else
								printf(" N/A ");
					}
		    			printf("AS%u\n",entry->body.zebra_message.destination_as);
				}


			    	break;
		    }
		    break;

		case BGPDUMP_SUBTYPE_ZEBRA_BGP_STATE_CHANGE:
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_STATE_CHANGE_AS4:
		    if (mode==0)
		    {
		    	printf("TYPE: %s/STATE_CHANGE\n", bgp4mp_format);

		    	printf("PEER:");
			switch(entry->body.zebra_state_change.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:

				fmt_ipv6(entry->body.zebra_state_change.source_ip,prefix);
				printf(" %s ",prefix);
				break;
#endif
			case AFI_IP:
			default:
				if (entry->body.zebra_state_change.source_ip.v4_addr.s_addr != 0x00000000L)
		    			printf(" %s ",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr));
				else
					printf(" N/A ");
			}	
		    	//if (entry->body.zebra_message.source_ip.s_addr != 0x00000000L)
		    	//	printf(" %s ",inet_ntoa(entry->body.zebra_message.source_ip));
		    	//else
			//	printf(" N/A ");
		    	printf("AS%u\n",entry->body.zebra_state_change.source_as);

		    	printf("STATE: %s/%s\n",get_bgp_state_name(entry->body.zebra_state_change.old_state),get_bgp_state_name(entry->body.zebra_state_change.new_state));
		    }
		    else if (mode==1 || mode==2 ) //-m -M
		    {
			switch(entry->body.zebra_state_change.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
				case AFI_IP6:
                    fmt_ipv6(entry->body.zebra_state_change.source_ip, prefix);
					break;
#endif
				case AFI_IP:
				default:
                    sprintf(prefix, "%s", inet_ntoa(entry->body.zebra_state_change.source_ip.v4_addr));
					break;
			}
            show_line_prefix(bgp4mp_format, time_str, "STATE");
            printf("%s|%u|%d|%d\n", prefix,
                    entry->body.zebra_state_change.source_as,
                    entry->body.zebra_state_change.old_state,
                    entry->body.zebra_state_change.new_state);
                
		    }
		    break;
		
	    } 
	    break;
    }
    if (mode==0)
    	printf("\n");
}

// print line prefix with respect of mode and show_packet_index flags
// output will have format:
// format|[packet_index|]time|type|
void show_line_prefix(const char* format, const char* time_str, const char* type)
{
    printf("%s|", format);
    if (show_packet_index)
        printf("%d|", packet_index);
    
    printf("%s|%s|", time_str, type);
} 


void process_bgpdump_mrtd_bgp(BGPDUMP_ENTRY *entry) {
    struct tm *date;
    char time_str[128];
    date=gmtime(&entry->time);

    if (mode == 1) {
        sprintf(time_str, "%lld", (long long)entry->time);
    } else {
        
        time2str(date, time_str);
    }
    
    switch (entry->subtype) {
    case BGPDUMP_SUBTYPE_MRTD_BGP_UPDATE:
    case BGPDUMP_SUBTYPE_MRTD_BGP_KEEPALIVE:
        if (mode == 0) {
            if (entry->subtype == BGPDUMP_SUBTYPE_MRTD_BGP_UPDATE)
                printf("TYPE: BGP/MESSAGE/Update\n");
            else
                printf("TYPE: BGP/MESSAGE/Keepalive\n"); 
            if (entry->body.mrtd_message.source_as) {
                printf("FROM:");
                show_ipv4_address(entry->body.mrtd_message.source_ip);
                printf("AS%u\n", entry->body.mrtd_message.source_as);
            }
            if (entry->body.mrtd_message.destination_as) {
                printf("TO:");
                show_ipv4_address(entry->body.mrtd_message.destination_ip);
                printf("AS%u\n", entry->body.mrtd_message.destination_as);                
            }
            if (entry->attr && entry->attr->len)
                show_attr(entry->attr);
            if (entry->body.mrtd_message.withdraw_count) {
                printf("WITHDRAW\n");
                show_prefixes(entry->body.mrtd_message.withdraw_count, entry->body.mrtd_message.withdraw, 0);
            }
            if (entry->body.mrtd_message.announce_count) {
                printf("ANNOUNCE\n");
                show_prefixes(entry->body.mrtd_message.announce_count, entry->body.mrtd_message.announce, 0);
            }
        }
        else {
            if (entry->subtype != BGPDUMP_SUBTYPE_MRTD_BGP_UPDATE)
                break;
            if (entry->body.mrtd_message.withdraw_count)
                mrtd_table_line_withdraw(entry->body.mrtd_message.withdraw, entry->body.mrtd_message.withdraw_count,
                                         entry, time_str);
            if (entry->body.mrtd_message.announce_count)
                mrtd_table_line_announce(entry->body.mrtd_message.announce, entry->body.mrtd_message.announce_count,
                                         entry, time_str);
        }
        break;
    case BGPDUMP_SUBTYPE_MRTD_BGP_STATE_CHANGE:
        if (mode == 0) {
            printf("TYPE: BGP/STATE_CHANGE\n");
            printf("PEER:");
            show_ipv4_address(entry->body.mrtd_state_change.destination_ip);
            printf("AS%u\n", entry->body.mrtd_state_change.destination_as);
            printf("STATE: %s/%s\n", get_bgp_state_name(entry->body.mrtd_state_change.old_state),
                   get_bgp_state_name(entry->body.mrtd_state_change.new_state));
        }
        else if (mode == 1 || mode == 2) {
            show_line_prefix("BGP", time_str, "STATE");
            printf("%s|%u|%d|%d\n",
                   inet_ntoa(entry->body.mrtd_state_change.destination_ip),
                   entry->body.mrtd_state_change.destination_as,
                   entry->body.mrtd_state_change.old_state,
                   entry->body.mrtd_state_change.new_state);
        }
        break;
    default:
        if (mode == 0) {
            printf("TYPE: Subtype %d not supported yet\n", entry->subtype);
        }
    }
}


void mrtd_table_line_withdraw(struct prefix *prefix, int count, BGPDUMP_ENTRY *entry, char *time_str) {
    int i;

    for (i = 0; i < count; i++) {
        show_line_prefix("BGP", time_str, "W");
        printf("%s|%u|%s/%d\n", inet_ntoa(entry->body.mrtd_message.source_ip),
               entry->body.mrtd_message.source_as,
               inet_ntoa(prefix[i].address.v4_addr), prefix[i].len);
    }
}


void mrtd_table_line_announce(struct prefix *prefix, int count, BGPDUMP_ENTRY *entry, char *time_str) {
    int i, npref, nmed;
    char *aggregate = entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE) ? "AG" : "NAG";

    for (i = 0; i < count; i++) {
        show_line_prefix("BGP", time_str, "A");
        printf("%s|%u", inet_ntoa(entry->body.mrtd_message.source_ip),
               entry->body.mrtd_message.source_as);
        printf("|%s/%d|%s|%s", inet_ntoa(prefix[i].address.v4_addr), prefix[i].len,
               attr_aspath(entry->attr), describe_origin(entry->attr->origin));
        if (mode == 1) {
            npref = ((entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)) == 0) ? 0 : entry->attr->local_pref;
            nmed  = ((entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)) == 0) ? 0 : entry->attr->med;
            printf("|%s|%u|%u", inet_ntoa(entry->attr->nexthop), npref, nmed);

            if ((entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES)) != 0)
                printf("%s|%s|", entry->attr->community->str+1, aggregate);
            else
                printf("|%s|", aggregate);
				
            if (entry->attr->aggregator_addr.s_addr != -1)
                printf("%u %s|\n", entry->attr->aggregator_as, inet_ntoa(entry->attr->aggregator_addr));
            else
                printf("|\n");
        }
        else
            printf("\n");
    }
}



void show_ipv4_address(struct in_addr ip) {
    if (ip.s_addr != 0x00000000L)
        printf(" %s ", inet_ntoa(ip));
    else
        printf(" N/A ");
}


void show_attr(attributes_t *attr) {
    
    if(attr != NULL) {

	    if( (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGIN) ) !=0 )
	    {
		    switch (attr->origin)
		    {
	            case 0:
			    printf("ORIGIN: IGP\n");
			    break;
		    case 1:
			    printf("ORIGIN: EGP\n");
		 	    break;
	            case 2:
			    printf("ORIGIN: INCOMPLETE\n");
				    
		    }
		   
	    }

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AS_PATH) ) !=0)		
		    printf("ASPATH: %s\n",attr->aspath->str);

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP) ) !=0)		
		    printf("NEXT_HOP: %s\n",inet_ntoa(attr->nexthop));

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) !=0)	
		    printf("MULTI_EXIT_DISC: %u\n",attr->med);

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) !=0)		
		    printf("LOCAL_PREF: %u\n",attr->local_pref);

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE) ) !=0)	
		    printf("ATOMIC_AGGREGATE\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR) ) !=0)		
		    printf("AGGREGATOR: AS%u %s\n",attr->aggregator_as,inet_ntoa(attr->aggregator_addr));

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID) ) !=0)
			printf("ORIGINATOR_ID: %s\n",inet_ntoa(attr->originator_id));
	
	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST) ) !=0)
		{
			int cluster_index;

			printf("CLUSTER_LIST: ");

			for (cluster_index = 0;cluster_index<attr->cluster->length;cluster_index++)
				printf("%s ",inet_ntoa(attr->cluster->list[cluster_index]));
			printf("\n");
		}

            int idx;
            for (idx=0;idx<attr->unknown_num;idx++)
            {
                struct unknown_attr *unknown = attr->unknown + idx;
                printf("   UNKNOWN_ATTR(%i, %i, %i):", unknown->flag, unknown->type, unknown->len);
                int b;
                for(b = 0; b < unknown->len; ++b)
                    printf(" %02x", unknown->raw[b]);
                printf("\n");
            }

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI) )!=0)
	    {
		    printf("MP_REACH_NLRI");
#ifdef BGPDUMP_HAVE_IPV6
		    if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST] || attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST] || attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST])
		    {
			   char buf[128];
			    
			   if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST])
			   {
				   printf("(IPv6 Unicast)\n");
                    if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_len==4)
                        printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop.v4_addr));
                    if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_len==16)
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop,buf));
                    if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_len==32) {
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop,buf));
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_local,buf));
                    }
			   }
			   else if (attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST])	 
		  	   {
			   	   printf("(IPv6 Multicast)\n");
                    if (attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop_len==4)
                        printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop.v4_addr));
                    if (attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop_len==16)
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop,buf));
                    if (attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop_len==32) {
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop,buf));
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop_local,buf));
                    }
               }
               else
               {
                   printf("(IPv6 Both unicast and multicast)\n");
                    if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop_len==4)
                        printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop.v4_addr));
                    if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop_len==16)
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop,buf));
                    if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop_len==32) {
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop,buf));
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop_local,buf));
                    }
			   }
		    }
		    else
#endif
		    {
			   char buf[128];

               if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST])
               {
                    printf("(IPv4 Unicast)\n");
                    if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_len==4)
                        printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop.v4_addr));
                    if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_len==16)
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop,buf));
                    if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_len==32) {
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop,buf));
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_local,buf));
                    }
                }
               else if (attr->mp_info->announce[AFI_IP][SAFI_MULTICAST])	 
                {
                    printf("(IPv4 Multicast)\n");
                    if (attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop_len==4)
                        printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop.v4_addr));
                    if (attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop_len==16)
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop,buf));
                    if (attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop_len==32) {
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop,buf));
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop_local,buf));
                    }
                }
                else if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST])
                {
                    printf("(IPv4 Both unicast and multicast)\n");
                    if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop_len==4)
                        printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop.v4_addr));
                    if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop_len==16)
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop,buf));
                    if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop_len==32) {
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop,buf));
                        printf("NEXT_HOP: %s\n",fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop_local,buf));
                    }
                }
            }
        }
	    
	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI) )!=0)
	    {
		    printf("MP_UNREACH_NLRI");
#ifdef BGPDUMP_HAVE_IPV6
		    if (attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST] || attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST] || attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST])

		    {
			    
			   if (attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST])
			   {
				   printf("(IPv6 Unicast)\n");
			   }
			   else if (attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST])	 
		  	   {
			   	   printf("(IPv6 Multicast)\n");

		           }
			   else
		           {
				   printf("(IPv6 Both unicast and multicast)\n");


			   }
		    }
		    else
#endif
		    {
			   
			   if (attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST])
			   {
				   printf("(IPv4 Unicast)\n");
			  
			   }
			   else if (attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST])	 
		  	   {
			   	   printf("(IPv4 Multicast)\n");
			  
		
		           }
			   else if (attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST])
		           {
				   printf("(IPv4 Both unicast and multicast)\n");
			  

			   }
  
		    }
	    } 
	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    printf("COMMUNITY:%s\n",attr->community->str);

        if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES) ) !=0)    
            printf("LARGE_COMMUNITY:%s\n",attr->lcommunity->str);
       
    }
 
}

void show_prefixes(int count,struct prefix *prefix, int addpath) {
    int i;
    for(i=0;i<count;i++)
        if (addpath)
	        printf("  %s/%d PATH_ID: %u\n",inet_ntoa(prefix[i].address.v4_addr),prefix[i].len, prefix[i].path_id);
        else
	        printf("  %s/%d\n",inet_ntoa(prefix[i].address.v4_addr),prefix[i].len);

}
#ifdef BGPDUMP_HAVE_IPV6
void show_prefixes6(int count,struct prefix *prefix, int addpath)
{
	int i;
	char buf[128];

	for (i=0;i<count;i++)
        if (addpath)
	        printf("  %s/%d PATH_ID: %u\n",fmt_ipv6(prefix[i].address,buf),prefix[i].len, prefix[i].path_id);
        else
	        printf("  %s/%d\n",fmt_ipv6(prefix[i].address,buf),prefix[i].len);

}
#endif


static void table_line_withdraw(struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int idx;
	char buf[128];
	
	for (idx=0;idx<count;idx++)
	{
        show_line_prefix(get_bgp4mp_format(entry), time_str, "W");

		switch(entry->body.zebra_message.address_family) {
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|",
						fmt_ipv6(entry->body.zebra_message.source_ip,buf),
						entry->body.zebra_message.source_as)
					: printf("%s|%u|",
						fmt_ipv6(entry->body.zebra_message.destination_ip,buf),
						entry->body.zebra_message.destination_as);
				break;
#endif
            		case AFI_IP:
            		default:
				bgp4mp_message_direction_receive(entry)
                			? printf("%s|%u|",
                       				inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),
                       				entry->body.zebra_message.source_as)
					: printf("%s|%u|",
                      				inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr),
                      				entry->body.zebra_message.destination_as);
                		break;
		}
        is_addpath(entry)
            ? printf("%s/%d|%u\n",inet_ntoa(prefix[idx].address.v4_addr),prefix[idx].len,prefix[idx].path_id)
            : printf("%s/%d\n",inet_ntoa(prefix[idx].address.v4_addr),prefix[idx].len);
        }
}

#ifdef BGPDUMP_HAVE_IPV6

static void table_line_withdraw6(struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int idx;
	char buf[128];
	char buf1[128];

	for (idx=0;idx<count;idx++)
	{
		show_line_prefix(get_bgp4mp_format(entry), time_str, "W");

		switch(entry->body.zebra_message.address_family) {
			case AFI_IP6:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|%s/%d",
						fmt_ipv6(entry->body.zebra_message.source_ip,buf1),
						entry->body.zebra_message.source_as,
						fmt_ipv6(prefix[idx].address,buf),prefix[idx].len)
					: printf("%s|%u|%s/%d",
						fmt_ipv6(entry->body.zebra_message.destination_ip,buf1),
						entry->body.zebra_message.destination_as,
						fmt_ipv6(prefix[idx].address,buf),prefix[idx].len);
				break;
            		case AFI_IP:
            		default:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|%s/%d",
						fmt_ipv4(entry->body.zebra_message.source_ip,buf1),
						entry->body.zebra_message.source_as,
						fmt_ipv6(prefix[idx].address,buf),prefix[idx].len)
					: printf("%s|%u|%s/%d",
						fmt_ipv6(entry->body.zebra_message.destination_ip,buf1),
						entry->body.zebra_message.destination_as,
						fmt_ipv6(prefix[idx].address,buf),prefix[idx].len);
                		break;
		}
        is_addpath(entry)
            ? printf("|%u\n", prefix[idx].path_id)
            : printf("\n");
        }	
}
#endif


static void table_line_announce(struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int idx  ;
	char buf[128];
	char aggregate[20];
	unsigned int npref;
	unsigned int nmed;

	if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
		sprintf(aggregate,"AG");
	else
		sprintf(aggregate,"NAG");

	for (idx=0;idx<count;idx++)
	{
        show_line_prefix(get_bgp4mp_format(entry), time_str, "A");

		if (mode == 1)
		{
			switch(entry->body.zebra_message.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.source_ip,buf),entry->body.zebra_message.source_as)
					: printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.destination_ip,buf),entry->body.zebra_message.destination_as);
				break;
#endif
			case AFI_IP:
			default:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as)
					: printf("%s|%u|",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr),entry->body.zebra_message.destination_as);
				break;
			}

            is_addpath(entry)
                ? printf("%s/%d|%u|%s|%s|",inet_ntoa(prefix[idx].address.v4_addr),prefix[idx].len,prefix[idx].path_id,attr_aspath(entry->attr),describe_origin(entry->attr->origin))
                : printf("%s/%d|%s|%s|",inet_ntoa(prefix[idx].address.v4_addr),prefix[idx].len,attr_aspath(entry->attr),describe_origin(entry->attr->origin));

		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
			printf("%s|%u|%u|",inet_ntoa(entry->attr->nexthop),npref,nmed);
			if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    	printf("%s|",entry->attr->community->str+1);
            else
                printf("|");

            if (show_large_comms) {
                if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES) ) !=0) 
                    printf("%s|",entry->attr->lcommunity->str+1);
                else
                    printf("|");
            }

		    printf("%s|", aggregate); /* AG/NAG */

			if (entry->attr->aggregator_addr.s_addr != -1)
				printf("%u %s|\n",entry->attr->aggregator_as,inet_ntoa(entry->attr->aggregator_addr));
			else
				printf("|\n");
		}
		else
		{
			switch(entry->body.zebra_message.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.source_ip,buf),entry->body.zebra_message.source_as)
					: printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.destination_ip,buf),entry->body.zebra_message.destination_as);
				break;
#endif
			case AFI_IP:
			default:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as)
					: printf("%s|%u|",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr),entry->body.zebra_message.destination_as);
				break;
			}

            is_addpath(entry)
                ? printf("%s/%d|%u|%s|%s\n",inet_ntoa(prefix[idx].address.v4_addr),prefix[idx].len,prefix[idx].path_id,attr_aspath(entry->attr),describe_origin(entry->attr->origin))
                : printf("%s/%d|%s|%s\n",inet_ntoa(prefix[idx].address.v4_addr),prefix[idx].len,attr_aspath(entry->attr),describe_origin(entry->attr->origin));
				
		}
	}

}
static void table_line_announce_1(struct mp_nlri *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int idx  ;
	char buf[128];
	char aggregate[20];
	unsigned int npref;
	unsigned int nmed;

	if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
		sprintf(aggregate,"AG");
	else
		sprintf(aggregate,"NAG");

	for (idx=0;idx<count;idx++)
	{
        show_line_prefix(get_bgp4mp_format(entry), time_str, "A");

		if (mode == 1)
		{
			if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI))
			{
				switch(entry->body.zebra_message.address_family)
				{
#ifdef BGPDUMP_HAVE_IPV6
				case AFI_IP6:
					bgp4mp_message_direction_receive(entry)
						? printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.source_ip,buf),entry->body.zebra_message.source_as)
						: printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.destination_ip,buf),entry->body.zebra_message.destination_as);
					break;
#endif
				case AFI_IP:
				default:
					bgp4mp_message_direction_receive(entry)
						? printf("%s|%u|",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as)
						: printf("%s|%u|",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr),entry->body.zebra_message.destination_as);
					break;
				}

                is_addpath(entry)
                    ? printf("%s/%d|%u|%s|%s|",inet_ntoa(prefix->nlri[idx].address.v4_addr),prefix->nlri[idx].len,prefix->nlri[idx].path_id,attr_aspath(entry->attr),describe_origin(entry->attr->origin))
                    : printf("%s/%d|%s|%s|",inet_ntoa(prefix->nlri[idx].address.v4_addr),prefix->nlri[idx].len,attr_aspath(entry->attr),describe_origin(entry->attr->origin));

		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
                if (prefix->nexthop_len == 4)
                    printf("%s|%d|%d|",inet_ntoa(prefix->nexthop.v4_addr),npref,nmed);
                else if ((prefix->nexthop_len == 16) || (prefix->nexthop_len == 32))
                    printf("%s|%d|%d|",fmt_ipv6(prefix->nexthop,buf),npref,nmed);
                
				//printf("%s|%d|%d|",inet_ntoa(prefix->nexthop.v4_addr),entry->attr->local_pref,entry->attr->med);
				if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    		printf("%s|",entry->attr->community->str+1);
				else
					printf("|");

                if (show_large_comms) {
                    if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES) ) !=0) 
                        printf("%s|",entry->attr->lcommunity->str+1);
                    else
                        printf("|");
                }

                printf("%s|", aggregate); /* AG/NAG */

			}
			else 
			{
                // I'm not convinced this code block is actually ever executed
                // it appears to handle old-style (non-MP) yet this function isn't
                // called for that type.....
                // cpetrie@ 2016-08-12

				switch(entry->body.zebra_message.address_family)
				{
#ifdef BGPDUMP_HAVE_IPV6
				case AFI_IP6:
					bgp4mp_message_direction_receive(entry)
						? printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.source_ip,buf),entry->body.zebra_message.source_as)
						: printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.destination_ip,buf),entry->body.zebra_message.destination_as);
					break;
#endif
				case AFI_IP:
				default:
					bgp4mp_message_direction_receive(entry)
						? printf("%s|%u|",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as)
						: printf("%s|%u|",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr),entry->body.zebra_message.destination_as);
					break;
				}

                is_addpath(entry)
                    ? printf("%s/%d|%u|%s|%s|",inet_ntoa(prefix->nlri[idx].address.v4_addr),prefix->nlri[idx].len,prefix->nlri[idx].path_id,attr_aspath(entry->attr),describe_origin(entry->attr->origin))
                    : printf("%s/%d|%s|%s|",inet_ntoa(prefix->nlri[idx].address.v4_addr),prefix->nlri[idx].len,attr_aspath(entry->attr),describe_origin(entry->attr->origin));

		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
			    printf("%s|%d|%d|",inet_ntoa(entry->attr->nexthop),npref,nmed);
				//printf("%s|%d|%d|",inet_ntoa(entry->attr->nexthop),entry->attr->local_pref,entry->attr->med);
				if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    		printf("%s|",entry->attr->community->str+1);
				else
					printf("|");

                if (show_large_comms) {
                    if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES) ) !=0) 
                        printf("%s|",entry->attr->lcommunity->str+1);
                    else
                        printf("|");
                }

                printf("%s|",aggregate); /* AG/NAG */

			}
			if (entry->attr->aggregator_addr.s_addr != -1)
				printf("%u %s|\n",entry->attr->aggregator_as,inet_ntoa(entry->attr->aggregator_addr));
			else
				printf("|\n");
		}
		else
		{
			switch(entry->body.zebra_message.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.source_ip,buf),entry->body.zebra_message.source_as)
					: printf("%s|%u|",fmt_ipv6(entry->body.zebra_message.destination_ip,buf),entry->body.zebra_message.destination_as);
				break;
#endif
			case AFI_IP:
			default:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|",inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as)
					: printf("%s|%u|",inet_ntoa(entry->body.zebra_message.destination_ip.v4_addr),entry->body.zebra_message.destination_as);
				break;
			}
            is_addpath(entry)
                ? printf("%s/%d|%u|%s|%s\n",inet_ntoa(prefix->nlri[idx].address.v4_addr),prefix->nlri[idx].len,prefix->nlri[idx].path_id,attr_aspath(entry->attr),describe_origin(entry->attr->origin))
                : printf("%s/%d|%s|%s\n",inet_ntoa(prefix->nlri[idx].address.v4_addr),prefix->nlri[idx].len,attr_aspath(entry->attr),describe_origin(entry->attr->origin));
				
		}
	}

}

#ifdef BGPDUMP_HAVE_IPV6
static void table_line_announce6(struct mp_nlri *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int idx  ;
	char buf[128];
	char buf1[128];
	char buf2[128];
	char aggregate[20];
	unsigned int npref;
	unsigned int nmed;

	if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
		sprintf(aggregate,"AG");
	else
		sprintf(aggregate,"NAG");

	for (idx=0;idx<count;idx++)
	{
        show_line_prefix(get_bgp4mp_format(entry), time_str, "A");

		if (mode == 1)
		{
			switch(entry->body.zebra_message.address_family)
			{
			case AFI_IP6:
				
		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|%s/%d|",fmt_ipv6(entry->body.zebra_message.source_ip,buf1),entry->body.zebra_message.source_as,fmt_ipv6(prefix->nlri[idx].address,buf2),prefix->nlri[idx].len)
					: printf("%s|%u|%s/%d|",fmt_ipv6(entry->body.zebra_message.destination_ip,buf1),entry->body.zebra_message.destination_as,fmt_ipv6(prefix->nlri[idx].address,buf2),prefix->nlri[idx].len);

				break;

			case AFI_IP:
			default:

		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
			//printf("%s|%d|%d|",inet_ntoa(entry->attr->nexthop),nprof,nmed);
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|%s/%d|",fmt_ipv4(entry->body.zebra_message.source_ip,buf1),entry->body.zebra_message.source_as,fmt_ipv6(prefix->nlri[idx].address,buf2),prefix->nlri[idx].len)
					: printf("%s|%u|%s/%d|",fmt_ipv4(entry->body.zebra_message.destination_ip,buf1),entry->body.zebra_message.destination_as,fmt_ipv6(prefix->nlri[idx].address,buf2),prefix->nlri[idx].len);

				break;
			}

            if (is_addpath(entry))
                printf("%u|", prefix->nlri[idx].path_id);

            if (prefix->nexthop_len == 4)
                printf("%s|%s|%s|%u|%u|", attr_aspath(entry->attr),describe_origin(entry->attr->origin),inet_ntoa(prefix->nexthop.v4_addr),npref,nmed);
            else if ((prefix->nexthop_len == 16) || (prefix->nexthop_len == 32))
                printf("%s|%s|%s|%u|%u|", attr_aspath(entry->attr),describe_origin(entry->attr->origin),fmt_ipv6(prefix->nexthop,buf),npref,nmed);

			if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    		printf("%s|",entry->attr->community->str+1);
			else
				printf("|");

            if (show_large_comms) {
                if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES) ) !=0) 
                    printf("%s|",entry->attr->lcommunity->str+1);
                else
                    printf("|");

            }

            printf("%s|", aggregate); /* AG/NAG */


			if (entry->attr->aggregator_addr.s_addr != -1)
				printf("%u %s|\n",entry->attr->aggregator_as,inet_ntoa(entry->attr->aggregator_addr));
			else
				printf("|\n");

		}
		else
		{
			switch(entry->body.zebra_message.address_family)
			{
			case AFI_IP6:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|%s/%d|",fmt_ipv6(entry->body.zebra_message.source_ip,buf1),entry->body.zebra_message.source_as,fmt_ipv6(prefix->nlri[idx].address,buf),prefix->nlri[idx].len)
					: printf("%s|%u|%s/%d|",fmt_ipv6(entry->body.zebra_message.destination_ip,buf1),entry->body.zebra_message.destination_as,fmt_ipv6(prefix->nlri[idx].address,buf),prefix->nlri[idx].len);
				break;
			case AFI_IP:
			default:
				bgp4mp_message_direction_receive(entry)
					? printf("%s|%u|%s/%d|",fmt_ipv4(entry->body.zebra_message.source_ip,buf1),entry->body.zebra_message.source_as,fmt_ipv6(prefix->nlri[idx].address,buf),prefix->nlri[idx].len)
					: printf("%s|%u|%s/%d|",fmt_ipv4(entry->body.zebra_message.destination_ip,buf1),entry->body.zebra_message.destination_as,fmt_ipv6(prefix->nlri[idx].address,buf),prefix->nlri[idx].len);
				break;
			}

            if (is_addpath(entry))
                printf("%u|", prefix->nlri[idx].path_id);

            printf("%s|%s\n",attr_aspath(entry->attr),describe_origin(entry->attr->origin));
		}		

	}

}
#endif


static void table_line_mrtd_route(BGPDUMP_MRTD_TABLE_DUMP *route,BGPDUMP_ENTRY *entry)
{
	
	struct tm *date = NULL;
	char aggregate[20];	
	unsigned int npref;
	unsigned int nmed;
	char  time_str[20];
        char peer[BGPDUMP_ADDRSTRLEN], prefix[BGPDUMP_ADDRSTRLEN], nexthop[BGPDUMP_ADDRSTRLEN];

	if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
		sprintf(aggregate,"AG");
	else
		sprintf(aggregate,"NAG");

    time_t *t;
    if (timetype==0) {
        t = &entry->time;
    } else {
        t = &route->uptime;
    }
    if (mode == 1) {
        sprintf(time_str, "%lld", (long long)*t);
    } else {
        date=gmtime(t);
        time2str(date, time_str);
    }
    show_line_prefix("TABLE_DUMP", time_str, "B");

#ifdef BGPDUMP_HAVE_IPV6
	    	if (entry->subtype == AFI_IP6)
		{
		    fmt_ipv6(route->peer_ip,peer);
		    fmt_ipv6(route->prefix,prefix);
		}
	    	else
#endif
                {
		    strncpy(peer, inet_ntoa(route->peer_ip.v4_addr), BGPDUMP_ADDRSTRLEN);
                    strncpy(prefix, inet_ntoa(route->prefix.v4_addr), BGPDUMP_ADDRSTRLEN);
		}

		if (mode == 1)
		{
                    printf("%s|%u|",peer,route->peer_as);
                    printf("%s/%d|%s|%s|",prefix,route->mask,
                           attr_aspath(entry->attr),describe_origin(entry->attr->origin));

		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
#ifdef BGPDUMP_HAVE_IPV6
	    	if ((entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)) && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST])
		{
		    fmt_ipv6(entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop,nexthop);
		}
	    	else
#endif
                {
		    strncpy(nexthop, inet_ntoa(entry->attr->nexthop), BGPDUMP_ADDRSTRLEN);
		}
		   printf("%s|%u|%u|",nexthop,npref,nmed);

		   if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    		printf("%s|",entry->attr->community->str+1);
			else
				printf("|");

            if (show_large_comms) {
                if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES) ) !=0)  
                    printf("%s|",entry->attr->lcommunity->str+1);
                else
                    printf("|");

            }

            printf("%s|",aggregate); /* AG/NAG */
				
			if (entry->attr->aggregator_addr.s_addr != -1)
				printf("%u %s|\n",entry->attr->aggregator_as,inet_ntoa(entry->attr->aggregator_addr));
			else
				printf("|\n");
		}
		else
		{
	 	    printf("%s|%u|",peer,route->peer_as);
                    printf("%s/%d|%s|%s\n",prefix,route->mask,attr_aspath(entry->attr),describe_origin(entry->attr->origin));
		}

}

static char *describe_origin(int origin) {
    if(origin == 0) return "IGP";
    if(origin == 1) return "EGP";
    return "INCOMPLETE";
}

static void table_line_dump_v2_prefix(BGPDUMP_TABLE_DUMP_V2_PREFIX *e,BGPDUMP_ENTRY *entry)
{
    struct tm *date = NULL;
    unsigned int npref;
    unsigned int nmed;
    char  time_str[20];
    char peer[BGPDUMP_ADDRSTRLEN], prefix[BGPDUMP_ADDRSTRLEN], nexthop[BGPDUMP_ADDRSTRLEN];
    
    int i;
    int addpath = is_addpath(entry);
    
    for(i = 0; i < e->entry_count; i++) {
        attributes_t *attr = e->entries[i].attr;
        if(! attr)
            continue;
        
        char *origin = describe_origin(attr->origin);
        char *aspath_str = (attr->aspath) ? attr->aspath->str: "";
        char *aggregate = attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE) ? "AG" : "NAG";
        
        if(e->entries[i].peer->afi == AFI_IP){
            fmt_ipv4(e->entries[i].peer->peer_ip, peer);
#ifdef BGPDUMP_HAVE_IPV6
        } else if(e->entries[i].peer->afi == AFI_IP6){
            fmt_ipv6(e->entries[i].peer->peer_ip, peer);
#endif
        }
        
        if(e->afi == AFI_IP) {
            fmt_ipv4(e->prefix, prefix);
#ifdef BGPDUMP_HAVE_IPV6
        } else if(e->afi == AFI_IP6) {
            fmt_ipv6(e->prefix, prefix);
#endif
        }

        time_t *t;
        if (timetype==0) {
            t = &entry->time;
        } else {
            time_t tmp = (time_t)((e->entries[i]).originated_time);
            t = &tmp;
        }
        if (mode == 1) {
            sprintf(time_str, "%lld", (long long)*t);
        } else {
            date=gmtime(t);
            time2str(date, time_str);
        }

        (addpath)
            ? show_line_prefix("TABLE_DUMP2_AP", time_str, "B")
            : show_line_prefix("TABLE_DUMP2", time_str, "B");

        if (mode == 1)
        {
            printf("%s|%u|",peer,e->entries[i].peer->peer_as);

            (addpath)
                ? printf("%s/%d|%u|%s|%s|",prefix,e->prefix_length,e->entries[i].path_id,aspath_str,origin)
                : printf("%s/%d|%s|%s|",prefix,e->prefix_length,aspath_str,origin);
            
            npref=attr->local_pref;
            if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
                npref=0;
            nmed=attr->med;
            if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
                nmed=0;
            
            if ((attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)) && attr->mp_info->announce[AFI_IP6][SAFI_UNICAST])
            {
                if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_len == 4)
                    strncpy(nexthop, inet_ntoa(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop.v4_addr), BGPDUMP_ADDRSTRLEN);
                else if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_len == 16)
                    fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop,nexthop);
                else if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_len == 32)
                    fmt_ipv6(attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop,nexthop);
            }
            else if ((attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)) && attr->mp_info->announce[AFI_IP][SAFI_UNICAST])
            {
                if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_len == 4)
                    strncpy(nexthop, inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop.v4_addr), BGPDUMP_ADDRSTRLEN);
                else if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_len == 16)
                    fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop,nexthop);
                else if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_len == 32)
                    fmt_ipv6(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop,nexthop);
            }
            else
            {
                strncpy(nexthop, inet_ntoa(attr->nexthop), BGPDUMP_ADDRSTRLEN);
            }
            printf("%s|%u|%u|",nexthop,npref,nmed);
            
            if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
                printf("%s|",attr->community->str+1);
            else
                printf("|");

            if (show_large_comms) {
                if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES) ) !=0)    
                    printf("%s|",attr->lcommunity->str+1);
                else
                    printf("|");
            }
            
            printf("%s|",aggregate);

            if (attr->aggregator_addr.s_addr != -1)
                printf("%u %s|\n",attr->aggregator_as,inet_ntoa(attr->aggregator_addr));
            else
                printf("|\n");
        }
        else
        {
            printf("%s|%u|",peer,e->entries[i].peer->peer_as);
            (addpath)
                ? printf("%s/%d|%u|%s|%s\n",prefix,e->prefix_length,e->entries[i].path_id,aspath_str,origin)
                : printf("%s/%d|%s|%s\n",prefix,e->prefix_length,aspath_str,origin);
            
        }
    }
    
}
