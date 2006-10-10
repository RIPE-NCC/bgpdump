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
Filename          : bgpdump.c
Author            : Shufu Mao(msf98@mails.tsinghua.edu.cn) 
Date              : 2003-11-02 
Revision          : 
Revised           : 
Description       : bgpdump program, the input and output format is the same as route_btoa 
Language Version  : C
OSs Tested        : Linux 2.4.22
To Do             : 
-------------------------------------------------------------------------------
*/

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "bgpdump_lib.h"
#include <time.h>

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

    void process(BGPDUMP_ENTRY *entry);
    void show_attr(struct attr *attr);
    void show_prefixes(int count,struct prefix *prefix);
    void table_line_announce_1(int mode,struct mp_nlri *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
    void table_line_announce(int mode,struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
    void table_line_withdraw(int mode,struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
    void table_line_mrtd_route(int mode,BGPDUMP_MRTD_TABLE_DUMP *route,BGPDUMP_ENTRY *entry, int timetype);
#ifdef BGPDUMP_HAVE_IPV6
    void show_prefixes6(int count,struct prefix *prefix);
    void table_line_withdraw6(int mode,struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
    void table_line_announce6(int mode,struct mp_nlri *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str);
#endif


    static int mode=0;
    static int timetype=0;

int main(int argc, char *argv[]) {
    
    BGPDUMP *my_dump;
    BGPDUMP_ENTRY *my_entry=NULL;
    extern char *optarg;
    char c;
    extern int optind;
    char *usage = "Usage: bgpdump [-m] [-M] [-i] [-t dump|change ] input_binary_file(s) \n";

    while ((c=getopt(argc,argv,"if:o:t:mM"))!=-1)
	switch(c)
	{
	case 'm':
		mode=1;
		break;
	case 'M':
		mode=2;
		break;
	case 't':
		if(strcmp(optarg,"dump")==0){
		  timetype=0;
		}else if(strcmp(optarg,"change")==0){
		  timetype=1;
		}
	default:
		break;
	}
    
    if(argc>1) {
	my_dump=bgpdump_open_dump(argv[optind]);
    } else {
	my_dump=bgpdump_open_dump("dumps/updates.20020701.0032");
    }
    
    if(my_dump==NULL) {
	printf("%s",usage);
	exit(1);
    }
    
    do {
	my_entry=bgpdump_read_next(my_dump);
	if(my_entry!=NULL) {
	    process(my_entry);
	    bgpdump_free_mem(my_entry);
	}
    } while(my_dump->eof==0);

    bgpdump_close_dump(my_dump);
    
 return 0;
}

char *bgp_state_name[] = {
	"Unknown",
	"Idle",
	"Connect",
	"Active",
	"Opensent",
	"Openconfirm",
	"Established",
	NULL
};
void time2str(struct tm* time,char *time_str)
{
	char tmp_str[10];

	if (time->tm_mon+1<10)
		sprintf(tmp_str,"0%d/",time->tm_mon+1);
	else
		sprintf(tmp_str,"%d/",time->tm_mon+1);
	strcpy(time_str,tmp_str);
	
	if (time->tm_mday<10)
		sprintf(tmp_str,"0%d/",time->tm_mday);
	else
		sprintf(tmp_str,"%d/",time->tm_mday);
	strcat(time_str,tmp_str);
	
	if (time->tm_year%100 <10)
		sprintf(tmp_str,"0%d ",time->tm_year%100);
	else
		sprintf(tmp_str,"%d ",time->tm_year%100);
	strcat(time_str,tmp_str);
	
	if (time->tm_hour<10)
		sprintf(tmp_str,"0%d:",time->tm_hour);
	else
		sprintf(tmp_str,"%d:",time->tm_hour);
	strcat(time_str,tmp_str);
	
	if (time->tm_min<10)
		sprintf(tmp_str,"0%d:",time->tm_min);
	else
		sprintf(tmp_str,"%d:",time->tm_min);
	strcat(time_str,tmp_str);
	
	if (time->tm_sec <10)
		sprintf(tmp_str,"0%d",time->tm_sec);
	else
		sprintf(tmp_str,"%d",time->tm_sec);
	strcat(time_str,tmp_str);

}
void process(BGPDUMP_ENTRY *entry) {

	struct tm *time;
	char time_str[128];
	char time_str2[128];
        char prefix[BGPDUMP_ADDRSTRLEN];  
	
	time=gmtime(&entry->time);
	time2str(time,time_str);	
	if (mode==0)
	{
		printf("TIME: %s\n",time_str);
	}	
    //printf("TIME: %s",asctime(gmtime(&entry->time)));
    //printf("LENGTH          : %u\n", entry->length);
    switch(entry->type) {
	case BGPDUMP_TYPE_MRTD_TABLE_DUMP:
	     if(mode==0){
	        const char *prefix_str = NULL;
#ifdef BGPDUMP_HAVE_IPV6
	    	if (entry->subtype == AFI_IP6)
		{
	    		printf("TYPE: TABLE_DUMP/INET6\n");
			prefix_str = inet_ntop(AF_INET6,&entry->body.mrtd_table_dump.prefix.v6_addr,prefix,sizeof(prefix));
		}
	    	else
#endif
                {
			printf("TYPE: TABLE_DUMP/INET\n");
			prefix_str = inet_ntoa(entry->body.mrtd_table_dump.prefix.v4_addr);
		}
		printf("VIEW: %d\n",entry->body.mrtd_table_dump.view);
	    	printf("SEQUENCE: %d\n",entry->body.mrtd_table_dump.sequence);
	    	printf("PREFIX: %s/%d\n",prefix_str,entry->body.mrtd_table_dump.mask);
	    	printf("FROM:");
		switch(entry->subtype)
		{
#ifdef BGPDUMP_HAVE_IPV6
		case AFI_IP6:

			inet_ntop(AF_INET6,&entry->body.mrtd_table_dump.peer_ip.v6_addr,prefix,sizeof(prefix));
			printf(" %s ",prefix);
			break;
#endif
		case AFI_IP:
		default:
			if (entry->body.mrtd_table_dump.peer_ip.v4_addr.s_addr != 0x00000000L)
		    		printf(" %s ",inet_ntoa(entry->body.mrtd_table_dump.peer_ip.v4_addr));
			else
				printf(" N/A ");
		}
		printf("AS%d\n",entry->body.mrtd_table_dump.peer_as);

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
	        table_line_mrtd_route(mode,&entry->body.mrtd_table_dump,entry,timetype);	     
	     }
	    break;
	    
	case BGPDUMP_TYPE_ZEBRA_BGP:
	    
	    switch(entry->subtype) 
	    {
		case BGPDUMP_SUBTYPE_ZEBRA_BGP_MESSAGE:

		    switch(entry->body.zebra_message.type) 
		    {
			case BGP_MSG_UPDATE:
			   if (mode ==0)
		    	   {
				printf("TYPE: BGP4MP/MESSAGE/Update\n");	 
				if (entry->body.zebra_message.source_as)
			        {
					printf("FROM:");
					switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip.v6_addr,prefix,sizeof(prefix));
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
					printf("AS%d\n",entry->body.zebra_message.source_as);
                                }
				if (entry->body.zebra_message.destination_as)
				{
					printf("TO:");
					switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							inet_ntop(AF_INET6,&entry->body.zebra_message.destination_ip.v6_addr,prefix,sizeof(prefix));
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
		    			printf("AS%d\n",entry->body.zebra_message.destination_as);
				}
				if (entry->attr && entry->attr->len)
				    	show_attr(entry->attr);
				if (entry->body.zebra_message.cut_bytes)
				{
					u_int16_t cutted,index;
					u_int8_t buf[128];
					
					printf("   INCOMPLETE PACKET: %d bytes cutted\n",entry->body.zebra_message.cut_bytes);
					printf("   INCOMPLETE PART: ");
					if (entry->body.zebra_message.incomplete.orig_len)
					{
					 	cutted=entry->body.zebra_message.incomplete.prefix.len/8+1;
						buf[0]=entry->body.zebra_message.incomplete.orig_len;
						memcpy(buf+1,&entry->body.zebra_message.incomplete.prefix.address,cutted-1);
						
						for (index=0;index<cutted;index++)
						{
							if (buf[index]<0x10)
								printf("0%x ",buf[index]);
							else
								printf("%x ",buf[index]);
						}
					}
					printf("\n");
				}
				if ((entry->body.zebra_message.withdraw_count) || (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI))) 
				{
#ifdef BGPDUMP_HAVE_IPV6
					if ((entry->body.zebra_message.withdraw_count)||(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count) ||(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count) )

#else
					if ((entry->body.zebra_message.withdraw_count)||(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count) || (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count))

#endif				
						printf("WITHDRAW\n");
					if (entry->body.zebra_message.withdraw_count)
			    			show_prefixes(entry->body.zebra_message.withdraw_count,entry->body.zebra_message.withdraw);
				 	if (entry->attr->mp_info)
					{
						if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count)
							show_prefixes(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->nlri);
					
						if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count)
							show_prefixes(entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->nlri);

						if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count)
							show_prefixes(entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->nlri);

#ifdef BGPDUMP_HAVE_IPV6
						if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count)
							show_prefixes6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->nlri);
					
						if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count)
							show_prefixes6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->nlri);

						if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count)
							show_prefixes6(entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->nlri);
#endif
					}
				}
				if ( (entry->body.zebra_message.announce_count) || (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI))) 
				{
					printf("ANNOUNCE\n");
			    		if (entry->body.zebra_message.announce_count)
			    			show_prefixes(entry->body.zebra_message.announce_count,entry->body.zebra_message.announce);
					if (entry->attr->mp_info)
					{
						if (entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->prefix_count)
							show_prefixes(entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nlri);
					
						if (entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->prefix_count)
							show_prefixes(entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nlri);

						if (entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count)
							show_prefixes(entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nlri);

#ifdef BGPDUMP_HAVE_IPV6
						if (entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->prefix_count)
							show_prefixes6(entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nlri);
					
						if (entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->prefix_count)
							show_prefixes6(entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nlri);

						if (entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count)
							show_prefixes6(entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count,entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nlri);
#endif					
					}
				}
			   }
			   else if (mode == 1  || mode == 2) //-m -M
			   {
				if ((entry->body.zebra_message.withdraw_count) || (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI)))
				{

					table_line_withdraw(mode,entry->body.zebra_message.withdraw,entry->body.zebra_message.withdraw_count,entry,time_str);
					if (entry->attr->mp_info)
					{
						if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count)
							table_line_withdraw(mode,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST]->prefix_count,entry,time_str);	
						if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count)
							table_line_withdraw(mode,entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP][SAFI_MULTICAST]->prefix_count,entry,time_str);
						if (entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count)
							table_line_withdraw(mode,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count,entry,time_str);

#ifdef BGPDUMP_HAVE_IPV6						
						if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count)
							table_line_withdraw6(mode,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST]->prefix_count,entry,time_str);	
						if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count)
							table_line_withdraw6(mode,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_MULTICAST]->prefix_count,entry,time_str);
						if (entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count)
							table_line_withdraw6(mode,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->nlri,entry->attr->mp_info->withdraw[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count,entry,time_str);
#endif

					}
	
				
				}
				if ( (entry->body.zebra_message.announce_count) || (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI)))
				{
					table_line_announce(mode,entry->body.zebra_message.announce,entry->body.zebra_message.announce_count,entry,time_str);
					if (entry->attr->mp_info)
					{
						if (entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->prefix_count)
							table_line_announce_1(mode,entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST],entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->prefix_count,entry,time_str);	
						if (entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->prefix_count)
							table_line_announce_1(mode,entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST],entry->attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->prefix_count,entry,time_str);
						if (entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count)
							table_line_announce_1(mode,entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST],entry->attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->prefix_count,entry,time_str);
#ifdef BGPDUMP_HAVE_IPV6						
						if (entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->prefix_count)
							table_line_announce6(mode,entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST],entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->prefix_count,entry,time_str);	
						if (entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->prefix_count)
							table_line_announce6(mode,entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST],entry->attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->prefix_count,entry,time_str);
						if (entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST] && entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count)
							table_line_announce6(mode,entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST],entry->attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->prefix_count,entry,time_str);
#endif

					}
					
				}  
			   }
			   break;
		    
			case BGP_MSG_OPEN:
			    if (mode != 0)
				    break;
		            printf("TYPE: BGP4MP/MESSAGE/Open\n");
			    if (entry->body.zebra_message.source_as)
			    {
				printf("FROM:");
				switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip.v6_addr,prefix,sizeof(prefix));
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
				printf("AS%d\n",entry->body.zebra_message.source_as);
			    }
			    if (entry->body.zebra_message.destination_as)
			    {
				printf("TO:");
				switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							inet_ntop(AF_INET6,&entry->body.zebra_message.destination_ip.v6_addr,prefix,sizeof(prefix));
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
		    		printf("AS%d\n",entry->body.zebra_message.destination_as);
                            }

			    printf("VERSION: %d\n",entry->body.zebra_message.version);
			    printf("AS: %d\n",entry->body.zebra_message.my_as);
			    printf("HOLD_TIME: %d\n",entry->body.zebra_message.hold_time);
			    printf("ID: %s\n",inet_ntoa(entry->body.zebra_message.bgp_id));
			    printf("OPT_PARM_LEN: %d\n",entry->body.zebra_message.opt_len);
			    break;
			
			case BGP_MSG_NOTIFY:
			    if (mode != 0)
				    break;
			    printf("TYPE: BGP4MP/MESSAGE/Notify\n");
			    if (entry->body.zebra_message.source_as)
			    {
				printf("FROM:");
				switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip.v6_addr,prefix,sizeof(prefix));
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
				printf("AS%d\n",entry->body.zebra_message.source_as);
	                    }
			    if (entry->body.zebra_message.destination_as)
		            {
				printf("TO:");
				switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							inet_ntop(AF_INET6,&entry->body.zebra_message.destination_ip.v6_addr,prefix,sizeof(prefix));
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
		    		printf("AS%d\n",entry->body.zebra_message.destination_as);
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

			    	printf("TYPE: BGP4MP/MESSAGE/Keepalive\n");
				if (entry->body.zebra_message.source_as)
				{
					printf("FROM:");
					switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip.v6_addr,prefix,sizeof(prefix));
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
					printf("AS%d\n",entry->body.zebra_message.source_as);
				}
				if (entry->body.zebra_message.destination_as)
				{
					printf("TO:");
					switch(entry->body.zebra_message.address_family)
					{
#ifdef BGPDUMP_HAVE_IPV6
						case AFI_IP6:

							inet_ntop(AF_INET6,&entry->body.zebra_message.destination_ip.v6_addr,prefix,sizeof(prefix));
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
		    			printf("AS%d\n",entry->body.zebra_message.destination_as);
				}


			    	break;
		    }
		    break;

		case BGPDUMP_SUBTYPE_ZEBRA_BGP_STATE_CHANGE:
		    if (mode==0)
		    {
		    	printf("TYPE: BGP4MP/STATE_CHANGE\n");

		    	printf("PEER:");
			switch(entry->body.zebra_state_change.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:

				inet_ntop(AF_INET6,&entry->body.zebra_state_change.source_ip.v6_addr,prefix,sizeof(prefix));
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
		    	printf("AS%d\n",entry->body.zebra_state_change.source_as);

		    	printf("STATE: %s/%s\n",bgp_state_name[entry->body.zebra_state_change.old_state],bgp_state_name[entry->body.zebra_state_change.new_state]);
		    }
		    else if (mode==1 || mode==2 ) //-m -M
		    {
			switch(entry->body.zebra_state_change.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
				case AFI_IP6:

					inet_ntop(AF_INET6,&entry->body.zebra_state_change.source_ip.v6_addr,prefix,sizeof(prefix));
					if (mode == 1)
						printf("BGP4MP|%ld|STATE|%s|%d|%d|%d\n",entry->time,prefix,entry->body.zebra_state_change.source_as,entry->body.zebra_state_change.old_state,entry->body.zebra_state_change.new_state);
					else
						printf("BGP4MP|%s|STATE|%s|%d|%d|%d\n",time_str,prefix,entry->body.zebra_state_change.source_as,entry->body.zebra_state_change.old_state,entry->body.zebra_state_change.new_state);
					break;
#endif
				case AFI_IP:
				default:
					if (mode == 1)
						printf("BGP4MP|%ld|STATE|%s|%d|%d|%d\n",entry->time,inet_ntoa(entry->body.zebra_state_change.source_ip.v4_addr),entry->body.zebra_state_change.source_as,entry->body.zebra_state_change.old_state,entry->body.zebra_state_change.new_state);
					else
						printf("BGP4MP|%s|STATE|%s|%d|%d|%d\n",time_str,inet_ntoa(entry->body.zebra_state_change.source_ip.v4_addr),entry->body.zebra_state_change.source_as,entry->body.zebra_state_change.old_state,entry->body.zebra_state_change.new_state);
					break;

			}
		    }
		    break;
		
	    } 
	    break;
    }
    if (mode==0)
    	printf("\n");
}

void show_attr(struct attr *attr) {
    
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
		    printf("MULTI_EXIT_DISC: %d\n",attr->med);

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) !=0)		
		    printf("LOCAL_PREF: %d\n",attr->local_pref);

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE) ) !=0)	
		    printf("ATOMIC_AGGREGATE\n");

	    if( (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR) ) !=0)		
		    printf("AGGREGATOR: AS%d %s\n",attr->aggregator_as,inet_ntoa(attr->aggregator_addr));

	    if (attr->unknown_num)
	    {
		    u_int32_t index,len;
		    u_char *p;
		    
		    for (index=0;index<attr->unknown_num;index++)
		    {
			    printf("   UNKNOWN_ATTR :");
			    p = attr->unknown[index].raw;
			    if(p[0] & BGP_ATTR_FLAG_EXTLEN) {
				len = attr->unknown[index].real_len + 4;
			    } else {
				len = attr->unknown[index].real_len + 3;
			    }

			    while (len) {
				printf(" %02x", *p);
				p++;
				len--;
			    }
			    printf("\n");
		    }
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
			   	   printf("NEXT_HOP: %s\n",inet_ntop(AF_INET6,&attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop.v6_addr,buf,128));
			           if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_len==32)
					printf("NEXT_HOP: %s\n",inet_ntop(AF_INET6,&attr->mp_info->announce[AFI_IP6][SAFI_UNICAST]->nexthop_local.v6_addr,buf,128));
			   }
			   else if (attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST])	 
		  	   {
			   	   printf("(IPv6 Multicast)\n");
				   printf("NEXT_HOP: %s\n",inet_ntop(AF_INET6,&attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop.v6_addr,buf,128));
			           if (attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop_len==32)
					printf("NEXT_HOP: %s\n",inet_ntop(AF_INET6,&attr->mp_info->announce[AFI_IP6][SAFI_MULTICAST]->nexthop_local.v6_addr,buf,128));

		           }
			   else
		           {
				   printf("(IPv6 Both unicast and multicast)\n");
				   printf("NEXT_HOP: %s\n",inet_ntop(AF_INET6,&attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop.v6_addr,buf,128));
			           if (attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop_len==32)
					printf("NEXT_HOP: %s\n",inet_ntop(AF_INET6,&attr->mp_info->announce[AFI_IP6][SAFI_UNICAST_MULTICAST]->nexthop_local.v6_addr,buf,128));


			   }
		    }
		    else
#endif
		    {
			   
			   if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST])
			   {
				   printf("(IPv4 Unicast)\n");
				   printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop.v4_addr));
			           if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_len==32)
					printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_UNICAST]->nexthop_local.v4_addr));
			  
			   }
			   else if (attr->mp_info->announce[AFI_IP][SAFI_MULTICAST])	 
		  	   {
			   	   printf("(IPv4 Multicast)\n");
			           printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop.v4_addr));
			           if (attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop_len==32)
					printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_MULTICAST]->nexthop_local.v4_addr));
			  
		
		           }
			   else if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST])
		           {
				   printf("(IPv4 Both unicast and multicast)\n");
				   printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop.v4_addr));
			           if (attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop_len==32)
					printf("NEXT_HOP: %s\n",inet_ntoa(attr->mp_info->announce[AFI_IP][SAFI_UNICAST_MULTICAST]->nexthop_local.v4_addr));
			  

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
    }
 
}

void show_prefixes(int count,struct prefix *prefix) {
    int i;
    for(i=0;i<count;i++)
	printf("  %s/%d\n",inet_ntoa(prefix[i].address.v4_addr),prefix[i].len);
}
#ifdef BGPDUMP_HAVE_IPV6
void show_prefixes6(int count,struct prefix *prefix)
{
	int i;
	char buf[128];

	for (i=0;i<count;i++)
	 printf("  %s/%d\n",inet_ntop(AF_INET6,&prefix[i].address.v6_addr,buf,128),prefix[i].len);
}
#endif


void table_line_withdraw(int mode,struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int index;
	char buf[128];
	
	for (index=0;index<count;index++)
	{
		if (mode==1)
		{
			switch(entry->body.zebra_message.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				printf("BGP4MP|%ld|W|%s|%d|",entry->time,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip.v6_addr,buf,128),entry->body.zebra_message.source_as);
				break;
#endif
			case AFI_IP:
			default:
				printf("BGP4MP|%ld|W|%s|%d|",entry->time,inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as);
				break;
			}
			printf("%s/%d\n",inet_ntoa(prefix[index].address.v4_addr),prefix[index].len);
		}
		else
		{
			switch(entry->body.zebra_message.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				printf("BGP4MP|%s|W|%s|%d|",time_str,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip.v6_addr,buf,128),entry->body.zebra_message.source_as);
				break;
#endif
			case AFI_IP:
			default:
				printf("BGP4MP|%s|W|%s|%d|",time_str,inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as);
				break;
			}
			printf("%s/%d\n",inet_ntoa(prefix[index].address.v4_addr),prefix[index].len);
		}
		
	}
}

#ifdef BGPDUMP_HAVE_IPV6

void table_line_withdraw6(int mode,struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int index;
	char buf[128];
	char buf1[128];

	for (index=0;index<count;index++)
	{
		if (mode==1)
		{
			switch(entry->body.zebra_message.address_family)
			{
			case AFI_IP6:
				printf("BGP4MP|%ld|W|%s|%d|%s/%d\n",entry->time,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf1,128),entry->body.zebra_message.source_as,inet_ntop(AF_INET6,&prefix[index].address.v6_addr,buf,128),prefix[index].len);
				break;
			case AFI_IP:
			default:
				printf("BGP4MP|%ld|W|%s|%d|%s/%d\n",entry->time,inet_ntop(AF_INET,&entry->body.zebra_message.source_ip,buf1,128),entry->body.zebra_message.source_as,inet_ntop(AF_INET6,&prefix[index].address.v6_addr,buf,128),prefix[index].len);
				break;
			}
		}	
		else
		{
			switch(entry->body.zebra_message.address_family)
			{
			case AFI_IP6:
				printf("BGP4MP|%s|W|%s|%d|%s/%d\n",time_str,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf1,128),entry->body.zebra_message.source_as,inet_ntop(AF_INET6,&prefix[index].address.v6_addr,buf,128),prefix[index].len);
				break;
			case AFI_IP:
			default:
				printf("BGP4MP|%s|W|%s|%d|%s/%d\n",time_str,inet_ntop(AF_INET,&entry->body.zebra_message.source_ip,buf1,128),entry->body.zebra_message.source_as,inet_ntop(AF_INET6,&prefix[index].address.v6_addr,buf,128),prefix[index].len);
				break;
			}
		}

	}
}
#endif

void table_line_announce(int mode,struct prefix *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int index  ;
	char buf[128];
	//char buf1[128];
	//char buf2[128];
	char tmp1[20];
	char tmp2[20];
	int  npref;
	int  nmed;
				
	switch (entry->attr->origin)
	{

	case 0 :
		sprintf(tmp1,"IGP");
		break;
	case 1:
		sprintf(tmp1,"EGP");
		break;
	case 2:
	default:
		sprintf(tmp1,"INCOMPLETE");
		break;
	}
	if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
		sprintf(tmp2,"AG");
	else
		sprintf(tmp2,"NAG");

	for (index=0;index<count;index++)
	{
		if (mode == 1)
		{
			switch(entry->body.zebra_message.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				printf("BGP4MP|%ld|A|%s|%d|",entry->time,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf,128),entry->body.zebra_message.source_as);
				break;
#endif
			case AFI_IP:
			default:
				printf("BGP4MP|%ld|A|%s|%d|",entry->time,inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as);
				break;
			}
			printf("%s/%d|%s|%s|",inet_ntoa(prefix[index].address.v4_addr),prefix[index].len,entry->attr->aspath->str,tmp1);
		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
			printf("%s|%d|%d|",inet_ntoa(entry->attr->nexthop),npref,nmed);
			if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    		printf("%s|%s|",entry->attr->community->str+1,tmp2);
			else
				printf("|%s|",tmp2);
				
			if (entry->attr->aggregator_addr.s_addr != -1)
				printf("%d %s|\n",entry->attr->aggregator_as,inet_ntoa(entry->attr->aggregator_addr));
			else
				printf("|\n");
		}
		else
		{
			switch(entry->body.zebra_message.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				printf("BGP4MP|%s|A|%s|%d|",time_str,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf,128),entry->body.zebra_message.source_as);
				break;
#endif
			case AFI_IP:
			default:
				printf("BGP4MP|%s|A|%s|%d|",time_str,inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as);
				break;
			}
			printf("%s/%d|%s|%s\n",inet_ntoa(prefix[index].address.v4_addr),prefix[index].len,entry->attr->aspath->str,tmp1);
				
		}
	}

}
void table_line_announce_1(int mode,struct mp_nlri *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int index  ;
	char buf[128];
	//char buf1[128];
	//char buf2[128];
	char tmp1[20];
	char tmp2[20];
	int  npref;
	int  nmed;
				
	switch (entry->attr->origin)
	{

	case 0 :
		sprintf(tmp1,"IGP");
		break;
	case 1:
		sprintf(tmp1,"EGP");
		break;
	case 2:
	default:
		sprintf(tmp1,"INCOMPLETE");
		break;
	}
	if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
		sprintf(tmp2,"AG");
	else
		sprintf(tmp2,"NAG");

	for (index=0;index<count;index++)
	{
		if (mode == 1)
		{
			if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MP_REACH_NLRI))
			{
				switch(entry->body.zebra_message.address_family)
				{
#ifdef BGPDUMP_HAVE_IPV6
				case AFI_IP6:
					printf("BGP4MP|%ld|A|%s|%d|",entry->time,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf,128),entry->body.zebra_message.source_as);
					break;
#endif
				case AFI_IP:
				default:
					printf("BGP4MP|%ld|A|%s|%d|",entry->time,inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as);
					break;
				}
				printf("%s/%d|%s|%s|",inet_ntoa(prefix->nlri[index].address.v4_addr),prefix->nlri[index].len,entry->attr->aspath->str,tmp1);

		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
			printf("%s|%d|%d|",inet_ntoa(entry->attr->nexthop),npref,nmed);
				//printf("%s|%d|%d|",inet_ntoa(prefix->nexthop.v4_addr),entry->attr->local_pref,entry->attr->med);
				if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    			printf("%s|%s|",entry->attr->community->str+1,tmp2);
				else
					printf("|%s|",tmp2);

			}
			else 
			{
				switch(entry->body.zebra_message.address_family)
				{
#ifdef BGPDUMP_HAVE_IPV6
				case AFI_IP6:
					printf("BGP4MP|%ld|A|%s|%d|",entry->time,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf,128),entry->body.zebra_message.source_as);
					break;
#endif
				case AFI_IP:
				default:
					printf("BGP4MP|%ld|A|%s|%d|",entry->time,inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as);
					break;
				}
				printf("%s/%d|%s|%s|",inet_ntoa(prefix->nlri[index].address.v4_addr),prefix->nlri[index].len,entry->attr->aspath->str,tmp1);

		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
			printf("%s|%d|%d|",inet_ntoa(entry->attr->nexthop),npref,nmed);
				//printf("%s|%d|%d|",inet_ntoa(entry->attr->nexthop),entry->attr->local_pref,entry->attr->med);
				if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    			printf("%s|%s|",entry->attr->community->str+1,tmp2);
				else
					printf("|%s|",tmp2);


			}
			if (entry->attr->aggregator_addr.s_addr != -1)
				printf("%d %s|\n",entry->attr->aggregator_as,inet_ntoa(entry->attr->aggregator_addr));
			else
				printf("|\n");
		}
		else
		{
			switch(entry->body.zebra_message.address_family)
			{
#ifdef BGPDUMP_HAVE_IPV6
			case AFI_IP6:
				printf("BGP4MP|%s|A|%s|%d|",time_str,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf,128),entry->body.zebra_message.source_as);
				break;
#endif
			case AFI_IP:
			default:
				printf("BGP4MP|%s|A|%s|%d|",time_str,inet_ntoa(entry->body.zebra_message.source_ip.v4_addr),entry->body.zebra_message.source_as);
				break;
			}
			printf("%s/%d|%s|%s\n",inet_ntoa(prefix->nlri[index].address.v4_addr),prefix->nlri[index].len,entry->attr->aspath->str,tmp1);
				
		}
	}

}

#ifdef BGPDUMP_HAVE_IPV6
void table_line_announce6(int mode,struct mp_nlri *prefix,int count,BGPDUMP_ENTRY *entry,char *time_str)
{
	int index  ;
	char buf[128];
	char buf1[128];
	char buf2[128];
	char tmp1[20];
	char tmp2[20];
	int  npref;
	int  nmed;
				
	switch (entry->attr->origin)
	{

	case 0 :
		sprintf(tmp1,"IGP");
		break;
	case 1:
		sprintf(tmp1,"EGP");
		break;
	case 2:
	default:
		sprintf(tmp1,"INCOMPLETE");
		break;
	}
	if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
		sprintf(tmp2,"AG");
	else
		sprintf(tmp2,"NAG");

	for (index=0;index<count;index++)
	{
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
			    
				printf("BGP4MP|%ld|A|%s|%d|%s/%d|%s|%s|%s|%d|%d|",entry->time,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf1,128),entry->body.zebra_message.source_as,inet_ntop(AF_INET6,&prefix->nlri[index].address.v6_addr,buf2,128),prefix->nlri[index].len,entry->attr->aspath->str,tmp1,inet_ntop(AF_INET6,&prefix->nexthop,buf,128),npref,nmed);
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
				printf("BGP4MP|%ld|A|%s|%d|%s/%d|%s|%s|%s|%d|%d|",entry->time,inet_ntop(AF_INET,&entry->body.zebra_message.source_ip,buf1,128),entry->body.zebra_message.source_as,inet_ntop(AF_INET6,&prefix->nlri[index].address.v6_addr,buf2,128),prefix->nlri[index].len,entry->attr->aspath->str,tmp1,inet_ntop(AF_INET6,&prefix->nexthop,buf,128),npref,nmed);
				break;
			}
			if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    		printf("%s|%s|",entry->attr->community->str+1,tmp2);
			else
				printf("|%s|",tmp2);


			if (entry->attr->aggregator_addr.s_addr != -1)
				printf("%d %s|\n",entry->attr->aggregator_as,inet_ntoa(entry->attr->aggregator_addr));
			else
				printf("|\n");

		}
		else
		{
			switch(entry->body.zebra_message.address_family)
			{
			case AFI_IP6:
				printf("BGP4MP|%s|A|%s|%d|%s/%d|%s|%s\n",time_str,inet_ntop(AF_INET6,&entry->body.zebra_message.source_ip,buf1,128),entry->body.zebra_message.source_as,inet_ntop(AF_INET6,&prefix->nlri[index].address.v6_addr,buf,128),prefix->nlri[index].len,entry->attr->aspath->str,tmp1);
				break;
			case AFI_IP:
			default:
				printf("BGP4MP|%s|A|%s|%d|%s/%d|%s|%s\n",time_str,inet_ntop(AF_INET,&entry->body.zebra_message.source_ip,buf1,128),entry->body.zebra_message.source_as,inet_ntop(AF_INET6,&prefix->nlri[index].address.v6_addr,buf,128),prefix->nlri[index].len,entry->attr->aspath->str,tmp1);
				break;
			}
		}		

	}

}
#endif


void table_line_mrtd_route(int mode,BGPDUMP_MRTD_TABLE_DUMP *route,BGPDUMP_ENTRY *entry,int timetype)
{
	
	struct tm *time;
	char tmp1[20];
	char tmp2[20];	
	int  npref;
	int  nmed;
	char  time_str[10];
        char peer[BGPDUMP_ADDRSTRLEN], prefix[BGPDUMP_ADDRSTRLEN];

	switch (entry->attr->origin)
	{

	case 0 :
		sprintf(tmp1,"IGP");
		break;
	case 1:
		sprintf(tmp1,"EGP");
		break;
	case 2:
	default:
		sprintf(tmp1,"INCOMPLETE");
		break;
	}
	if (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
		sprintf(tmp2,"AG");
	else
		sprintf(tmp2,"NAG");

#ifdef BGPDUMP_HAVE_IPV6
	    	if (entry->subtype == AFI_IP6)
		{
		    strncpy(peer, inet_ntop(AF_INET6,&route->peer_ip.v6_addr,peer,sizeof(peer)), BGPDUMP_ADDRSTRLEN);
		    strncpy(prefix, inet_ntop(AF_INET6,&route->prefix.v6_addr,prefix,sizeof(prefix)), BGPDUMP_ADDRSTRLEN);
		}
	    	else
#endif
                {
		    strncpy(peer, inet_ntoa(route->peer_ip.v4_addr), BGPDUMP_ADDRSTRLEN);
                    strncpy(prefix, inet_ntoa(route->prefix.v4_addr), BGPDUMP_ADDRSTRLEN);
		}

		if (mode == 1)
		{
		   if(timetype==0){
	   	   printf("TABLE_DUMP|%ld|B|%s|%d|",entry->time,peer,route->peer_as);
		   }else if(timetype==1){
	   	   printf("TABLE_DUMP|%ld|B|%s|%d|",route->uptime,peer,route->peer_as);
		   }
	      	   printf("%s/%d|%s|%s|",prefix,route->mask,entry->attr->aspath->str,tmp1);

		    npref=entry->attr->local_pref;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF) ) ==0)
	            npref=0;
		    nmed=entry->attr->med;
	            if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ) ==0)
	            nmed=0;
			    
		   printf("%s|%d|%d|",inet_ntoa(entry->attr->nexthop),npref,nmed);
		   if( (entry->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES) ) !=0)	
		    		printf("%s|%s|",entry->attr->community->str+1,tmp2);
			else
				printf("|%s|",tmp2);
				
			if (entry->attr->aggregator_addr.s_addr != -1)
				printf("%d %s|\n",entry->attr->aggregator_as,inet_ntoa(entry->attr->aggregator_addr));
			else
				printf("|\n");
		}
		else
		{
                    if(timetype==0){
                        time=gmtime(&entry->time);
		    }else if(timetype==1){
			time=gmtime(&route->uptime);
		    }
	            time2str(time,time_str);	
	 	    printf("TABLE_DUMP|%s|A|%s|%d|",time_str,peer,route->peer_as);
			printf("%s/%d|%s|%s\n",prefix,route->mask,entry->attr->aspath->str,tmp1);
				
		}

}