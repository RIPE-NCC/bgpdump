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
*/

/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * Copyright 1994, 1995 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "util.h"

const char OCTETS[][4] = {        
     "0",  "1",  "2",  "3",  "4",  "5",  "6",  "7",  "8",  "9", "10", "11", "12", "13", "14", "15",
    "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31",
    "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63",
    "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79",
    "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95",
    "96", "97", "98", "99",
    "100", "101", "102", "103", "104", "105", "106", "107", "108", "109",
    "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122",
    "123", "124", "125", "126", "127", "128", "129", "130", "131", "132", "133", "134", "135",
    "136", "137", "138", "139", "140", "141", "142", "143", "144", "145", "146", "147", "148",
    "149", "150", "151", "152", "153", "154", "155", "156", "157", "158", "159", "160", "161",
    "162", "163", "164", "165", "166", "167", "168", "169", "170", "171", "172", "173", "174",
    "175", "176", "177", "178", "179", "180", "181", "182", "183", "184", "185", "186", "187", 
    "188", "189", "190", "191", "192", "193", "194", "195", "196", "197", "198", "199", "200",
    "201", "202", "203", "204", "205", "206", "207", "208", "209", "210", "211", "212", "213",
    "214", "215", "216", "217", "218", "219", "220", "221", "222", "223", "224", "225", "226",
    "227", "228", "229", "230", "231", "232", "233", "234", "235", "236", "237", "238", "239",
    "240", "241", "242", "243", "244", "245", "246", "247", "248", "249", "250", "251", "252",
    "253", "254", "255"
};

char *fmt_ipv4(BGPDUMP_IP_ADDRESS addr, char *buffer)
{
    assert(buffer);
    uint8_t *ap = (uint8_t *)&addr.v4_addr.s_addr;
    
    int pos = 0;
    int i;
    for(i = 0; i < 4; ++i) {
        const char *octet = OCTETS[ap[i]];
        buffer[pos++] = octet[0];
        octet[1] ? buffer[pos++] = octet[1] : (void)0;
        octet[2] ? buffer[pos++] = octet[2] : (void)0;
        buffer[pos++] = '.';
    }
    
    buffer[pos - 1] = '\0';
    
    return buffer;
}

char *fmt_ipv6(BGPDUMP_IP_ADDRESS addr, char *buffer)
{    
    static const char hexchars[] = "0123456789abcdef";

    assert(buffer);
        
    /*  check for mapped or compat addresses */
    bool m = IN6_IS_ADDR_V4MAPPED(&addr.v6_addr);
    bool c = IN6_IS_ADDR_V4COMPAT(&addr.v6_addr);
    if (m || c) {
        char buffer2[100];
        BGPDUMP_IP_ADDRESS mapped = { .v4_addr.s_addr = ((uint32_t *)addr.v6_addr.s6_addr)[3] };
        
        sprintf(buffer, "::%s%s", m ? "ffff:" : "", fmt_ipv4(mapped, buffer2));
        return buffer;
    }
    
    char hexa[8][5];
    int zr[8];
    size_t len;
    uint8_t x8, hx8;
    uint16_t x16;
    
    int i, k = 0;
    for (i = 0; i < 16; i += 2) {
        int j = 0;
        bool skip = 1;
        
        memset(hexa[k], 0, 5);
        
        x8 = addr.v6_addr.s6_addr[i];
        
        hx8 = x8 >> 4;
        if (hx8 != 0)
        {
            skip = 0;
            hexa[k][j++] = hexchars[hx8];
        }
        
        hx8 = x8 & 0x0f;
        if ((skip == 0) || ((skip == 1) && (hx8 != 0)))
        {
            skip = 0;
            hexa[k][j++] = hexchars[hx8];
        }
        
        x8 = addr.v6_addr.s6_addr[i + 1];
        
        hx8 = x8 >> 4;
        if ((skip == 0) || ((skip == 1) && (hx8 != 0)))
        {
            hexa[k][j++] = hexchars[hx8];
        }
        
        hx8 = x8 & 0x0f;
        hexa[k][j] = hexchars[hx8];
        
        k++;
    }
    
    /* find runs of zeros for :: convention */
    int j = 0;
    for (i = 7; i >= 0; i--)
    {
        zr[i] = j;
        x16 = ((uint16_t *)addr.v6_addr.s6_addr)[i];
        if (x16 == 0) j++;
        else j = 0;
        zr[i] = j;
    }
    
    /* find longest run of zeros */
    k = -1;
    j = 0;
    for(i = 0; i < 8; i++)
    {
        if (zr[i] > j)
        {
            k = i;
            j = zr[i];
        }
    }
    
    for(i = 0; i < 8; i++)
    {
        if (i != k) zr[i] = 0;
    }
    
    len = 0;
    for (i = 0; i < 8; i++)
    {
        if (zr[i] != 0)
        {
            /* check for leading zero */
            if (i == 0)
                buffer[len++] = ':';
            buffer[len++] = ':';
            i += (zr[i] - 1);
            continue;
        }
        for (j = 0; hexa[i][j] != '\0'; j++)
            buffer[len++] = hexa[i][j];
        if (i != 7)
            buffer[len++] = ':';
    }
    
    buffer[len] = '\0';
    
    return buffer;
}

static void test_roundtrip(char *str)
{
    BGPDUMP_IP_ADDRESS addr;
    inet_pton(AF_INET6, str, &addr.v6_addr);
    char tmp[1000];
    fmt_ipv6(addr, tmp);
    printf("%s -> %s [%s]\n", str, tmp, strcmp(str, tmp) ? "ERROR" : "ok");
}

void test_fmt_ip()
{
    test_roundtrip("fe80::");
    test_roundtrip("2001:db8::1");
    test_roundtrip("::ffff:192.168.2.1");
    test_roundtrip("::192.168.1.2");
    test_roundtrip("2001:7f8:30::2:1:0:8447");
}
