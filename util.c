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
 
 Created by Devin Bayer on 9/1/10.
*/

#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <stdbool.h>
#include <syslog.h>
#include <time.h>
#include <string.h>

static bool use_syslog = true;

void log_to_syslog() {
    use_syslog = true;
}

void log_to_stderr() {
    use_syslog = false;
}

#define log(lvl, lvl_str) \
    va_list args; \
    va_start(args, fmt); \
    _log(LOG_##lvl, #lvl_str, fmt, args)

static char *now_str() {
    static char buffer[1000];
    time_t now = time(0);
    strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%S", localtime(&now));
    return buffer;
}

static void _log(int lvl, char *lvl_str, const char *fmt, va_list args) {
    if(use_syslog) {
        syslog(lvl, fmt, args);
    } else {
        char prefix[strlen(fmt) + 1000];
        sprintf(prefix, "%s [%s] %s\n", now_str(), lvl_str, fmt);
        vfprintf(stderr, prefix, args);
    }
}

void err(const char *fmt, ...) { log(ERR, error); }
void warn(const char *fmt, ...) { log(WARNING, warn); }
void debug(const char *fmt, ...) { log(INFO, info); }

int time2str(struct tm* date,char *time_str)
{
    return sprintf(time_str, "%02d/%02d/%02d %02d:%02d:%02d", date->tm_mon+1, date->tm_mday, date->tm_year%100,
            date->tm_hour, date->tm_min, date->tm_sec);
}

int int2str(uint32_t value, char* str)
{
    return sprintf(str, "%u", value);
}

static void ti2s(uint32_t value) {
    char buf[100], ref[100];
    sprintf(ref, "%u", value);
    int len = int2str(value, buf);
    printf("%s =?= %s (%i)\n", ref, buf, len);
}

void test_utils()
{
    ti2s(0);
    ti2s(99999);
    ti2s(4294967295L);
}

