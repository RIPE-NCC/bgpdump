# $Id$

CC	= gcc
CFLAGS	=  -Wall -Wcast-align -O3
INCLUDES = -I./
COMPILE  = $(CC) $(CFLAGS) $(INCLUDES)

LD	= gcc
LDFLAGS	= 
AR	= /usr/bin/ar
RANLIB	= ranlib

SYS_LIBS= -lz 

LIB_H	 = bgpdump.h bgpdump_attr.h bgpdump_formats.h bgpdump_lib.h bgpdump_mstream.h
LIB_C    = bgpdump_lib.c bgpdump_mstream.c
LIB_O	 = bgpdump_lib.o bgpdump_mstream.o

all: libbgpdump.so libbgpdump.a testbgpdump bgpdump 

libbgpdump.so: $(LIB_H) $(LIB_C) Makefile
	$(COMPILE) -fpic -c $(LIB_C)
	$(COMPILE) -shared -o libbgpdump.so $(LIB_O) $(SYS_LIBS)

libbgpdump.a: $(LIB_H) $(LIB_C) $(LIB_O) Makefile
	$(AR) r libbgpdump.a $(LIB_O)
	$(RANLIB) libbgpdump.a

testbgpdump: test.c $(LIB_H) $(LIB_C) Makefile
	$(COMPILE) -o testbgpdump test.c libbgpdump.a $(SYS_LIBS)

bgpdump: bgpdump.c $(LIB_H) $(LIB_C) Makefile
	$(COMPILE) -o bgpdump bgpdump.c libbgpdump.a $(SYS_LIBS)

clean:
	rm -f libbgpdump.so libbgpdump.a testbgpdump bgpdump *.o 
