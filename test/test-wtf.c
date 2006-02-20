/*
 * This file is part of libtrace
 *
 * Copyright (c) 2004 The University of Waikato, Hamilton, New Zealand.
 * Authors: Daniel Lawson 
 *          Perry Lorier 
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include "dagformat.h"
#include "libtrace.h"

struct libtrace_t *trace;

int main(int argc, char *argv[]) {
        char *uri = "wtf:traces/wed.wtf";
        int psize = 0;
	int error = 0;
	int count = 0;
	struct libtrace_packet_t *packet;

	trace = trace_create(uri);
	if (!trace) {
		printf("ERROR: %s\n",trace_err.problem);
		return 1;
	}

	if (trace_start(trace)==-1) {
		printf("ERROR: %s\n",trace_err.problem);
		return 1;
	}
	
	packet = trace_create_packet();
        for (;;) {
		if ((psize = trace_read_packet(trace, packet)) <0) {
			error = 1;
			break;
		}
		if (psize == 0) {
			error = 0;
			break;
		}
		count ++;
        }
	trace_destroy_packet(&packet);
	if (error == 0) {
		if (count == 100) {
			printf("success: 100 packets read\n");
		} else {
			printf("failure: 100 packets expected, %d seen\n",count);
			error = 1;
		}
	} else {
		printf("failure: %s\n",trace_err.problem);
	}
        trace_destroy(trace);
        return error;
}
