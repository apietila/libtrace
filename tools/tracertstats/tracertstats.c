/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007 The University of Waikato, Hamilton, New Zealand.
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

/* This program takes a series of traces and bpf filters and outputs how many
 * bytes/packets every time interval
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
#include <getopt.h>
#include <inttypes.h>
#include <lt_inttypes.h>

#include "libtrace.h"
#include "output.h"
#include "rt_protocol.h"
#include "dagformat.h"

#ifndef UINT32_MAX
    #define UINT32_MAX      0xffffffffU
#endif

#define DEFAULT_OUTPUT_FMT "txt"

struct libtrace_t *trace;
char *output_format=NULL;

int merge_inputs = 0;

int report_directions = 0;

int report_rel_time = 0;

// stats per filter / report period
struct filter_t {
    char *expr;
    struct libtrace_filter_t *filter;
    uint64_t count;
    uint64_t bytes;
    uint64_t count_in;
    uint64_t bytes_in;
    uint64_t count_out;
    uint64_t bytes_out;
} *filters = NULL;
int filter_count=0;

// totals (since start and period)
struct {
    uint64_t count;
    uint64_t bytes;
    uint64_t count_in;
    uint64_t bytes_in;
    uint64_t count_out;
    uint64_t bytes_out;
} totals;

// packets per report (define this or interval)
uint64_t packet_count=UINT64_MAX;
// report interval (in seconds)
double packet_interval=UINT32_MAX;
// number of report periods (default infinite)
uint64_t report_periods=UINT64_MAX;
uint64_t reported=0;

struct output_data_t *output = NULL;

static void report_results(double ts)
{
    int i=0;
    int cols = 2;
    output_set_data_time(output,0,ts);
    output_set_data_int(output,1,totals.count);
    output_set_data_int(output,2,totals.bytes);
    totals.count=totals.bytes=0;

    if (report_directions) {
        output_set_data_int(output,3,totals.count_in);
        output_set_data_int(output,4,totals.bytes_in);
        output_set_data_int(output,5,totals.count_out);
        output_set_data_int(output,6,totals.bytes_out);
        cols = 6;
	totals.count_in=totals.bytes_in=0;
	totals.count_out=totals.bytes_out=0;
    }

    for(i=0;i<filter_count;++i) {
        output_set_data_int(output,i*cols+cols+1,filters[i].count);
        output_set_data_int(output,i*cols+cols+2,filters[i].bytes);
        filters[i].count=filters[i].bytes=0;

        if (report_directions) {
            output_set_data_int(output,i*cols+cols+3,filters[i].count_in);
            output_set_data_int(output,i*cols+cols+4,filters[i].bytes_in);
            output_set_data_int(output,i*cols+cols+5,filters[i].count_out);
            output_set_data_int(output,i*cols+cols+6,filters[i].bytes_out);
            filters[i].count_in=filters[i].bytes_in=0;
            filters[i].count_out=filters[i].bytes_out=0;
        }
    }
    output_flush_row(output);
    ++reported;
}

static void create_output(char *title) {
    int i;
    
    output=output_init(title,output_format?output_format:DEFAULT_OUTPUT_FMT);
    if (!output) {
        fprintf(stderr,"Failed to create output file\n");
        return;
    }

    output_add_column(output,"ts");
    output_add_column(output,"packets");
    output_add_column(output,"bytes");
    if (report_directions) {
        output_add_column(output,"packets in");
        output_add_column(output,"bytes in");
        output_add_column(output,"packets out");
        output_add_column(output,"bytes out");      
    }

    for(i=0;i<filter_count;++i) {
        char buff[2048];
        snprintf(buff,sizeof(buff),"%s packets",filters[i].expr);
        output_add_column(output,buff);
        snprintf(buff,sizeof(buff),"%s bytes",filters[i].expr);
        output_add_column(output,buff);

        if (report_directions) {
            snprintf(buff,sizeof(buff),"%s packets in",filters[i].expr);
            output_add_column(output,buff);
            snprintf(buff,sizeof(buff),"%s bytes in",filters[i].expr);
            output_add_column(output,buff);         
            snprintf(buff,sizeof(buff),"%s packets out",filters[i].expr);
            output_add_column(output,buff);
            snprintf(buff,sizeof(buff),"%s bytes out",filters[i].expr);
            output_add_column(output,buff);         
        }
    }
    output_flush_headings(output);
}

/* Process a trace, counting packets that match filter(s) */
static void run_trace(char *uri) 
{
    struct libtrace_packet_t *packet = trace_create_packet();
    int dir;
    int i;
    double last_ts = 0;
    double ts = 0;

    int report_in_time = (packet_interval != UINT32_MAX); 

    if (!merge_inputs) 
        create_output(uri);

    if (output == NULL) {
        fprintf(stderr,"no output!?!\n");        
        return;
    }

    trace = trace_create(uri);
    if (trace_is_err(trace)) {
        trace_perror(trace,"trace_create");
        trace_destroy(trace);
        if (!merge_inputs)
            output_destroy(output);
        return; 
    }
    if (trace_start(trace)==-1) {
        trace_perror(trace,"trace_start");
        trace_destroy(trace);
        if (!merge_inputs)
            output_destroy(output);
        return;
    }

    for (;;) {
        int psize;
        if ((psize = trace_read_packet(trace, packet)) <1) {
            fprintf(stderr,"trace_read_packet: %d\n",psize);
            break;
        }
        
        if (trace_get_packet_buffer(packet,NULL,NULL) == NULL) {
            continue;
        }
        
        ts = trace_get_seconds(packet);
        dir = trace_get_direction(packet);

        if (last_ts == 0) {
	  last_ts = ts;
        }

	// this will fill in all missed periods (because there
	// was no traffic)
        while (report_in_time && last_ts+packet_interval<ts) {
	  last_ts+=packet_interval;
	  if (report_rel_time) {
            report_results(packet_interval);
	  } else {
            report_results(last_ts);
	  }
	  if (report_periods != UINT64_MAX && 
	      reported >= report_periods) {
	    break;
	  }
        }
	if (report_periods != UINT64_MAX && 
	    reported >= report_periods) {
	  break;
	}

        for(i=0;i<filter_count;++i) {
            if(trace_apply_filter(filters[i].filter,packet)) {
                ++filters[i].count;
                filters[i].bytes+=trace_get_wire_length(packet);

                if (report_directions) {
                    if (dir == TRACE_DIR_OUTGOING) {
                        ++filters[i].count_out;
                        filters[i].bytes_out+=trace_get_wire_length(packet);
                    } else if (dir == TRACE_DIR_INCOMING) {
                        ++filters[i].count_in;
                        filters[i].bytes_in+=trace_get_wire_length(packet);
                    } // else unknown
                }
            }
        }

	// total stats
        totals.count++;
        totals.bytes+=trace_get_wire_length(packet);
        if (report_directions) {
            if (dir == TRACE_DIR_OUTGOING) {
	      totals.count_out++;
	      totals.bytes_out+=trace_get_wire_length(packet);
            } else if (dir == TRACE_DIR_INCOMING) {
	      totals.count_in++;
	      totals.bytes_in+=trace_get_wire_length(packet);
            }
        }

        if (!report_in_time && packet_count != UINT64_MAX && 
	    totals.count > 0 && 
	    totals.count%packet_count == 0) {
	  if (report_rel_time) {
            report_results(ts-last_ts);
	  } else {
            report_results(ts);
	  }
	  last_ts = ts;
	  if (report_periods != UINT64_MAX && 
	      reported >= report_periods) {
	    break;
	  }
        }
    }

    if (trace_is_err(trace))
        trace_perror(trace,"%s",uri);

    fprintf(stderr,"done!\n");

    trace_destroy(trace);

    if (!merge_inputs)
        output_destroy(output);

    trace_destroy_packet(packet);
}

static void usage(char *argv0)
{
    fprintf(stderr,"Usage:\n"
    "%s flags libtraceuri [libtraceuri...]\n"
    "-i --interval=seconds  Duration of reporting interval in seconds (default 10s)\n"
    "-c --count=packets     Duration of reporting interval in packets (can't be defined together with -i)\n"
    "-e --exit=periods      Exit after number of report periods (or never if missing)\n"
    "-d --direction         Report packets and bytes per direction (up/down)\n"
    "-r --relative          Report relative timestamps (useful for count based reporting)\n"
    "-o --output-format=txt|csv|html|png Reporting output format\n"
    "-f --filter=bpf        Apply BPF filter. Can be specified multiple times\n"
    "-m --merge-inputs      Do not create separate outputs for each input trace\n"
    "-H --libtrace-help     Print libtrace runtime documentation\n"
    ,argv0);
}

int main(int argc, char *argv[]) {

    int i;
    
    while(1) {
        int option_index;
        struct option long_options[] = {
	  { "filter",         1, 0, 'f' },
	  { "interval",       1, 0, 'i' },
	  { "count",          1, 0, 'c' },
	  { "exit",           1, 0, 'e' },
	  { "direction",      0, 0, 'd' },
	  { "relative",       0, 0, 'r' },
	  { "output-format",  1, 0, 'o' },
	  { "libtrace-help",  0, 0, 'H' },
	  { "merge-inputs",   0, 0, 'm' },
	  { NULL,             0, 0, 0   },
        };

        int c=getopt_long(argc, argv, "c:f:i:e:o:Hmdr",
                long_options, &option_index);

        if (c==-1)
            break;

        switch (c) {
            case 'f': 
                ++filter_count;
                filters=realloc(filters,filter_count*sizeof(struct filter_t));
                filters[filter_count-1].expr=strdup(optarg);
                filters[filter_count-1].filter=trace_create_filter(optarg);
                filters[filter_count-1].count=0;
                filters[filter_count-1].bytes=0;
                filters[filter_count-1].count_in=0;
                filters[filter_count-1].bytes_in=0;
                filters[filter_count-1].count_out=0;
                filters[filter_count-1].bytes_out=0;
                break;
            case 'i':
                packet_interval=atof(optarg);
		packet_count=UINT64_MAX; // make sure only one is defined
                break;
            case 'c':
                packet_count=atoi(optarg);
		packet_interval=UINT32_MAX; // make sure only one is defined
                break;
            case 'e':
                report_periods=atoi(optarg);
                break;
            case 'd':
                report_directions = 1;
                break;
            case 'r':
                report_rel_time = 1;
                break;
            case 'o':
                if (output_format) free(output_format);
                output_format=strdup(optarg);
                break;
            case 'm':
                merge_inputs = 1;
                break;
            case 'H': 
                  trace_help(); 
                  exit(1); 
                  break;    
            default:
                fprintf(stderr,"Unknown option: %c\n",c);
                usage(argv[0]);
                return 1;
        }
    }

    // default report period is every 10s
    if (packet_count == UINT64_MAX && packet_interval == UINT32_MAX) {
        packet_interval = 10; /* every 10 seconds */
    }

    if (optind >= argc)
        return 0;

    if (output_format)
        fprintf(stderr,"output format: '%s'\n",output_format);
    else
        fprintf(stderr,"output format: '%s'\n", DEFAULT_OUTPUT_FMT);
    
    if (merge_inputs) {
        /* If we're merging the inputs, we only want to create all
         * the column headers etc. once rather than doing them once
         * per trace */

        /* This is going to "name" the output based on the first 
         * provided URI - admittedly not ideal */
        create_output(argv[optind]);
        if (output == NULL) {
            return 0;
        }
    }
        
    for(i=optind;i<argc;++i) {
        fprintf(stderr,"processsing: '%s'\n", argv[i]);            
        run_trace(argv[i]);
    }

    if (merge_inputs) {
        /* Clean up after ourselves */
        output_destroy(output);
    }

    return 0;
}
