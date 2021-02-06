#define __GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <libgen.h>
#include <string.h>
#include <pthread.h>
#include <sys/random.h>
#include <time.h>

#include <ioth.h>
#include <iothconf.h>
#include <iothdns.h>

#include "udp_dns.h"
#include "parse_dns.h"
#include "config.h"
#include "utils.h"
#include "const.h"


struct ioth* server_stack = NULL;
struct ioth* fwd_stack = NULL;
struct ioth* query_stack = NULL;

struct iothdns* qdns;

int auth = 1;
int verbose = 0;

//#################


void printusage(char *progname){
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--help|-h\n"
			"\t--verbose|-v\n"
			"\t--stacks|-s //Create virtual stacks according to sconfig.txt file\n"
			"\t--reverse|-r //Set reverse resolution policy for hash addresses. Options are never, always, same and net, default is never.\n"
			"\t--auth|-a //Enable authentication\n",
			progname);
	exit(1);
}

void init_random(){
    unsigned int seed;
    if(getrandom(&seed, sizeof(unsigned int), 0) == 0){
        srandom(seed);
    } else {
        srandom(time(NULL) ^ getpid());
    }
}

int main(int argc, char** argv){
    pthread_t udp_t, tcp_t;
    char* progname = basename(argv[0]);
	static char *short_options = "hvsa";
	static struct option long_options[] = {
		{"help", no_argument , 0, 'h'},
		{"verbose", no_argument , 0, 'v'},
		{"stacks", no_argument , 0, 's'},
		{"reverse", 1 , 0, 'r'},
		{"auth", no_argument , 0, 'a'},
		{0, 0, 0, 0}
	};
    load_fwdconfig();
	int option_index;
    while(1) {
        int c;
		c = getopt_long (argc, argv, short_options,
				long_options, &option_index);
        if(c < 0) break;
        switch (c){
            case 'h':
                printusage(progname);
                break;
            case 'v':
                verbose = 1;
                break;
            case 's':
				set_stacks();
                break;
            case 'r':
				if(set_reverse_policy(optarg))
					printusage(progname);
                break;
            case 'a':
				auth = 0;
				load_authconfig();
                break;
        }
    }
    //if no stack assigned manually, defaults to kernel
    if(server_stack == NULL) server_stack = ioth_newstack("kernel", NULL);
    if(fwd_stack == NULL) fwd_stack = ioth_newstack("kernel", NULL);
    if(query_stack == NULL) query_stack = ioth_newstack("kernel", NULL);
	
	//TODO is this the best way to prevent sigpipes happening when writing
	//on a tcp socket where peer closed connection?
	signal(SIGPIPE, SIG_IGN);

    qdns = iothdns_init(fwd_stack, "./config");  
    
    //server to be implemented as second thread
    pthread_create(&udp_t, 0, run_udp, NULL);    
    pthread_join(udp_t, NULL);
}

