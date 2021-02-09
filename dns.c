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
#include "revdb.h"
#include "utils.h"
#include "const.h"


struct ioth* fwd_stack = NULL;
struct ioth* query_stack = NULL;

struct iothdns* qdns;

int auth = 1;
int verbose = 0;
int forwarding = 1;
long dnstimeout = TIMEOUT;

//#################


void printusage(char *progname){
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--help|-h\tPrint this help message.\n"
			"\t--verbose|-v\tEnable extensive program printing.\n"
			"\t--stacks|-s\tCreate virtual stacks according to stackconfig.txt file.\n"
			"\t--server|-S\tDisable forwarding in order to act as a no-recursion server.\n"
			"\t--reverse|-r\tSet reverse resolution policy for hash addresses.\n"
			"\t\t\tOptions are 'never', 'always', 'same' and 'net', default is 'always'.\n"
			"\t--timeout|-t\tSet request timeout in milliseconds (default is 1000).\n"
			"\t--revtimeout|-T\tSet reverse domain table expire time in seconds (default is 3600).\n"
			"\t--auth|-a\tEnable authorization mode according to authconfig.txt file.\n",
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
	static char *short_options = "r:t:T:hvsSa";
	static struct option long_options[] = {
		{"help", no_argument , 0, 'h'},
		{"verbose", no_argument , 0, 'v'},
		{"stacks", no_argument , 0, 's'},
		{"server", no_argument , 0, 'S'},
		{"reverse", 1 , 0, 'r'},
		{"timeout", 1 , 0, 't'},
		{"revtimeout", 1 , 0, 'T'},
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
            case 'S':
				forwarding = 0;
                break;
            case 'r':
				if(set_reverse_policy(optarg))
					printusage(progname);
                break;
            case 't':
				dnstimeout = atol(optarg);
                break;
            case 'T':
				ra_set_timeout(atoi(optarg));
                break;
            case 'a':
				auth = 0;
				load_authconfig();
                break;
        }
    }
    //if no stack assigned manually, defaults to kernel
    if(fwd_stack == NULL) fwd_stack = ioth_newstack("kernel", NULL);
    if(query_stack == NULL) query_stack = ioth_newstack("kernel", NULL);
	
	signal(SIGPIPE, SIG_IGN);

    qdns = iothdns_init(fwd_stack, "./config");  
    
    pthread_create(&udp_t, 0, run_udp, NULL);
	//TODO TCP
    //pthread_create(&tcp_t, 0, run_tcp, NULL);
	//clean reverse address resolution record
	for(;;){
		sleep(1);
		ra_clean();
	}
}

