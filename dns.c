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
#include <arpa/inet.h>
#include <time.h>

#include <ioth.h>
#include <iothconf.h>
#include <iothdns.h>

#include "udp_dns.h"
#include "tcp_dns.h"
#include "parse_dns.h"
#include "revdb.h"
#include "config.h"
#include "utils.h"
#include "const.h"


struct ioth* fwd_stack = NULL;
struct ioth* query_stack = NULL;

int verbose = 0;
int auth = 1;
int logging_level = 1;
int stacks = 0;
int forwarding = 1;
int daemonize = 0;
int savepid = 0;

char pidpath[PATH_MAX];
char *setconfigpath = NULL;
long dnstimeout = TIMEOUT;
unsigned int udp_maxbuf = IOTHDNS_UDP_MAXBUF;
struct in6_addr *bindaddr = NULL;

pthread_mutex_t slock;

static void printusage(char *progname){
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--help|-h\tPrint this help message.\n"
			"\t--verbose|-v\tChoose program printing level (default is 1).\n"
			"\t\t\tOptions are 0 (No printing), 1 (Errors), 2 (Info), 3 (Debugging).\n"
			"\t--config|-c\tManually set configuration file path.\n"
			"\t--bind|-b\tBind to target IPv4 or IPv6 address (default is any).\n"
			"\t--stacks|-s\tCreate virtual stacks according to configuration file.\n"
			"\t--server|-S\tDisable forwarding in order to act as a no-recursion server.\n"
			"\t--reverse|-r\tSet reverse resolution policy for hash addresses (default is 'always').\n"
			"\t\t\tOptions are 'never', 'always', 'same' and 'net'.\n"
			"\t--buffer|-B\tSet new limit for UDP packet size.\n"
			"\t\t\tThis is needed when using newer DNS extensions such as EDNS0. (default is 512)\n"
			"\t--timeout|-t\tSet request timeout in milliseconds (default is 1000).\n"
			"\t--revtimeout|-R\tSet reverse domain table expire time in seconds (default is 3600).\n"
			"\t--auth|-a\tEnable authorization mode according to configuration file.\n"
			"\t--daemonize|-d\tDaemonize process.\n"
			"\t--pid|-p\tSave pid file in given path.\n"
			"\t--log|-L\tPrint to program log instead of standard output.\n",
			progname);
	exit(1);
}

static void init_random(){
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
	static char *short_options = "b:r:t:R:p:B:v:c:hsSadL";
	static struct option long_options[] = {
		{"help", no_argument , 0, 'h'},
		{"verbose", 1 , 0, 'v'},
		{"config", 1 , 0, 'c'},
		{"bind", 1 , 0, 'b'},
		{"stacks", no_argument , 0, 's'},
		{"server", no_argument , 0, 'S'},
		{"reverse", 1 , 0, 'r'},
		{"buffer", 1 , 0, 'B'},
		{"timeout", 1 , 0, 't'},
		{"revtimeout", 1 , 0, 'R'},
		{"auth", no_argument , 0, 'a'},
		{"daemonize", no_argument , 0, 'd'},
		{"pid", 1 , 0, 'p'},
		{"log", no_argument , 0, 'L'},
		{0, 0, 0, 0}
	};
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
                logging_level = atoi(optarg);
                break;
            case 'c':
				setconfigpath = malloc(PATH_MAX);
				//get either relative or absolute path
				if(optarg[0] != '/'){
					char cwd[PATH_MAX];
					snprintf(setconfigpath, PATH_MAX, "%s/%s", getcwd(cwd, PATH_MAX), optarg);
				} else {
					snprintf(setconfigpath, PATH_MAX, "%s", optarg);	
				}
                break;
            case 'b':
				bindaddr = malloc(sizeof(struct in6_addr));
				//try to parse as ipv4 on converted ipv4 template, else try ipv6
				*bindaddr = (struct in6_addr){{IP4_IP6_MAP}};
				if(inet_pton(AF_INET, optarg, ((uint8_t*)bindaddr)+12) != 1){
					if(inet_pton(AF_INET6, optarg, (uint8_t*)bindaddr) != 1){
						printusage(progname);
					}
				}
                break;
            case 's':
				stacks = 1;
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
            case 'R':
				ra_set_timeout(atoi(optarg));
                break;
            case 'B':
				udp_maxbuf = atoi(optarg);
                break;
            case 'a':
				auth = 0;
                break;
			case 'd':
				daemonize=1;
				break;
            case 'p':
				savepid=1;
				strncpy(pidpath, optarg, PATH_MAX);
				pidpath[PATH_MAX-1] = '\0';
                break;
			case 'L':
				start_logging();
				break;
			default:
				printusage(progname);
        }
    }
	if(init_config()) exit(1);
	if(daemonize && daemon(0, 0)){
		perror("daemon");
		exit(1);
	}
	if(savepid) save_pid(pidpath);
    //if stack not assigned manually, defaults to kernel
    if(fwd_stack == NULL) fwd_stack = ioth_newstack("kernel", NULL);
    if(query_stack == NULL) query_stack = ioth_newstack("kernel", NULL);
	
	init_random();
	
	//mutex lock for stacks operations
	pthread_mutex_init(&slock, NULL);

	//program should not close in case of sigpipe
	signal(SIGPIPE, SIG_IGN);

    pthread_create(&udp_t, 0, run_udp, NULL);
    pthread_create(&tcp_t, 0, run_tcp, NULL);
	//clean reverse address resolution record
	for(;;){
		sleep(1);
		ra_clean();
	}
}

