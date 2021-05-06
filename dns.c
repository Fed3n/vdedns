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
#include <arpa/inet.h>
#include <sys/random.h>
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
long dnstimeout = TIMEOUT;
unsigned int udp_maxbuf = IOTHDNS_UDP_MAXBUF;
struct in6_addr *bindaddr = NULL;

pthread_mutex_t ralock;
pthread_mutex_t slock;

//data for unique id generation
static uint8_t id_table[ID_TABLE_SIZE];
static pthread_mutex_t idlock;

static void init_random(){
    unsigned int seed;
    if(getrandom(&seed, sizeof(unsigned int), 0) == 0){
        srandom(seed);
    } else {
        srandom(time(NULL) ^ getpid());
    }
}

//tries to generate unique packet ids across both threads
//algorithm is optimistic and will give up after some tries
//hoping not to cause a packet mismatch
#define MAX_RETRY 8
uint16_t get_unique_id(){
	int i;
	uint16_t id;
	pthread_mutex_lock(&idlock);
	for(i = 0; i < MAX_RETRY; i++){
		id = random();
		if(id_table[id] == 0) {
			id_table[id]++;
			break;
		}
	}
	if(i >= MAX_RETRY) {
		printlog(LOG_ERROR, "Failed to generate unique ID.\n");
		id_table[id]++;
	}
	pthread_mutex_unlock(&idlock);
	return id;
}
void free_id(uint16_t id){
	pthread_mutex_lock(&idlock);
	id_table[id]--;
	//printf("ID AMOUNT IS NOW %d\n", id_table[id]);
	pthread_mutex_unlock(&idlock);
}


void printusage(char *progname){
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--help|-h\tPrint this help message.\n"
			"\t--verbose|-v\tChoose program printing level (default is 1).\n"
			"\t\t\tOptions are 0 (No printing), 1 (Errors), 2 (Info), 3 (Debugging).\n"
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

int main(int argc, char** argv){
    pthread_t udp_t, tcp_t;
    char* progname = basename(argv[0]);
	static char *short_options = "b:r:t:R:p:B:v:hsSadL";
	static struct option long_options[] = {
		{"help", no_argument , 0, 'h'},
		{"verbose", 1 , 0, 'v'},
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
            case 'b':
				bindaddr = malloc(sizeof(struct in6_addr));
				//try to parse as ipv4 on converted ipv4 template, else try ipv6
				*bindaddr = (struct in6_addr){{{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
					0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0}}};
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
	//mutex lock for packet id generation
	pthread_mutex_init(&idlock, NULL);
	//mutex lock for stacks operations
	pthread_mutex_init(&slock, NULL);
	//mutex lock for writing on reverse address table
	pthread_mutex_init(&ralock, NULL);

	memset(id_table, 0, ID_TABLE_SIZE);

	//program should not close in case of sigpipe
	signal(SIGPIPE, SIG_IGN);

    pthread_create(&udp_t, 0, run_udp, NULL);
    pthread_create(&tcp_t, 0, run_tcp, NULL);
	//clean reverse address resolution record
	for(;;){
		sleep(1);
		pthread_mutex_lock(&ralock);
		ra_clean();
		pthread_mutex_unlock(&ralock);
	}
}

