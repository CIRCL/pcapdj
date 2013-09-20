/*
* pcapdj - dispatch pcap files
*
* Copyright (C) 2013 Gerard Wagener
* Copyright (C) 2013 CIRCL Computer Incident Response Center Luxembourg 
* (SMILE gie).
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <string.h>
#include <pcap/pcap.h>
#include <wtap.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#define PQUEUE "PCAPDJ_IN_QUEUE"
#define RQUEUE "PCAPDJ_PROCESSED"
#define NEXTJOB "PCAPDJ_NEXT"
#define AKEY "PCAPDJ_AUTH"
#define DEFAULT_SRV "127.0.0.1"
#define POLLINT 100000
#define PCAPDJ_STATE "PCAPDJ_STATE"
#define PCAPDJ_STATE_DONE "DONE"

/* Internal pcapdj states */
#define PCAPDJ_I_STATE_RUN 0
#define PCAPDJ_I_STATE_SUSPEND 1
#define PCAPDJ_I_STATE_AUTH_WAIT 2
#define PCAPDJ_I_STATE_FEED 3 
#include <hiredis/hiredis.h>
#include <linux/limits.h>

#define ABSFILEMAX PATH_MAX+NAME_MAX+1
/* FIXME No atomicity is assured so it might be that they are not accurate */
typedef struct statistics_s {
    u_int64_t num_files;
    u_int64_t num_packets;
    u_int64_t sum_cap_lengths;
    u_int64_t sum_lengths;
    u_int64_t infile_cnt;
    u_int64_t num_suspend;
    u_int8_t state;
    u_int8_t oldstate;
    time_t startepoch;
    struct tm *starttime;
    char lastprocessedfile[ABSFILEMAX]; 
} statistics_t;

/* Global variables */
sig_atomic_t sigusr1_suspend = 0;
statistics_t stats;
char statedir[ABSFILEMAX];

int save_internal_states();

void usage(void)
{
    
    printf("pcapdj [-h] -b namedpipe [-s redis_server] -p [redis_srv_port] [-d statedir]\n\n");
    printf("Connects to the redis instance specified with by the redis_server\n");
    printf("and redis_srv_port.\n\n"); 

    printf("Read a list of pcap-ng files from the  queue PCAPDJ_IN_QUEUE.\n");
    printf("Open the pcap-ng file and feed each packet to the fifo buffer\n"); 
    printf("specified by with the -b option.  When a pcap file from the list\n"); 
    printf("has been transferred to the buffer update the queue PCAPDJ_PROCESSED\n");
    printf("with the filename that just was processed.\n\n"); 

    printf("Update the  PCAPDJ_NEXT with the next file that is beeing processed.\n");
    printf("Poll PCAPDJ_AUTH key. When the value of this key corresponds to the next file then use \n");
    printf("the next pcap file and feed the fifo buffer with the packets.\n");
    printf("\nWhen the last packet of the last file has been processed the fifo\n");
    printf("the file handle  is closed.\n"); 

    printf("\nOPTIONS\n");
    printf("    -d <statedir> Specify the state directory to store internal states\n");
}

void suspend_pcapdj_if_needed(const char *state) 
{
    if (sigusr1_suspend) {
        fprintf(stderr,"[INFO] pcapdj is suspended. %s\n",state);
        while (sigusr1_suspend) { 
                usleep(POLLINT);
        }
    }
}

void display_stats()
{
    char stimebuf[64];
    u_int64_t uptime;
    time_t t;
    /* Display accounting numbers */
    if (strftime((char*)&stimebuf, 64, "%Y-%d-%m %H:%M:%S",stats.starttime))
        printf("[STATS] Start time:%s\n",stimebuf);
    t = time(NULL);
    uptime = t - stats.startepoch;
    printf("[STATS] Uptime:%ld (seconds)\n", uptime);

    /* Describe the internal state */
    switch (stats.state) {
        case PCAPDJ_I_STATE_RUN:
            printf("[STATS] Internal state:Running\n");
            break;
        case PCAPDJ_I_STATE_SUSPEND:
            printf("[STATS] Internal state:Suspended\n");
            break;
        case PCAPDJ_I_STATE_AUTH_WAIT:
            printf("[STATS] Internal state:Waiting for authorization\n");
            break;
        case PCAPDJ_I_STATE_FEED:
            printf("[STATS] Internal state:Feeding fifo buffer\n");
            break;
        default:
            printf("[STATS] Internal state:Unknown\n");        
    }
    printf("[STATS] Number of suspensions:%ld\n",stats.num_suspend);
    printf("[STATS] Number of files:%ld\n",stats.num_files);
    printf("[STATS] Number of packets:%ld\n",stats.num_packets);
    printf("[STATS] Number of cap_lengths:%ld\n",stats.sum_cap_lengths);
    printf("[STATS] Number of lengths:%ld\n",stats.sum_lengths);
    printf("[INFO] Last processed file:%s\n",stats.lastprocessedfile);
    printf("[INFO] Packet offset:%ld\n",stats.infile_cnt);
}

void sig_handler(int signal_number)
{
    if (signal_number == SIGUSR1) {
        sigusr1_suspend=~sigusr1_suspend;

        if (sigusr1_suspend) {
            printf("[INFO] Suspending pcapdj\n");
            stats.oldstate = stats.state;
            stats.state = PCAPDJ_I_STATE_SUSPEND;
            stats.num_suspend++;
            /* This function should not block otherwise the resume does not work */
        }else{
            printf("[INFO] Resuming pcapdj\n");
            stats.state = stats.oldstate;
            stats.oldstate = PCAPDJ_I_STATE_SUSPEND;
        }
    }
    if (signal_number == SIGUSR2) {
        display_stats();
    }
    if (signal_number == SIGTERM) {
        printf("[INFO] Got TERM signal\n");
        save_internal_states();
        printf("[INFO] Terminating program\n");
        exit(1);
    }
}

void update_processed_queue(redisContext* ctx, char *filename)
{
    /* FIXME errors are currently ignored */
    redisReply *reply;
    reply = redisCommand(ctx,"RPUSH %s %s",RQUEUE, filename);
    if (reply)
        freeReplyObject(reply);
}
void update_next_file(redisContext* ctx, char* filename)
{
    /* FIXME Currently we don't care if the field was set */
    redisReply *reply;
    reply = redisCommand(ctx,"RPUSH %s %s", NEXTJOB, filename);
    if (reply)
        freeReplyObject(reply);
} 

void delete_next_file_queue(redisContext* ctx)
{
    /* FIXME errors are ignored */
    redisReply * reply;
    reply = redisCommand(ctx, "DEL %s",NEXTJOB);
    if (reply)
        freeReplyObject(reply);
}


void delete_auth_file(redisContext* ctx)
{
    /* FIXME errors are ignored */
    redisReply * reply;
    reply = redisCommand(ctx, "DEL %s", AKEY);
    if (reply)
        freeReplyObject(reply);
}

void wait_auth_to_proceed(redisContext* ctx, char* filename)
{
    redisReply *reply;
    stats.state = PCAPDJ_I_STATE_AUTH_WAIT;
    /* If there is an error the program waits forever */
    
    do {
        reply = redisCommand(ctx,"GET %s",AKEY);
        if (reply){
            if (reply->type == REDIS_REPLY_STRING) {
                /* Delete the authorized key. So in the next
                 * iteration the AUTH_KEY is not there anymore and
                 * the error message is not reated all the times
                 */
                delete_auth_file(ctx);
                if (!strncmp(reply->str, filename, strlen(filename))) {
                    fprintf(stderr, "[INFO] Got authorization to process %s\n",filename);
                    freeReplyObject(reply);
                    return;
                }else{
                    fprintf(stderr,"[ERROR] Got the wrong authorization. Waited for (%s). Got %s.\n", filename, reply->str);
                }
            }       
            freeReplyObject(reply);
        }else{
            fprintf(stderr,"[ERROR] redis server did not replied for the authorization\n");
        }
        usleep(POLLINT);
    } while (1);
}

void process_file(redisContext* ctx, pcap_dumper_t* dumper, char* filename)
{
    wtap *wth;
    int err;
    char *errinfo;
    gint64 data_offset;
    const struct wtap_pkthdr *phdr;
    struct pcap_pkthdr pchdr;
    guint8 *buf;

    fprintf(stderr,"[INFO] Next file to process %s\n",filename);
    update_next_file(ctx, filename);
    fprintf(stderr,"[INFO] Waiting authorization to process file %s\n",filename);
    wait_auth_to_proceed(ctx, filename);
    
    strncpy((char*)&stats.lastprocessedfile, filename, ABSFILEMAX);
    stats.infile_cnt=0;

    wth = wtap_open_offline ( filename, (int*)&err, (char**)&errinfo, FALSE);
    if (wth) {
        stats.num_files++;
        /* Loop over the packets and adjust the headers */
        while (wtap_read(wth, &err, &errinfo, &data_offset)) {
            suspend_pcapdj_if_needed("Stop feeding buffer.");
            stats.state = PCAPDJ_I_STATE_FEED;
            phdr = wtap_phdr(wth);
            buf = wtap_buf_ptr(wth);
            pchdr.caplen = phdr->caplen;
            pchdr.len = phdr->len;
            pchdr.ts.tv_sec = phdr->ts.secs;
            /* Need to convert micro to nano seconds */
            pchdr.ts.tv_usec = phdr->ts.nsecs/1000;
            pcap_dump((u_char*)dumper, &pchdr, buf);
            stats.num_packets++;
            stats.sum_cap_lengths+=phdr->caplen;
            stats.sum_lengths+=phdr->caplen;
            stats.infile_cnt++;
        }
        update_processed_queue(ctx, filename);
        wtap_close(wth);
	fprintf(stderr,"[INFO] Processing of filename %s done\n",filename);
    }else{
        fprintf(stderr, "[ERROR] Could not open filename %s,cause=%s\n",filename,
                wtap_strerror(err));
    }
}

int process_input_queue(pcap_dumper_t *dumper, char* redis_server, int redis_srv_port)
{
    redisContext* ctx; 
    redisReply* reply;    
    int rtype;
    ctx = redisConnect(redis_server, redis_srv_port);

    if (ctx != NULL && ctx->err) {
        fprintf(stderr,"[ERROR] Could not connect to redis. %s.\n", ctx->errstr);
        return EXIT_FAILURE;
    }
    

    do {
        reply = redisCommand(ctx,"LPOP %s", PQUEUE); 
        if (!reply){
            fprintf(stderr,"[ERROR] Redis error %s\n",ctx->errstr);
            return EXIT_FAILURE;
        }
        /* We got a reply */
        rtype = reply->type;
        if (rtype == REDIS_REPLY_STRING) {
            process_file(ctx, dumper, reply->str);
            
        }
        freeReplyObject(reply);
    } while (rtype != REDIS_REPLY_NIL);
    /* Notify other party that everything is done */
    reply = redisCommand(ctx, "SET %s %s",PCAPDJ_STATE, PCAPDJ_STATE_DONE);
    if (reply) {
        freeReplyObject(reply);
    }
    /* Do the cleanup */
    delete_next_file_queue(ctx);
    redisFree(ctx);
    return EXIT_SUCCESS;
}
 

void init(void)
{
    struct sigaction sa;
    
    sigusr1_suspend = 0;
    memset(&sa,0,sizeof(sa));
    memset(&stats,0,sizeof(statistics_t));
    
    /* Update the start time */
    stats.startepoch = time(NULL);
    stats.starttime = localtime(&stats.startepoch);
    assert(stats.starttime);
    
    bzero((char*)&statedir, ABSFILEMAX);

    /* Install signal handler */
    sa.sa_handler = &sig_handler;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* The file is composed of the following format
 * statedir/pcapdj_states_YYYYmmDDHHMM.ini
 * where YYYY is the year expressed in 4 digits
 * mm is the month expressed in 2 digits
 * DD is the day
 * HH is the hour
 * MM is the miniute
 * SS is the second
 * This timestamp is the date when the dump was done
 * NULL is retuned on errors
 */
char *create_target_filename(void)
{
    time_t t;
    struct tm *tm;
    char buf[16];
    char *filename;
   
    filename = calloc(ABSFILEMAX,1);
    if (!filename) { 
        fprintf(stderr,"[ERROR] No memory to save internal states\n");
        return NULL;
    }

    t = time(NULL);
    tm = localtime(&t);

    if (tm) {
         if (strftime((char*)&buf, 16, "%Y%m%d%H%M%S", tm)) {
            if (statedir[0]) {
                snprintf(filename, ABSFILEMAX, "%s/pcapdj_%s.txt",statedir, buf);
            }else{
                snprintf(filename, ABSFILEMAX, "pcapdj_%s.txt", buf);
            }
        } else{
            fprintf(stderr, "[ERROR] Strftime failed\n");    
            return NULL;
        }
    }else{
        fprintf(stderr, "[ERROR] localtime failed\n");
        return NULL;
    }
    return filename;
}

int save_internal_states()
{
    char * filename;
    FILE *fd;
    char stimebuf[16];
    time_t t;
    int uptime;
    filename = create_target_filename();
    if (!filename)
        return 0;
    fd = fopen(filename,"w");
    if (fd) { 
        fprintf(fd,"[PCAPDJ_STATES]\n");
        fprintf(fd,"lastprocessedfile=%s\n",stats.lastprocessedfile);
        fprintf(fd,"offset:%ld\n",stats.infile_cnt);
        fprintf(fd, "[STATS]\n");
        if (strftime((char*)&stimebuf, 64, "%Y-%d-%m %H:%M:%S",
            stats.starttime)){
            fprintf(fd,"starttime=%s\n",stimebuf);
        } 
        t = time(NULL);
        uptime = t - stats.startepoch;
        fprintf(fd,"uptime=%d\n", uptime);

        /* Store the internal state */
        switch (stats.state) {
            case PCAPDJ_I_STATE_RUN:
                fprintf(fd,"state=run\n");
                break;
        case PCAPDJ_I_STATE_SUSPEND:
            fprintf(fd,"state=suspend\n");
            break;
        case PCAPDJ_I_STATE_AUTH_WAIT:
            fprintf(fd,"internal_state=wait\n");
            break;
        case PCAPDJ_I_STATE_FEED:
            fprintf(fd,"state=feeding\n");
            break;
        default:
            fprintf(fd,"state=unknown\n");        
        }
        fprintf(fd,"num_suspend:%ld\n",stats.num_suspend);
        fprintf(fd,"num_files:%ld\n",stats.num_files);
        fprintf(fd,"num_packets:%ld\n",stats.num_packets);
        fprintf(fd,"num_cap_lengths:%ld\n",stats.sum_cap_lengths);
        fprintf(fd,"num_lengths:%ld\n",stats.sum_lengths);
        fclose(fd);
        free(filename);
        return 1;
    } else{
        fprintf(stderr,"[ERROR] cannot open filename %s.%s\n", 
        filename, strerror(errno));
    }
    /* An error happened */
    free(filename);
    return 0;
}

int main(int argc, char* argv[])
{

    int opt;
    int r;
    char* redis_server;
    int redis_srv_port; 
    char *namedpipe;
    pcap_t *pcap;
    pcap_dumper_t *dumper;
    
    init();
    
    namedpipe = calloc(128,1);
    assert(namedpipe);  
    
    redis_server = calloc(64,1);
    assert(redis_server);

    redis_srv_port = 6379;        
    while ((opt = getopt(argc, argv, "b:hs:p:d:")) != -1) {
        switch (opt) {
            case 's':
                strncpy(redis_server,optarg,64);
                break;
            case 'p':
                redis_srv_port = atoi(optarg);
                break;
            case 'b':
                strncpy(namedpipe , optarg, 128);
                break;
            case 'd':
                strncpy((char*)&statedir, optarg, ABSFILEMAX);
                break;
            case 'h':
                usage();
                return EXIT_SUCCESS;
            default: /* '?' */
                fprintf(stderr, "[ERROR] Invalid command line was specified\n");
        }
    }
    /* Set default values if needed */
    if (!redis_server[0])
        strncpy(redis_server,DEFAULT_SRV,64);
    /* Connect to redis */
    if (!namedpipe[0]){
        fprintf(stderr,"[ERROR] A named pipe must be specified\n");
        return EXIT_FAILURE; 
    }

    fprintf(stderr, "[INFO] redis_server = %s\n",redis_server);
    fprintf(stderr, "[INFO] redis_port = %d\n",redis_srv_port);
    fprintf(stderr, "[INFO] named pipe = %s\n", namedpipe);
    fprintf(stderr, "[INFO] pid = %d\n",(int)getpid());
    fprintf(stderr, "[INFO] used state directory:%s\n", statedir);
    /* Open the pcap named pipe */
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap) {
        printf("[INFO] Waiting for other peer (IDS, tcp-reassembly engine, etc)...\n");
        dumper = pcap_dump_open(pcap, namedpipe);
        if (dumper) {
            r = process_input_queue(dumper, redis_server, redis_srv_port);
            if (r == EXIT_FAILURE) {
                fprintf(stderr,"[ERROR] Something went wrong in during processing");
            }else{
                fprintf(stderr,"[INFO] All went fine. No files in the pipe to process.\n");
            }
            /* In all case close the connection */
            pcap_dump_close(dumper);
            return r;
        }else {
            fprintf(stderr,"[ERROR] pcap dumper failed\n");
        }
        pcap_close(pcap);
    }else {
        fprintf(stderr, "[ERROR] pcap_open_dead failed\n");
    }
    return EXIT_FAILURE;
}

