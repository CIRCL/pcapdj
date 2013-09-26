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
#define _XOPEN_SOURCE 
#define _GNU_SOURCE
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
#include <dirent.h>
#include <glib.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#define PQUEUE "PCAPDJ_IN_QUEUE"
#define RQUEUE "PCAPDJ_PROCESSED"
#define NEXTJOB "PCAPDJ_NEXT"
#define AKEY "PCAPDJ_AUTH"
#define SKEY "PCAPDJ_SUSPEND"
#define CKEY "PCAPDJ_STATS"
#define DEFAULT_SRV "127.0.0.1"
#define POLLINT 100000
#define PCAPDJ_STATE "PCAPDJ_STATE"
#define PCAPDJ_STATE_DONE "DONE"

/* Internal pcapdj states */
#define PCAPDJ_I_STATE_RUN 0
#define PCAPDJ_I_STATE_SUSPEND 1
#define PCAPDJ_I_STATE_AUTH_WAIT 2
#define PCAPDJ_I_STATE_FEED 3 
#define DEFAULT_SUSPEND_TRS 500 
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
    char currentprocessedfile[ABSFILEMAX]; 
} statistics_t;

typedef struct filenamepair_s {
    char filename[FILENAME_MAX];
    uint32_t epoch;
} filenamepair_t;


/* Global variables */
statistics_t stats;
char statedir[ABSFILEMAX];
int ignore;
int shouldreset;
int suspend_treshold; 
int database_num;

int save_internal_states();
void display_stats();

void usage(void)
{
    
    printf("pcapdj [-h] [-b namedpipe] [-s redis_server] [-p redis_srv_port]%s",
           " [-d statedir]\n       [-i] [-r] [-t N] [-n databasenumber]\n\n");
    printf("Connects to the redis instance specified by the %s", 
           "redis_server and\nredis_srv_port.\n\n"); 

    printf("Pcap files are read from the queue PCAPDJ_IN_QUEUE. ");
    printf("Each pcap file is opened\nand the contained packets are put %s ",
           "into the fifo buffer"); 
    printf("specified by with the\n-b option when an explicit permission ");
    printf("is granted.\n\n"); 
    printf("When pcapdj is started it connects to the named pipe and waits%s",
           " for the consumer\n");
    printf("program which processes the frames included in the pcap files.\n");
    printf("\nWhen the consumer program connected to the named pipe, pcapdj%s",
           " pops the redis\n");
    printf("queue PCAPDJ_IN_QUEUE which should contain filenames of pcap %s",
           "files that are\n");
    printf("planned to be processed.\n\n");
    printf("The pcap file name that is planned to be processed is put in %s",
           "the redis queue\n"); 
    printf("entitled PCAPDJ_NEXT. Another program, denoted controller %s",
           "program should\n");
    printf("take the latest element of the queue PCAPDJ_NEXT and do the %s",
           "necessary checks,\n"); 
    printf("such as if there is enough of disk space, monitor memory %s",
           "consumption etc. When\n");
    printf("all the checks are fine, the value of the redis key %s",
           "PCAPDJ_AUTH is updated\nwith the ");
    printf("pcap file name that is planned to be processed.\n\n");
    printf("Pcapdj notices this and starts to feed the named pipe until %s",
           "it is suspended or\n");
    printf("if the end of the pcap file is reached. Pcapdj closes the pcap %s",
           "file and asks\nfor permission to process the next pcap file ");
    printf("included in the redis queue\nlabeled PCAPDJ_IN_QUEUE.\n");
    printf("Pcapdj does not close the file descriptor of the named pipe. %s",
           "Hence, the\n");
    printf("consumer program \"thinks\" that it is still reading the same %s",
           "pcap file.\n\n");
    printf("This process goes on until the redis queue PCAPDJ_IN_QUEUE is %s",
           "empty and the\n");
    printf("file descriptor of the named pipe is closed.\n\n");
    printf("REPORTING\n\n");

    printf("When pcapdj is running for a long period and if the consumer %s",
            "program is not\n");
    printf("very verbose, the process identifier of pcapdj can be given to %s",
           " the redis key\nPCAPDJ_STATS. ");
    printf("Pcapdj polls this value each N packets and reacts appropriately\n");
    printf("The default value of N is 500. This value can be overriden with ");
    printf("the -t switch.\n");
    printf("On standard output similar to the report shown in the %s",
           "example below.\n\n");

    printf("EXAMPLE\n\n");

    printf("    [STATS] Start time:2013-24-09 14:19:57\n");
    printf("    [STATS] Uptime:30 (seconds)\n");
    printf("    [STATS] Internal state:Feeding fifo buffer\n");
    printf("    [STATS] Number of suspensions:0\n");
    printf("    [STATS] Number of files:1\n");
    printf("    [STATS] Number of packets:978\n");
    printf("    [STATS] Number of cap_lengths:626286\n");
    printf("    [STATS] Number of lengths:626286\n");
    printf("    [INFO] Last processed file:2.pcap.gz\n");
    printf("    [INFO] Packet offset:979\n\n");

    printf("SUSPENDING PCAPDJ\n\n");
    printf("Pcapdj can be suspended during operation by setting the %s",
           "redis key\nPCAPDJ_SUSPEND to the process identifier of");
    printf(" pcapdj.\nPcapdj polls this queue every N packets.\n");
    printf("The default value of N is 500. This value can be overriden with ");
    printf("the -t switch.\n");
    printf("If suspended pcapdj does not feed packets anymore %s",
           "to the named pipe.\n");
    printf("Please note that there are internal buffers of named pipes.\n");
    printf("Hence, the effects are not immediate.\n"); 
    printf("Pcapdj shows the following message when suspended.\n\n");
    printf("    [INFO] Suspending pcapdj\n\n");
    printf("When pcapdj is resumed the following message is shown.\n\n");
    printf("    [INFO] Resuming pcapdj\n\n");
       
    printf("\nOPTIONS\n\n");
    printf("    -h                   Shows this screen\n");
    printf("    -b <namedpipe>       Specify a named pipe previously %s ",
           "created with mkfifo\n");
    printf("   -s <redis_server>    Specify a redis-server used for %s",
           "interactions.\n");
    printf("                         Default one: 127.0.0.1\n");
    printf("    -p <redis_srv_port>  Specify the port where redis %s",
           "listens on.\n");
    printf("    -n <database number> Specify the redis database number\n");
    printf("                         Default one: 6379\n"); 
    printf("    -d <statedir>        Specify the state directory to store %s",
           "internal states\n");
    printf("    -i                   Ignore the old state files if found.\n");
    printf("    -r                   Delete in redis all data structures %s ",
           "used by pcapdj\n");
    printf("   -t                   Specify the number N meaning after");
    printf(" how many packets\n");
    printf("                         PCAPDJ_SUSPEND and PCAPDJ_STATS %s\n",
           "should be queried.");
    printf("                         The higher N is, the lower the ");
    printf("performance overhead.\n");
    printf("                         A high value of N makes pcapdj less %s", 
           "reactive.\n");
}

void check_stat_request(redisContext* ctx)
{
    redisReply *reply;
    redisReply *reply2; 
    char buf[16];
    
    snprintf((char*)&buf, 16,"%d",getpid());
    reply = redisCommand(ctx, "GET %s", CKEY);
    if (reply) {
        if (reply->type == REDIS_REPLY_STRING) {
            if (!strncmp(reply->str, buf, 16)) {
                display_stats();
                /* Delete key otherwise the stats are repeated */
                reply2 = redisCommand(ctx,"DEL %s",CKEY);
                if (reply2)
                    freeReplyObject(reply2);
            }
        }
        freeReplyObject(reply);
    }
}


void wait_to_resume(redisContext* ctx)
{
    redisReply *reply;
    pid_t pid;
    char buf[16];

    pid = getpid();
    snprintf((char*)&buf, 16, "%d", pid);

    stats.state = PCAPDJ_I_STATE_SUSPEND;

    do {
        reply = redisCommand(ctx,"GET %s",SKEY);
        if (reply){
            if (reply->type == REDIS_REPLY_STRING) {
                if (strncmp(reply->str, buf, 16)) {
                    fprintf(stderr,"[INFO] There is a pcapdj instance (%s) \
that is suspended but it's not me\n",reply->str);
                    goto out;
                }
            } else{
                /* Another value was returned for instance NULL */
                goto out;
            }       
            freeReplyObject(reply);
        } else {
            fprintf(stderr,"[ERROR] redis server did not replied for being\
unsuspended\n");
        }
        usleep(POLLINT);
    } while (1);
    out:
        freeReplyObject(reply);
        printf("[INFO] Resuming pcapdj\n");
}

void suspend_pcapdj_if_needed(redisContext* ctx) 
{
    redisReply *reply;
    pid_t pid;
    char buf[16];
    
    pid = getpid();
    snprintf((char*)&buf,16,"%d",pid);

    reply = redisCommand(ctx,"GET %s",SKEY);
    if (reply) {
        if (reply->type == REDIS_REPLY_STRING) {
            if (!strncmp(reply->str, buf, 16)) {
                fprintf(stderr, "[INFO] Suspending pcapdj pid=%s\n", buf);
                stats.num_suspend++;
                wait_to_resume(ctx);
            } else {
                fprintf(stderr,"[INFO] Another instance should be %s%s\n",
                               "suspended not me. Other pid=", reply->str);
                }
            } 
            freeReplyObject(reply);
        }else{
            fprintf(stderr,"[ERROR] Could not check for being suspended\n");
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
    printf("[INFO] Last processed file:%s\n",stats.currentprocessedfile);
    printf("[INFO] Packet offset:%ld\n",stats.infile_cnt);
}

void sig_handler(int signal_number)
{
    if (signal_number == SIGPIPE) {
        fprintf(stderr,"[ERROR] Consumer program died.\n");
        save_internal_states();
        exit(1);
    }
    if (signal_number == SIGTERM || signal_number == SIGINT) {
        printf("[INFO] Got TERM or INT signal\n");
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

void process_file(redisContext* ctx, pcap_dumper_t* dumper, char* filename, 
                  uint64_t offset, int resume)
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
    
    strncpy((char*)&stats.currentprocessedfile, filename, ABSFILEMAX);
    stats.infile_cnt=0;
    
    if (!resume) {
        fprintf(stderr,"[INFO] Waiting authorization to process file %s\n",filename);
        wait_auth_to_proceed(ctx, filename);
    }

    wth = wtap_open_offline ( filename, (int*)&err, (char**)&errinfo, FALSE);
    data_offset = 0;
    if (wth) {
        stats.num_files++;
        /* Loop over the packets and adjust the headers */
        while (wtap_read(wth, &err, &errinfo, &data_offset)) {
            if (stats.infile_cnt % suspend_treshold == 0) { 
                suspend_pcapdj_if_needed(ctx);
                check_stat_request(ctx); 
            }
            stats.state = PCAPDJ_I_STATE_FEED;
            stats.infile_cnt++;
            phdr = wtap_phdr(wth);
            buf = wtap_buf_ptr(wth);
            pchdr.caplen = phdr->caplen;
            pchdr.len = phdr->len;
            pchdr.ts.tv_sec = phdr->ts.secs;
            /* Need to convert micro to nano seconds */
            pchdr.ts.tv_usec = phdr->ts.nsecs/1000;
            if (stats.infile_cnt > offset) {
                pcap_dump((u_char*)dumper, &pchdr, buf);
                stats.num_packets++;
                stats.sum_cap_lengths+=phdr->caplen;
                stats.sum_lengths+=phdr->caplen;
            }
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
    
    /* Select database */
    reply = redisCommand(ctx, "SELECT %d\n",database_num);
    if (!reply) {
        fprintf(stderr,"[ERROR] Could not select the redis database %d\n",
                database_num);
        return EXIT_FAILURE;
    }
    if ((reply->type == REDIS_REPLY_ERROR) || (reply->type == REDIS_REPLY_NIL)){
        fprintf(stderr,"[ERROR] Could not select the redis database %d\n",1);
        return EXIT_FAILURE;
    }
    /* Check if a previously started instance processed a file */
    if (stats.currentprocessedfile[0]){
        printf("[INFO] Found last processed file %s\n",stats.currentprocessedfile);
        process_file(ctx, dumper, stats.currentprocessedfile, stats.infile_cnt,1);
    } else {
        printf("[INFO] No last processed file was found.\n");
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
            process_file(ctx, dumper, reply->str,0,0);
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
 
void reset_redis_structures(char *redis_server, int redis_srv_port)
{
    redisContext* ctx;
    redisReply* reply;
    ctx = redisConnect(redis_server, redis_srv_port);

    if (ctx != NULL && ctx->err) {
        fprintf(stderr,"[ERROR] Could not connect to redis. %s\n",ctx->errstr);
        return;
    }
    printf("[INFO] Connected to redis %s on port %d\n", redis_server, 
           redis_srv_port);
    printf("[INFO] Reseting data structures\n");
    
    /* Select database */
    reply = redisCommand(ctx, "SELECT %d\n",database_num);
    if (!reply) {
        fprintf(stderr,"[ERROR] Could not select the redis database %d\n",
                database_num);
        return;
    }
    if ((reply->type == REDIS_REPLY_ERROR) || (reply->type == REDIS_REPLY_NIL)){
        fprintf(stderr,"[ERROR] Could not select the redis database %d\n",1);
        return;
    }

    /* Delete the related fields */
    redisCommand(ctx, "DEL %s",PQUEUE);
    redisCommand(ctx, "DEL %s",RQUEUE);
    redisCommand(ctx, "DEL %s",NEXTJOB);
    redisCommand(ctx, "DEL %s",AKEY);
    redisCommand(ctx, "DEL %s",PCAPDJ_STATE);
    redisCommand(ctx, "DEL %s",CKEY);
    redisCommand(ctx, "DEL %s\n",SKEY);
}

void init(void)
{
    struct sigaction sa;
    
    memset(&sa,0,sizeof(sa));
    memset(&stats,0,sizeof(statistics_t));
    
    /* Update the start time */
    stats.startepoch = time(NULL);
    stats.starttime = localtime(&stats.startepoch);
    assert(stats.starttime);
    
    bzero((char*)&statedir, ABSFILEMAX);
    
    ignore = 0;
    shouldreset = 0;
    suspend_treshold = DEFAULT_SUSPEND_TRS;
    database_num = 0;

    /* Install signal handler */
    sa.sa_handler = &sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
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
                snprintf(filename, ABSFILEMAX, "%s/pcapdj_states_%s.txt",statedir, buf);
            }else{
                snprintf(filename, ABSFILEMAX, "pcapdj_states_%s.txt", buf);
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
        fprintf(fd,"currentprocessedfile=%s\n",stats.currentprocessedfile);
        fprintf(fd,"offset=%ld\n",stats.infile_cnt);
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
        fprintf(fd,"num_suspend=%ld\n",stats.num_suspend);
        fprintf(fd,"num_files=%ld\n",stats.num_files);
        fprintf(fd,"num_packets=%ld\n",stats.num_packets);
        fprintf(fd,"num_cap_lengths=%ld\n",stats.sum_cap_lengths);
        fprintf(fd,"num_lengths=%ld\n",stats.sum_lengths);
        fprintf(stderr, "[INFO] Saved internal states to %s\n",filename);
        fclose(fd);
        free(filename);
        return 1;
    } else{
        fprintf(stderr,"[ERROR] cannot open filename %s.%s\n", 
        filename, strerror(errno));
    }
    /* An error happened */
    fprintf(stderr,"[ERROR] The file %s might be corrupted\n",filename);
    free(filename);
    return 0;
}

void remove_trailing_slash(char* filename)
{
    int l;
    l = strlen(filename);
    if (l>0) {
        if (filename[l-1] == '/')
            filename[l-1] = 0;
    }
}

uint32_t extract_timestamp(char* filename)
{
    char *p;
    int i;
    char* buf;
    uint32_t out;
    struct tm tm;
    /* Error when no properly parsed */
    out = -1;
    buf = calloc(ABSFILEMAX,1);
    assert(buf);
    
    p = strstr(filename,"pcapdj_states_");
    if (p) {
        p+=14;
        for (i=0; i<strlen(filename); i++)
            if (filename[i] == '.') {
                assert((i-14) >0);
                strncpy(buf,p,i-14);
                break;
            }
        if (buf[0]) {
            if (strptime(buf,"%Y%m%d%H%M%S",&tm)) {
                if (strftime(buf,16, "%s",&tm)){
                    out = atoi(buf);
                }
            }
        }    
    }
    free(buf);
    return out;
}

int  fpaircmp (filenamepair_t* a, filenamepair_t* b) {
    int r;
    if (a->epoch < b->epoch) {
        r = -1;
    } else {
        if (a->epoch > b->epoch) {
            r = 1;
        } else {
            /* Both are equals */
            r = 0;
        }
    }
    
    /* printf("[DEBUG] Comparing %s %d with %s %d. Returned:%d\n",
     *      a->filename, a->epoch, b->filename, b->epoch,r);
     * Debuging purpose
     */
    return r; 
}

GList *search_old_state_files(void)
{
    DIR* d;
    struct dirent* entry;
    char* r;
    uint32_t epoch;
    GList* dirlist;
    filenamepair_t * fpair;
    /* If no directory was specified the current directory should be used */
    if (!statedir[0])
        statedir[0] = '.';

    dirlist = NULL;

    printf("[INFO] Looking for old state files in %s\n",statedir);
    d = opendir(statedir);
    if (d) {
        while ((entry = readdir(d)) != NULL) {
            r = strstr(entry->d_name,"pcapdj_states_");
            if (r == entry->d_name) { 
                epoch = extract_timestamp(entry->d_name);
                if (epoch > 0) {
                    /* printf("[INFO] Identified state file %s at timestamp %d \n",
                     *     entry->d_name, epoch); 
                     * Debuging purpose
                     */
                    fpair = calloc(sizeof(filenamepair_t),1);
                    assert(fpair);
                    strncpy((char*)&fpair->filename, entry->d_name, FILENAME_MAX);
                    fpair->epoch = epoch; 
                    dirlist = g_list_append(dirlist, fpair);
                }
            }
        }
    }
    dirlist = g_list_sort(dirlist, (GCompareFunc)&fpaircmp); 
    dirlist = g_list_reverse(dirlist);
    return dirlist;
}

int load_state_file(char* filename)
{
    GKeyFile *gf;
    GError *err;
    char *afilename;
    int ret;
    char *lfbuf;
    uint64_t offset;

    ret = 0;
    gf = g_key_file_new();
    afilename = calloc(ABSFILEMAX, 1);
    
    assert(afilename);
    assert(gf);

    if (statedir[0]) {
        snprintf(afilename, ABSFILEMAX, "%s/%s", statedir, filename);
    } else {
        strncpy(afilename, filename, ABSFILEMAX);
    }

    err = NULL;
    if (g_key_file_load_from_file(gf, afilename, G_KEY_FILE_KEEP_COMMENTS, &err))
    {
        printf("[INFO] Successfully loaded %s\n",afilename);
        err = NULL;
        offset = g_key_file_get_integer (gf,"PCAPDJ_STATES", "offset", &err);
        lfbuf = g_key_file_get_value (gf, "PCAPDJ_STATES","currentprocessedfile",
                &err);
        if (lfbuf) {
            if (lfbuf[0]) {
                printf("[INFO] Using old offset %ld\n", offset);
                printf("[INFO] Using old filename %s\n", lfbuf); 
                strncpy((char*)&stats.currentprocessedfile, lfbuf, ABSFILEMAX);
                stats.infile_cnt = offset; 
            }
        } else {
            if (err) {
                fprintf(stderr,"[ERROR] Broken pcapdj_state file %s\n",
                        err->message); 
            }
        }
    } else {
        fprintf(stderr,"[ERROR] failed to load file %s.\n[ERROR] Cause:%s\n.",
                afilename,err->message);
    }

    free(afilename);   
    return ret;
}

void destroy_filelist(GList *filelist)
{
    GList* p;
    filenamepair_t *fpair;
    if (filelist) {
        p = filelist;
        while (p) {
            fpair = (filenamepair_t*) p->data;
            free(fpair);
            p = p->next;
        }
        g_list_free(filelist);
    }
}

int handle_old_state_files(void)
{
    GList* sfilelist;
    GList* p;
    filenamepair_t *fpair;
    sfilelist = search_old_state_files();
    if (sfilelist) { 
        p = sfilelist;
        while (p) {
            fpair = (filenamepair_t*)p->data;
            printf("[INFO] Identified old state file %s\n", fpair->filename);
            p=p->next;
        }
        fpair = (filenamepair_t*)sfilelist->data;
        printf("[INFO] Selecting most recent state file %s\n",fpair->filename);
        load_state_file(fpair->filename);
    } else {
        printf("[INFO] No previously saved states were found.\n");
    }
    destroy_filelist(sfilelist);
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
    while ((opt = getopt(argc, argv, "b:hs:p:d:irt:n:")) != -1) {
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
                remove_trailing_slash((char*)&statedir);
                break;
            case 'h':
                usage();
                return EXIT_SUCCESS;
            case 'i':
                ignore = 1;
                break;
            case 'r':
                shouldreset = 1;
                break;
            case 't':
                suspend_treshold = atoi(optarg);
                break; 
            case 'n':
                database_num = atoi(optarg);
                break;
            default: /* '?' */
                fprintf(stderr, "[ERROR] Invalid command line was specified\n");
        }
    }
    /* Set default values if needed */
    if (!redis_server[0])
        strncpy(redis_server,DEFAULT_SRV,64);
    /* Connect to redis */
    if (shouldreset) {
        reset_redis_structures(redis_server, redis_srv_port);
        return EXIT_SUCCESS;
    }
    if (!namedpipe[0]){
        fprintf(stderr,"[ERROR] A named pipe must be specified\n");
        return EXIT_FAILURE; 
    }

    fprintf(stderr, "[INFO] redis_server = %s\n",redis_server);
    fprintf(stderr, "[INFO] redis_port = %d\n",redis_srv_port);
    fprintf(stderr, "[INFO] used redis database number = %d\n",database_num);
    fprintf(stderr, "[INFO] named pipe = %s\n", namedpipe);
    fprintf(stderr, "[INFO] pid = %d\n",(int)getpid());
    fprintf(stderr, "[INFO] used state directory:%s\n", statedir);
    fprintf(stderr, "[INFO] used check interval (suspend and stats) %s%d\n",
                    "denoted N=",suspend_treshold);
    if (!ignore) {
        handle_old_state_files();
    } else {
        fprintf(stderr,"[INFO] ignoring old state files\n");
    }

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

