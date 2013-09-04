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
#define PQUEUE "PCAPDJ_IN_QUEUE"
#define RQUEUE "PCAPDJ_PROCESSED"
#define NEXTJOB "PCAPDJ_NEXT"
#define AKEY "PCAPDJ_AUTH"
#define DEFAULT_SRV "127.0.0.1"
#define POLLINT 100000
#define PCAPDJ_STATE "PCAPDJ_STATE"
#define PCAPDJ_STATE_DONE "DONE"

#include <hiredis/hiredis.h>

void usage(void)
{
    
    printf("pcapdj [-h] -b namedpipe [-s redis_server] -p [redis_srv_port]\n\n");
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

void wait_auth_to_proceed(redisContext* ctx, char* filename)
{
    redisReply *reply;
    /* If there is an error the program waits forever */
    
    do {
        reply = redisCommand(ctx,"GET %s",AKEY);
        if (reply){
            if (reply->type == REDIS_REPLY_STRING) {
                if (!strncmp(reply->str, filename, strlen(filename))) {
                    fprintf(stderr, "Got authorization to proceed\n");
                    freeReplyObject(reply);
                    return;
                }else{
                    //fprintf(stderr,"Got the wrong authorization. Waited for (%s). Got %s.\n", filename, reply->str);
                }
            }       
            freeReplyObject(reply);
        }else{
            fprintf(stderr,"redis server did not replied for the authorization\n");
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
    wth = wtap_open_offline ( filename, (int*)&err, (char**)&errinfo, FALSE);
    if (wth) {
        /* Loop over the packets and adjust the headers */
        while (wtap_read(wth, &err, &errinfo, &data_offset)) {
            phdr = wtap_phdr(wth);
            buf = wtap_buf_ptr(wth);
            pchdr.caplen = phdr->caplen;
            pchdr.len = phdr->len;
            pchdr.ts.tv_sec = phdr->ts.secs;
            /* Need to convert micro to nano seconds */
            pchdr.ts.tv_usec = phdr->ts.nsecs/1000;
            pcap_dump((u_char*)dumper, &pchdr, buf);
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
        fprintf(stderr,"Could not connect to redis. %s.\n", ctx->errstr);
        return EXIT_FAILURE;
    }
    

    do {
        reply = redisCommand(ctx,"LPOP %s", PQUEUE); 
        if (!reply){
            fprintf(stderr,"Redis error %s\n",ctx->errstr);
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
 
int main(int argc, char* argv[])
{

    int opt;
    int r;
    char* redis_server;
    int redis_srv_port; 
    char *namedpipe;
    pcap_t *pcap;
    pcap_dumper_t *dumper;
    namedpipe = calloc(128,1);
    assert(namedpipe);  
    
    redis_server = calloc(64,1);
    assert(redis_server);

    redis_srv_port = 6379;        
    while ((opt = getopt(argc, argv, "b:hs:p:")) != -1) {
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
            case 'h':
                usage();
                return EXIT_SUCCESS;
            default: /* '?' */
                fprintf(stderr, "Invalid command line was specified\n");
        }
    }
    /* Set default values if needed */
    if (!redis_server[0])
        strncpy(redis_server,DEFAULT_SRV,64);
    /* Connect to redis */
    if (!namedpipe[0]){
        fprintf(stderr,"A named pipe must be specified\n");
        return EXIT_FAILURE; 
    }

    printf("redis_server = %s\n",redis_server);
    printf("redis_port = %d\n",redis_srv_port);
    printf("named pipe = %s\n", namedpipe);

    /* Open the pcap named pipe */
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap) {
        printf("Waiting for other peer (IDS, tcp-reassembly engine, etc)...\n");
        dumper = pcap_dump_open(pcap, namedpipe);
        if (dumper) {
            r = process_input_queue(dumper, redis_server, redis_srv_port);
            if (r == EXIT_FAILURE) {
                fprintf(stderr,"Something went wrong in during processing");
            }else{
                fprintf(stderr,"All went fine\n");
            }
            /* In all case close the connection */
            pcap_dump_close(dumper);
            return r;
        }else {
            fprintf(stderr,"pcap dumper failed\n");
        }
        pcap_close(pcap);
    }else {
        fprintf(stderr, "pcap_open_dead failed\n");
    }
    return EXIT_FAILURE;
}

