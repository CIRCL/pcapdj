pcapdj
======

pcapdj - dispatch pcap files

Network captures often result in very large files. Therefore, tools like
tcpdump or dumpcap offer features of file rotation either after a fixed
size or a fixed amount of time.

When these files are analyzed focusing on stateful protocols such as TCP, 
TCP sessions could have been established in one pcap file and continue in
the next pcap files. When these TCP sessions have to be properly reassembled,
then either the TCP reassembly tool has to support multiple pcap files as
input or the pcap files have to merged in a single file using for instance a
tool such as editcap. However, in this case, very large files are the results,
that were tried to be avoided with the file rotation. 

PCAPDJ processes a list of pcap files and write each individual packet in a
named pipe. A second process reads these individual packets and does some
processing. A third process, does some cleanup operations and controls pcapdj. 

Each pcap file that is processed by pcapdj must be authorized by a third process. 
When a pcap file is not acknowledged the file descriptor to the named pipe
is not closed and hence the other program processing pcap data does not end and
keeps its internal states. Before a next file is authorized, other tasks could be done, 
such as removing duplicated files or already processed pcap files in order to free disk space. 


Building PCAPDJ
===============

Dependencies
------------


In an Ubuntu 12.04 Operating system the following packages must be installed.

apt-get install libwiretap-dev libpcap-dev libhiredis-dev libglib2.0-dev

Compiling
---------

unzip pcapdj-master.zip

cd pcapdj-master

make

Use case with Suricata
----------------------

The Suricata IDS can be configured to extract all HTTP payloads [1].
This feature is used in the following example in conjunction with pcapdj
feeding suricata with multiple pcap files.

Import the pcap files that should be processed by pcapdj

```python
#!/usr/bin/python
import redis
import os
root="mypcapfiledir"
red = redis.Redis()
files = os.listdir(root)
files.sort()
for rf in files:
    f = root + "/"+rf
    if f.endswith('pcap') == True:
        red.rpush("PCAPDJ_IN_QUEUE",f)
```

Create a name pipe that is shared between pcapdj and suricta
```
mkfifo /tmp/pcapbuffer
```

Launch pcapdj
```
 ./pcapdj -b /tmp/pcapbuffer 
redis_server = 127.0.0.1
redis_port = 6379
named pipe = /tmp/pcapbuffer
Waiting for other peer (IDS, tcp-reassembly engine, etc)...
PCAPDJ waits for the consumer of the fifo bufer. In this case suricata.
```

Launch suricata

```
suricata -r /tmp/pcapbuffer 
```

Until now no packets are put in the buffer because pcapdj needs an
authorization. PCAPDJ says that it is ready to process the pcapfile 1.pcap
and that it waits for this authorization.  For doing so, pcapdj puts the
next file it wants to process in a queue called PCAPDJ_NEXT and it polls the
key PCAPDJ_AUTH. The value of PCAPDJ_AUTH must correspond to the file pcapdj 
put previously in the queue PCAPDJ_NEXT.

```
[INFO] Next file to process /tmp/testpcaps/1.pcap
[INFO] Waiting authorization to process file /tmp/testpcaps/2.pcap
```

Launch the controler script that authorizes each pcap file that is put 
in the named pipe.

```python
while True:
    #Check if some data is ready to be process
    pcapname = red.lpop("PCAPDJ_NEXT")
    if pcapname != None:
        print "Authorized file ",pcapname
        red.set("PCAPDJ_AUTH", pcapname)
```

Wait until pcapdj and suricata are done

Experimental features
=====================

On the experimental branch two new features were implemented based on 
a signal handler.

Suspending PCAPDJ
-----------------

If PCAPDJ is processing a large file and the resources are at the point of
being exhausted, the command kill -SIGUSR1 <pid of pcap dj> can be executed.
PCAPDJ stops feeding the fifo buffer and resources can be manually freed 
without terminating the consumer program.

Once, the machine is cleaned up, PCAPDJ can be resumed by sending a second
time the SIGUSR1 signal.

Display Accounting Data
-----------------------

When PCAPDJ is running for a while, it might be interesting to determine
what is happening. The signal SIGUSR2 can be sent to PCAPDJ. PCAPDJ 
shows then following information on standard output.

-  A timestamp when PCAPDJ started 
-  The number of seconds elapsed since PCAPDJ started
-  The internal state of PCAPDJ
-  The number of times PCAPDJ has been suspended
-  The number of files PCAPDJ processed
-  The number of packets PCAPDJ processed
-  The sum of the cap length fields
-  The sum of the length fields. If the sum of lengths is different from
   the sum of cap lengths then the capture is incomplete. 
 
An example is shown below:

```
[STATS] Start time:2013-06-09 09:17:50
[STATS] Uptime:322 (seconds)
[STATS] Internal state:Waiting for authorization
[STATS] Number of suspensions:0
[STATS] Number of files:1
[STATS] Number of packets:2968
[STATS] Number of cap_lengths:330581
[STATS] Number of lengths:330581
```
References
==========
[1] http://blog.inliniac.net/2011/11/29/file-extraction-in-suricata/
