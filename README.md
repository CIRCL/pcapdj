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

Each pcap file that is processed by pcapdj must be authorized by a third process. When a pcap file is not acknowledged the file descriptor to the named pipe
is not closed and hence the other program processing pcap data does not end and
keeps its internal states.

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

Use Case with Suricata
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

References
==========
[1] http://blog.inliniac.net/2011/11/29/file-extraction-in-suricata/
