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

=Building PCAPDJ=
==Dependencies==
In an Ubuntu 12.04 Operating system the following packages must be installed.

apt-get install libwiretap-dev libpcap-dev libhiredis-dev libglib2.0-dev


==Compiling==

unzip pcapdj-master.zip

cd pcapdj-master

make

