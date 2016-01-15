# sflowtool
Print binary sFlow feed to ASCII,  or forward it to other collectors.

This tool receives sFlow data, and generates either a simple-to-parse tagged-ASCII output,
or binary output in tcpdump(1) format. It can also generate Cisco NetFlow version 5 datagrams
and send them to a destination UDP host:port,  or forward the original sFlow feed to a number
of additional collectors.

Please read the licence terms in ./COPYING.

For more details on the sFlow data format, see http://www.sflow.org.

# Build from sources

	./boot.sh
	./configure
	make
	sudo make install

(Start from ./configure if you downloaded a released version.)

# Usage examples

If sFlow is arriving on port 6343, you can pretty-print the data like this:

% ./sflowtool -p 6343

or get a line-by-line output like this:

% ./sflowtool -p 6434 -l

In a typical application, this output would be parsed by an awk or perl script, perhaps to
extract MAC->IP address-mappings or to extract a particular counter for trending. The
usage might then look more like this:

% ./sflowtool -p 6343 | my_perl_script.pl > output

Alternatively, you can show packet decodes like this:

% ./sflowtool -p 6343 -t | tcpdump -r -

To forward Cisco NetFlow v5 records to UDP port 9991 on host collector.mysite.com, the
options would be:

% ./sflowtool -p 6343 -c collector.mysite.com -d 9991

If you compiled with -DSPOOFSOURCE, then you have the option of "spoofing" the IP source
address of the netflow packets to match the IP address(es) of the original sflow agent(s)...

% ./sflowtool -p 6343 -c collector.mysite.com -d 9991 -S

To replicate the input sflow stream to several collectors, use the "-f host/port" option
like this:

% ./sflowtool -p 6343 -f localhost/7777 -f localhost/7778 -f collector.mysite.com/6343


# Example Output

An example of the pretty-printed output is shown below. Note that every field can be
parsed as two space-separated tokens (tag and value). Newlines separate one field from
the next. The first field in a datagram is always the "unixSecondsUTC" field, and the
first field in a flow or counters sample is always the "sampleSequenceNo" field. In
this example, the datagram held two flow-samples and two counters-samples. Comments
have been added in <<>> brackets.  These are not found in the output.

     unixSecondsUTC 991362247      <<this is always the first field of a new datagram>>
     datagramVersion 2
     agent 10.0.0.254              <<the sFlow agent>>
     sysUpTime 10391000
     packetSequenceNo 5219         <<the sequence number for datagrams from this agent>>
     samplesInPacket 4
     sampleSequenceNo 9466         <<the sequence number for the first sample - a flow sample from 0:0>>
     sourceId 0:0
     sampleType FLOWSAMPLE
     meanSkipCount 10
     samplePool 94660
     dropEvents 0
     inputPort 14
     outputPort 16
     packetDataTag INMPACKETTYPE_HEADER
     headerProtocol 1
     sampledPacketSize 1014
     headerLen 128
     headerBytes 00-50-04-29-1B-D9-00-D0-B7-23-B7-D8-08-00-45-00-03-E8-37-44-40-00-40-06-EB-C6-0A-00-00-01-0A-00-00-05-0D-F1-17-70-A2-4C-D2-AF-B1-F0-BF-01-80-18-7C-70-82-E0-00-00-01-01-08-0A-23-BC-42-93-01-A9-
     dstMAC 005004291bd9               <<a rudimentary decode, which assumes an ethernet packet format>>
     srcMAC 00d0b723b7d8
     srcIP 10.0.0.1
     dstIP 10.0.0.5
     IPProtocol 6
     TCPSrcPort 3569
     TCPDstPort 6000
     TCPFlags 24
     extendedType ROUTER               <<we have some layer3 forwarding information here too>>
     nextHop 129.250.28.33
     srcSubnetMask 24
     dstSubnetMask 24
     sampleSequenceNo 346              <<the next sample is a counters sample from 0:92>>
     sourceId 0:92
     sampleType COUNTERSSAMPLE
     statsSamplingInterval 20
     counterBlockVersion 1
     ifIndex 92
     networkType 53
     ifSpeed 0
     ifDirection 0
     ifStatus 0
     ifInOctets 18176791
     ifInUcastPkts 92270
     ifInMulticastPkts 0
     ifInBroadcastPkts 100
     ifInDiscards 0
     ifInErrors 0
     ifInUnknownProtos 0
     ifOutOctets 40077590
     ifOutUcastPkts 191170
     ifOutMulticastPkts 1684
     ifOutBroadcastPkts 674
     ifOutDiscards 0
     ifOutErrors 0
     ifPromiscuousMode 0
     sampleSequenceNo 9467             <<another flow sample from 0:0>>
     sourceId 0:0
     sampleType FLOWSAMPLE
     meanSkipCount 10
     samplePool 94670
     dropEvents 0
     inputPort 16
     outputPort 14
     packetDataTag INMPACKETTYPE_HEADER
     headerProtocol 1
     sampledPacketSize 66
     headerLen 66
     headerBytes 00-D0-B7-23-B7-D8-00-50-04-29-1B-D9-08-00-45-00-00-34-1E-D7-40-00-40-06-07-E8-0A-00-00-05-0A-00-00-01-17-70-0D-F1-B1-F0-BF-01-A2-4C-E3-A3-80-10-7C-70-E2-62-00-00-01-01-08-0A-01-A9-7F-A0-23-BC-
     dstMAC 00d0b723b7d8
     srcMAC 005004291bd9
     srcIP 10.0.0.5
     dstIP 10.0.0.1
     IPProtocol 6
     TCPSrcPort 6000
     TCPDstPort 3569
     TCPFlags 16
     extendedType ROUTER
     nextHop 129.250.28.33
     srcSubnetMask 24
     dstSubnetMask 24
     sampleSequenceNo 346             <<and another counters sample, this time from 0:93>>
     sourceId 0:93
     sampleType COUNTERSSAMPLE
     statsSamplingInterval 30
     counterBlockVersion 1
     ifIndex 93
     networkType 53
     ifSpeed 0
     ifDirection 0
     ifStatus 0
     ifInOctets 103959
     ifInUcastPkts 448
     ifInMulticastPkts 81
     ifInBroadcastPkts 93
     ifInDiscards 0
     ifInErrors 0
     ifInUnknownProtos 0
     ifOutOctets 196980
     ifOutUcastPkts 460
     ifOutMulticastPkts 599
     ifOutBroadcastPkts 153
     ifOutDiscards 0
     ifOutErrors 0
     ifPromiscuousMode 0


# Other ExtendedTypes

If your sFlow agent is running BGP, you may also see GATEWAY extendedType sections like this:

   extendedType GATEWAY
   my_as 65001
   src_as 0
   src_peer_as 0
   dst_as_path_len 3
   dst_as_path 65000-2828-4908


The SWITCH, USER and URL extendedTypes may also appear. The SWITCH extendedType provides
information on input and output VLANs and priorities. The USER extendedType provides
information on the user-id that was allocated this IP address via a remote access session
(e.g. RADIUS or TACAS). The URL field indicates for an HTTP flow what the original requested
URL was for the flow.  For more information, see the published sFlow documentation at
http://www.sflow.org.


# line-by-line csv output

If you run sflowtool using the "-l" option then only one row of output will be generated
for each flow or counter sample. It will look something like this:

    [root@server src]# ./sflowtool -l
    CNTR,10.0.0.254,17,6,100000000,0,2147483648,175283006,136405187,2578019,297011,0,3,0,0,0,0,0,0,0,1
    FLOW,10.0.0.254,0,0,00902773db08,001083265e00,0x0800,0,0,10.0.0.1,10.0.0.254,17,0x00,64,35690,161,0x00,143,125,80

The counter samples are indicated with the "CNTR" entry in the first column.
The second column is the agent address.  The remaining columns are the
fields from the generic counters structure (see SFLIf_counters in sflow.h).

The flow samples are indicated with the "FLOW" entry in the first column.
The second column is the agent address. The remaining columns are:

    inputPort
    outputPort
    src_MAC
    dst_MAC
    ethernet_type
    in_vlan
    out_vlan
    src_IP
    dst_IP
    IP_protocol
    ip_tos
    ip_ttl
    udp_src_port OR tcp_src_port OR icmp_type
    udp_dst_port OR tcp_dst_port OR icmp_code
    tcp_flags
    packet_size
    IP_size
    sampling_rate


# grep-friendly output

Adding the "-g" option causes sflowtool to include contextual information on every
line of output.  The fields are:

     agentIP
     agentSubId
     datasource_sequenceNo
     datasource_class
     datasource_index
     sampletype_tag
     elementtype_tag

For example,  this makes it much easier to extract a particular counter for each agent,
accumulate the deltas, and stream it to a time-series database.

---
----------------------------------------
Neil McKee (neil.mckee@inmon.com)
InMon Corp. http://www.inmon.com

