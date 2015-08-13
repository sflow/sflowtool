#!/usr/bin/rrdcgi
# Copyright (c) 2001 InMon Corp. Licensed under the terms of the InMon sFlow licence:
# http://www.inmon.com/technology/sflowlicense.txt
<HTML>
<HEAD><TITLE>Interface Traffic</TITLE></HEAD>
<BODY>
<H1>Interface Load</H1>
<H2>Selection</H2>
<FORM>
Agent:<INPUT NAME=AGENT TYPE=TEXT SIZE=20 VALUE=<RRD::CV::QUOTE AGENT>>
ifIndex:<INPUT NAME=IFINDEX TYPE=TEXT SIZE=10 VALUE=<RRD::CV::QUOTE IFINDEX>>
<INPUT TYPE=SUBMIT>
</FORM>
<H2>Graph</H2>
<P>
<RRD::GRAPH images/<RRD::CV::QUOTE AGENT>-<RRD::CV::QUOTE IFINDEX>.gif
      --lazy
      --title "Agent="<RRD::CV::QUOTE AGENT>" ifIndex="<RRD::CV::QUOTE IFINDEX>
      --vertical-label "Bits Per Second"
      DEF:bytesIn=ifdata/<RRD::CV::QUOTE AGENT>-<RRD::CV::QUOTE IFINDEX>.rrd:bytesIn:AVERAGE
      DEF:bytesOut=ifdata/<RRD::CV::QUOTE AGENT>-<RRD::CV::QUOTE IFINDEX>.rrd:bytesOut:AVERAGE
      CDEF:bpsOut=bytesOut,8,*
      CDEF:bpsIn=0,bytesIn,8,*,-
      AREA:bpsOut#0022e9:out
      AREA:bpsIn#00b674:in>
</P>
</BODY>
</HTML>
