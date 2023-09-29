/* Copyright (c) 2002-2019 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#if defined(__cplusplus)
extern "C" {
#endif

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <setjmp.h>
#include <ctype.h>
#include <search.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <byteswap.h>
#include <getopt.h>

#include "sflow.h" /* sFlow v5 */
#include "sflow_v2v4.h" /* sFlow v2/4 */
#include "assert.h"
#include "sflow_xdr.h" /* sFlow encode */

#define SPOOFSOURCE 1
#define YES 1
#define NO 0

/* define my own IP header struct - to ease portability */
struct myiphdr
  {
    uint8_t version_and_headerLen;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

/* ip6 header if no option headers */
struct myip6hdr {
  uint8_t version_and_priority;
  uint8_t priority_and_label1;
  uint8_t label2;
  uint8_t label3;
  uint16_t payloadLength;
  uint8_t nextHeader;
  uint8_t ttl;
  struct in6_addr saddr;
  struct in6_addr daddr;
};

/* same for tcp */
struct mytcphdr
  {
    uint16_t th_sport;		/* source port */
    uint16_t th_dport;		/* destination port */
    uint32_t th_seq;		/* sequence number */
    uint32_t th_ack;		/* acknowledgement number */
    uint8_t th_off_and_unused;
    uint8_t th_flags;
    uint16_t th_win;		/* window */
    uint16_t th_sum;		/* checksum */
    uint16_t th_urp;		/* urgent pointer */
};

/* and UDP */
struct myudphdr {
  uint16_t uh_sport;           /* source port */
  uint16_t uh_dport;           /* destination port */
  uint16_t uh_ulen;            /* udp length */
  uint16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct myicmphdr
{
  uint8_t type;		/* message type */
  uint8_t code;		/* type sub-code */
  /* ignore the rest */
};

#ifdef SPOOFSOURCE
#define SPOOFSOURCE_SENDPACKET_SIZE 2000
struct mySendPacket {
  struct myiphdr ip;
  struct myudphdr udp;
  uint8_t data[SPOOFSOURCE_SENDPACKET_SIZE];
};
#endif

/* tcpdump file format */

struct pcap_file_header {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  uint32_t thiszone;	/* gmt to local correction */
  uint32_t sigfigs;	/* accuracy of timestamps */
  uint32_t snaplen;	/* max length saved portion of each pkt */
  uint32_t linktype;	/* data link type (DLT_*) */
};

struct pcap_pkthdr {
  uint32_t ts_sec;	/* time stamp - used to be struct timeval, but time_t can be 64 bits now */
  uint32_t ts_usec;
  uint32_t caplen;	/* length of portion present */
  uint32_t len;	/* length this packet (off wire) */
  /* some systems expect to see more information here. For example,
   * on some versions of RedHat Linux, there are three extra fields:
   *   int index;
   *   unsigned short protocol;
   *   unsigned char pkt_type;
   */
};

typedef struct _SFForwardingTarget {
  struct _SFForwardingTarget *nxt;
  struct sockaddr_in addr;
  int sock;
} SFForwardingTarget;

typedef struct _SFForwardingTarget6 {
  struct _SFForwardingTarget6 *nxt;
  struct sockaddr_in6 addr;
  int sock;
} SFForwardingTarget6;

typedef union _SFSockAddr {
  struct sockaddr_in sa4;
  struct sockaddr_in6 sa6;
} SFSockAddr;

typedef enum { SFLFMT_FULL=0,
	       SFLFMT_PCAP,
	       SFLFMT_PCAP_DISCARD,
	       SFLFMT_LINE,
	       SFLFMT_LINE_CUSTOM,
	       SFLFMT_NETFLOW,
	       SFLFMT_FWD,
	       SFLFMT_CLF,
	       SFLFMT_SCRIPT,
	       SFLFMT_JSON,
	       SFLFMT_SFLOW
} EnumSFLFormat;

#define SA_MAX_PCAP_PKT 65536
#define SA_MAX_SFLOW_PKT_SIZ 65536

#define SA_MAX_FIELDNAME_LEN 64
#define SA_MAX_FIELD_PREFIX 4

#define MAX_STRBUF_LEN 2048
typedef struct {
  int cap;
  int len;
  char str[MAX_STRBUF_LEN];
} SFStr;

typedef enum { SFSCOPE_NONE, SFSCOPE_DATAGRAM, SFSCOPE_SAMPLE } EnumSFScope;

typedef struct _SFFieldList {
  int n;
  char **fields;
  SFStr *values;
  /* dynamic info */
  char *fieldScope;
  int sampleFields;
} SFFieldList;

typedef struct _SFConfig {
  /* sflow(R) options */
  uint16_t sFlowInputPort;
  /* netflow(TM) options */
  uint16_t netFlowOutputPort;
  SFLAddress netFlowOutputIP;
  SFSockAddr netFlowOutputSA;
  int netFlowOutputSocket;
  uint16_t netFlowPeerAS;
  int disableNetFlowScale;
  uint16_t netFlowVersion;
  /* tcpdump options */
  char *readPcapFileName;
  FILE *readPcapFile;
  struct pcap_file_header readPcapHdr;
  int pcapSwap;
  /* sFlow-from-pcap generator */
  uint32_t pcapSamplingN;
  SFDDgram *sFlowDatagram;
  uint64_t pcap_uS;
  double playback;
  uint32_t output_sample_pool;
  uint32_t output_sample_seqNo;
  int output_sample_skip;
  EnumSFLFormat outputFormat;
  /* JSON */
  int jsonIndent;
  int jsonStart;
  int jsonListStart;
  int outputDepth;
  SFFieldList outputFieldList;
  EnumSFScope currentFieldScope;

#ifdef SPOOFSOURCE
  int spoofSource;
  uint16_t ipid;
  struct mySendPacket sendPkt;
  uint32_t packetLen;
#endif

  SFForwardingTarget *forwardingTargets;
  SFForwardingTarget6 *forwardingTargets6;

  /* vlan filtering */
  int gotVlanFilter;
#define FILTER_MAX_VLAN 4096
  uint8_t vlanFilter[FILTER_MAX_VLAN + 1];

  /* content stripping */
  int removeContent;

  /* options to restrict IP socket / bind */
  int listen4;
  int listen6;
  int listenControlled;

  /* general options */
  int keepGoing;
  int allowDNS;
  /* Anonymize */
  int anonymize;

} SFConfig;

/* make the options structure global to the program */
static SFConfig sfConfig;

/* define a separate global we can use to construct the common-log-file format */
typedef struct _SFCommonLogFormat {
#define SFLFMT_CLF_MAX_LINE 2000
#define SFLFMT_CLF_MAX_CLIENT_LEN 64
  int valid;
  char client[SFLFMT_CLF_MAX_CLIENT_LEN];
  char http_log[SFLFMT_CLF_MAX_LINE];
} SFCommonLogFormat;

static SFCommonLogFormat sfCLF;
static const char *SFHTTP_method_names[] = { "-", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT" };

typedef struct _SFSample {
  /* the raw pdu */
  uint8_t *rawSample;
  uint32_t rawSampleLen;
  uint8_t *endp;
  time_t pcapTimestamp;
  time_t readTimestamp;

  /* decode cursor */
  uint32_t *datap;

  /* datagram fields */
  SFLAddress sourceIP;
  SFLAddress agent_addr;
  uint32_t agentSubId;
  uint32_t datagramVersion;
  uint32_t sysUpTime;
  uint32_t sequenceNo;

  /* per-element fields */
  struct {
    uint32_t prefixCount;
    char *fieldPrefix[SA_MAX_FIELD_PREFIX];

    uint32_t sampleType;
    uint32_t elementType;
    uint32_t ds_class;
    uint32_t ds_index;

    /* generic interface counter sample */
    SFLIf_counters ifCounters;

    /* data-source stream info */
    uint32_t samplesGenerated;
    uint32_t meanSkipCount;
    uint32_t samplePool;
    uint32_t dropEvents;

    /* the sampled header */
    uint32_t sampledPacketSize;
    uint32_t packet_data_tag;
    uint32_t headerProtocol;
    uint8_t *header;
    uint32_t headerLen;
    uint32_t stripped;

    /* header decode */
    int gotIPV4;
    int gotIPV4Struct;
    int offsetToIPV4;
    int gotIPV6;
    int gotIPV6Struct;
    int offsetToIPV6;
    int offsetToPayload;
    SFLAddress ipsrc;
    SFLAddress ipdst;
    uint32_t dcd_ipProtocol;
    uint32_t dcd_ipTos;
    uint32_t dcd_ipTTL;
    uint32_t dcd_sport;
    uint32_t dcd_dport;
    uint32_t dcd_tcpFlags;
    uint32_t dcd_flowLabel;
    uint32_t ip_fragmentOffset;
    uint32_t udp_pduLen;

    /* ports */
    uint32_t inputPortFormat;
    uint32_t outputPortFormat;
    uint32_t inputPort;
    uint32_t outputPort;

    /* ethernet */
    uint32_t eth_type;
    uint32_t eth_len;
    uint8_t eth_src[8];
    uint8_t eth_dst[8];

    /* vlan */
    uint32_t in_vlan;
    uint32_t in_priority;
    uint32_t internalPriority;
    uint32_t out_vlan;
    uint32_t out_priority;
    int vlanFilterReject;

    /* extended data fields */
    uint32_t num_extended;
    uint32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096
#define SASAMPLE_EXTENDED_DATA_NAT_PORT 8192

    /* IP forwarding info */
    SFLAddress nextHop;
    uint32_t srcMask;
    uint32_t dstMask;

    /* BGP info */
    SFLAddress bgp_nextHop;
    uint32_t my_as;
    uint32_t src_as;
    uint32_t src_peer_as;
    uint32_t dst_as_path_len;
    uint32_t *dst_as_path;
    /* note: version 4 dst as path segments just get printed, not stored here, however
     * the dst_peer and dst_as are filled in, since those are used for netflow encoding
     */
    uint32_t dst_peer_as;
    uint32_t dst_as;

    uint32_t communities_len;
    uint32_t *communities;
    uint32_t localpref;

    /* mpls */
    SFLAddress mpls_nextHop;

    /* nat */
    SFLAddress nat_src;
    SFLAddress nat_dst;

    /* counter blocks */
    uint32_t statsSamplingInterval;
    uint32_t counterBlockVersion;
  } s;

  /* exception handler context */
  jmp_buf env;

#define ERROUT stderr

#ifdef DEBUG
# define SFABORT(s, r) abort()
# undef ERROUT
# define ERROUT stdout
#else
# define SFABORT(s, r) longjmp((s)->env, (r))
#endif

#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

} SFSample;

/* Cisco netflow version 5 record format */

typedef struct _NFFlow5 {
  uint32_t srcIP;
  uint32_t dstIP;
  uint32_t nextHop;
  uint16_t if_in;
  uint16_t if_out;
  uint32_t frames;
  uint32_t bytes;
  uint32_t firstTime;
  uint32_t lastTime;
  uint16_t srcPort;
  uint16_t dstPort;
  uint8_t pad1;
  uint8_t tcpFlags;
  uint8_t ipProto;
  uint8_t ipTos;
  uint16_t srcAS;
  uint16_t dstAS;
  uint8_t srcMask;  /* No. bits */
  uint8_t dstMask;  /* No. bits */
  uint16_t pad2;
} NFFlow5;

typedef struct _NFFlowHdr5 {
  uint16_t version;
  uint16_t count;
  uint32_t sysUpTime;
  uint32_t unixSeconds;
  uint32_t unixNanoSeconds;
  uint32_t flowSequence;
  uint8_t engineType;
  uint8_t engineId;
  uint16_t sampling_interval;
} NFFlowHdr5;

typedef struct _NFFlowPkt5 {
  NFFlowHdr5 hdr;
  NFFlow5 flow; /* normally an array, but here we always send just 1 at a time */
} NFFlowPkt5;

/* Cisco NetFlow version 9 format */

/* NetFlow v9/ipfix element ids */

#define ID_SRC_IP 8
#define ID_DST_IP 12
#define ID_NEXT_HOP 15
#define ID_IF_IN 10
#define ID_IF_OUT 14
#define ID_PACKETS 2
#define ID_BYTES 1
#define ID_FIRST_SWITCHED 22
#define ID_LAST_SWITCHED 21
#define ID_SRC_PORT 7
#define ID_DST_PORT 11
#define ID_TCP_FLAGS 6
#define ID_PROTOCOL 4
#define ID_TOS 5
#define ID_SRC_AS 16
#define ID_DST_AS 17
#define ID_SRC_MASK 9
#define ID_DST_MASK 13
#define ID_SAMPLING_INTERVAL 34
#define ID_SRC_IP6 27
#define ID_DST_IP6 28
#define ID_NEXT_HOP_IP6 62
#define ID_FLOW_LABEL_IP6 31

/* NetFlow v9/ipfix element sizes */

#define SZ_SRC_IP 4
#define SZ_DST_IP 4
#define SZ_NEXT_HOP 4
#define SZ_IF_IN 4
#define SZ_IF_OUT 4
#define SZ_PACKETS 4
#define SZ_BYTES 4
#define SZ_FIRST_SWITCHED 4
#define SZ_LAST_SWITCHED 4
#define SZ_SRC_PORT 2
#define SZ_DST_PORT 2
#define SZ_TCP_FLAGS 1
#define SZ_PROTOCOL 1
#define SZ_TOS 1
#define SZ_SRC_AS 4
#define SZ_DST_AS 4
#define SZ_SRC_MASK 1
#define SZ_DST_MASK 1
#define SZ_SAMPLING_INTERVAL 4
#define SZ_SRC_IP6 16
#define SZ_DST_IP6 16
#define SZ_NEXT_HOP_IP6 16
#define SZ_FLOW_LABEL_IP6 4
  
/* NetFlow v9/ipfix element type */

typedef struct _NFField9 {
  uint16_t id;
  uint16_t sz;
} __attribute__ ((packed)) NFField9;

/* NetFlow v9/ipfix (id, sz) pairs for each element */

static const NFField9 nfField9[] = {
 { ID_SRC_IP, SZ_SRC_IP },
 { ID_DST_IP, SZ_DST_IP },
 { ID_NEXT_HOP, SZ_NEXT_HOP },
 { ID_IF_IN, SZ_IF_IN },
 { ID_IF_OUT, SZ_IF_OUT },
 { ID_PACKETS, SZ_PACKETS },
 { ID_BYTES, SZ_BYTES },
 { ID_FIRST_SWITCHED, SZ_FIRST_SWITCHED },
 { ID_LAST_SWITCHED, SZ_LAST_SWITCHED },
 { ID_SRC_PORT, SZ_SRC_PORT },
 { ID_DST_PORT, SZ_DST_PORT },
 { ID_TCP_FLAGS, SZ_TCP_FLAGS },
 { ID_PROTOCOL, SZ_PROTOCOL },
 { ID_TOS, SZ_TOS },
 { ID_SRC_AS, SZ_SRC_AS },
 { ID_DST_AS, SZ_DST_AS },
 { ID_SRC_MASK, SZ_SRC_MASK },
 { ID_DST_MASK, SZ_DST_MASK },
 { ID_SAMPLING_INTERVAL, SZ_SAMPLING_INTERVAL }
 };

static const NFField9 nfField9_v6[] = {
 { ID_SRC_IP6, SZ_SRC_IP6 },
 { ID_DST_IP6, SZ_DST_IP6 },
 { ID_NEXT_HOP_IP6, SZ_NEXT_HOP_IP6 },
 { ID_IF_IN, SZ_IF_IN },
 { ID_IF_OUT, SZ_IF_OUT },
 { ID_PACKETS, SZ_PACKETS },
 { ID_BYTES, SZ_BYTES },
 { ID_FIRST_SWITCHED, SZ_FIRST_SWITCHED },
 { ID_LAST_SWITCHED, SZ_LAST_SWITCHED },
 { ID_FLOW_LABEL_IP6, SZ_FLOW_LABEL_IP6 },
 { ID_SRC_PORT, SZ_SRC_PORT },
 { ID_DST_PORT, SZ_DST_PORT },
 { ID_TCP_FLAGS, SZ_TCP_FLAGS },
 { ID_PROTOCOL, SZ_PROTOCOL },
 { ID_TOS, SZ_TOS },
 { ID_SRC_AS, SZ_SRC_AS },
 { ID_DST_AS, SZ_DST_AS },
 { ID_SRC_MASK, SZ_SRC_MASK },
 { ID_DST_MASK, SZ_DST_MASK },
 { ID_SAMPLING_INTERVAL, SZ_SAMPLING_INTERVAL }
 };

/* The NetFlow v9 flow will be shaped similarly to v5,
 * but we move sampling interval from the v5 header into
 * the flow dataset and expand the interface field widths. */

typedef struct _NFFlow9 {
  uint32_t srcIP;
  uint32_t dstIP;
  uint32_t nextHop;
  uint32_t if_in;
  uint32_t if_out;
  uint32_t packets;
  uint32_t bytes;
  uint32_t firstTime;
  uint32_t lastTime;
  uint16_t srcPort;
  uint16_t dstPort;
  uint8_t tcpFlags;
  uint8_t ipProto;
  uint8_t ipTos;
  uint32_t srcAS;
  uint32_t dstAS;
  uint8_t srcMask;
  uint8_t dstMask;
  uint32_t samplingInterval;
#define NFFLOW9_NUM_ELEMENTS 19
} __attribute__ ((packed)) NFFlow9;

typedef struct _NFFlow9_v6 {
  uint32_t srcIP6[4];
  uint32_t dstIP6[4];
  uint32_t nextHopIP6[4];
  uint32_t if_in;
  uint32_t if_out;
  uint32_t packets;
  uint32_t bytes;
  uint32_t firstTime;
  uint32_t lastTime;
  uint32_t flowLabel;
  uint16_t srcPort;
  uint16_t dstPort;
  uint8_t tcpFlags;
  uint8_t ipProto;
  uint8_t ipTos;
  uint32_t srcAS;
  uint32_t dstAS;
  uint8_t srcMask;
  uint8_t dstMask;
  uint32_t samplingInterval;
#define NFFLOW9_V6_NUM_ELEMENTS 20
} __attribute__ ((packed)) NFFlow9_v6;
  

/* NetFlow v9 template flowset */

typedef struct _NFTemplateFlowSet9 {
  uint16_t setId;
  uint16_t length;
  uint16_t templateId;
#define NFTEMPLATE_IPV4 256
#define NFTEMPLATE_IPV6 257
  uint16_t fieldCount;
  NFField9 field[NFFLOW9_NUM_ELEMENTS];
} __attribute__ ((packed)) NFTemplateFlowSet9;

typedef struct _NFTemplateFlowSet9_v6 {
  uint16_t setId;
  uint16_t length;
  uint16_t templateId;
  uint16_t fieldCount;
  NFField9 field[NFFLOW9_V6_NUM_ELEMENTS];
} __attribute__ ((packed)) NFTemplateFlowSet9_v6;


/* NetFlow v9 data flowset */

typedef struct _NFDataFlowSet9 {
  uint16_t templateId;
  uint16_t length;
  NFFlow9 flow;
} __attribute__ ((packed)) NFDataFlowSet9;

  typedef struct _NFDataFlowSet9_v6 {
  uint16_t templateId;
  uint16_t length;
  NFFlow9_v6 flow;
} __attribute__ ((packed)) NFDataFlowSet9_v6;


/* NetFlow v9 flow packet header */

typedef struct _NFFlowHeader9 {
  uint16_t version;
  uint16_t count;
  uint32_t sysUpTime;
  uint32_t unixSeconds;
  uint32_t flowSequence;
  uint32_t sourceId;
} __attribute__ ((packed)) NFFlowHeader9;


/* NetFlow v9 flow packet */

typedef struct _NFFlowPkt9 {
  NFFlowHeader9 hdr;
  NFTemplateFlowSet9 tmpl;
  NFDataFlowSet9 data;
} __attribute__ ((packed)) NFFlowPkt9;

  typedef struct _NFFlowPkt9_v6 {
  NFFlowHeader9 hdr;
  NFTemplateFlowSet9_v6 tmpl;
  NFDataFlowSet9_v6 data;
} __attribute__ ((packed)) NFFlowPkt9_v6;


/* NetFLow packet can be either v5 or v9 or v9v6 */

typedef struct _NFFlowPkt {
  union {
    NFFlowPkt5 v5;
    NFFlowPkt9 v9;
    NFFlowPkt9_v6 v9v6;
  };
} __attribute__ ((packed)) NFFlowPkt;


/* NetFlow functions to send datagrams */
static void sendNetFlowV5Datagram(SFSample *sample);
static void sendNetFlowV9Datagram(SFSample *sample);
static void sendNetFlowV9V6Datagram(SFSample *sample);
static void (*sendNetFlowDatagram)(SFSample *sample) = sendNetFlowV5Datagram;
static void (*sendNetFlowDatagram_v6)(SFSample *sample) = NULL;

static void readFlowSample_header(SFSample *sample);
static void readFlowSample(SFSample *sample, int expanded);

/*_________________---------------------------__________________
  _________________     heap allocation       __________________
  -----------------___________________________------------------
*/
void *my_calloc(size_t bytes) {
  void *mem = calloc(1, bytes);
  if(mem == NULL) {
    fprintf(ERROUT, "calloc(%"PRIu64") failed: %s\n", (uint64_t)bytes, strerror(errno));
    exit(-1);
  }
  return mem;
}

void my_free(void *ptr) {
  if(ptr) {
    free(ptr);
  }
}

void *my_cb_alloc(void *magic, size_t bytes) {
  return my_calloc(bytes);
}

void my_cb_free(void *magic, void *ptr) {
  my_free(ptr);
}

/*_________________------------------------__________________
  _________________      time              __________________
  -----------------________________________------------------
*/
  
void clockMono(struct timespec *ts) {
  clockid_t monoClock = CLOCK_MONOTONIC;
#ifdef CLOCK_MONOTONIC_COARSE
  // more efficient if supported,  since we only need mS accuracy
  monoClock = CLOCK_MONOTONIC_COARSE;
#endif
  if(clock_gettime(monoClock, ts) == -1) {
    fprintf(ERROUT, "clock_gettime() failed: %s", strerror(errno));
    exit(-51);
  }
}

uint64_t now_mS(void *magic) {
  struct timespec ts;
  clockMono(&ts);
  uint64_t mS = ts.tv_sec;
  mS *= 1000;
  mS += (ts.tv_nsec >> 20); // approximation of / 1e6
  return mS;
}
/*_________________---------------------------__________________
  _________________     sfl_random            __________________
  -----------------___________________________------------------
  Gerhard's generator
*/

static uint32_t SFLRandom = 1;

uint32_t sfl_random(uint32_t lim) {
  SFLRandom = ((SFLRandom * 32719) + 3) % 32749;
  return ((SFLRandom % lim) + 1);
} 

void sfl_random_init(uint32_t seed) {
  SFLRandom = seed;
} 

/*_________________---------------------------__________________
  _________________      string buffer        __________________
  -----------------___________________________------------------
  use string buffer scratchpad to avoid snprintf() idiosyncracies
*/

static void SFStr_init(SFStr *sb) {
  sb->cap = MAX_STRBUF_LEN;
  sb->len = 0;
  sb->str[0] = '\0';
}

static char *SFStr_str(SFStr *sb) {
  return sb->str;
}

static int SFStr_len(SFStr *sb) {
  return sb->len;
}

static int SFStr_append(SFStr *sb, char *str) {
  if(str == NULL)
    return YES;
  int slen = strlen(str);
  int copylen = strlen(str);
  if((sb->len + copylen) >= sb->cap)
    copylen = sb->cap - sb->len - 1;
  if(copylen > 0) {
    memcpy(sb->str + sb->len, str, copylen);
    sb->len += copylen;
    sb->str[sb->len] = '\0';
  }
  return (copylen == slen);
}

/* hex printing tends to be one of the performance bottlenecks,
   so take the trouble to optimize it just a little */

static u_int8_t HexLookupL[513]= {
  "000102030405060708090a0b0c0d0e0f"
  "101112131415161718191a1b1c1d1e1f"
  "202122232425262728292a2b2c2d2e2f"
  "303132333435363738393a3b3c3d3e3f"
  "404142434445464748494a4b4c4d4e4f"
  "505152535455565758595a5b5c5d5e5f"
  "606162636465666768696a6b6c6d6e6f"
  "707172737475767778797a7b7c7d7e7f"
  "808182838485868788898a8b8c8d8e8f"
  "909192939495969798999a9b9c9d9e9f"
  "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
  "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
  "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
  "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
  "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
};

static uint8_t HexLookupU[513]= {
  "000102030405060708090A0B0C0D0E0F"
  "101112131415161718191A1B1C1D1E1F"
  "202122232425262728292A2B2C2D2E2F"
  "303132333435363738393A3B3C3D3E3F"
  "404142434445464748494A4B4C4D4E4F"
  "505152535455565758595A5B5C5D5E5F"
  "606162636465666768696A6B6C6D6E6F"
  "707172737475767778797A7B7C7D7E7F"
  "808182838485868788898A8B8C8D8E8F"
  "909192939495969798999A9B9C9D9E9F"
  "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
  "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
  "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
  "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
  "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
  "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
};

static int SFStr_append_hex(SFStr *sb, u_char *hex, int nbytes, int prefix, int upper, char sep) {
  if(prefix) {
    if((sb->cap - sb->len) < 3)
      return NO;
    sb->str[sb->len++] = '0';
    sb->str[sb->len++] = 'x';
  }
  int hexPerByte = 2;
  if(sep) hexPerByte++;
  int roomForBytes = (sb->cap - sb->len - 1) / hexPerByte;
  if(nbytes > roomForBytes)
    nbytes = roomForBytes;

  uint16_t *lookup = (uint16_t *)(upper ? HexLookupU : HexLookupL);

  for(int ii = 0; ii < nbytes; ii++) {
    if(sep && ii) sb->str[sb->len++] = sep;
    uint16_t word = ntohs(lookup[hex[ii]]);
    sb->str[sb->len++] = word >> 8;
    sb->str[sb->len++] = word & 0xFF;
  }

  sb->str[sb->len] = '\0';
  return (nbytes < roomForBytes);
}

static int SFStr_append_array32(SFStr *sb, uint32_t *array32, int n, int net_byte_order, char sep) {
  for(int i = 0; i < n; i++) {
    char ibuf[64];
    uint32_t val32 = array32[i];
    if(net_byte_order)
      val32 = ntohl(val32);
    snprintf(ibuf, 64, "%u", val32);
    int ilen = strlen(ibuf);
    if((sb->len + 1 + ilen) >= sb->cap)
      return NO;
    if(i > 0)
      sb->str[sb->len++] = sep;
    memcpy(sb->str + sb->len, ibuf, ilen);
    sb->len += ilen;
    sb->str[sb->len] = '\0';
  }
  return YES;
}

static int SFStr_append_U32(SFStr *sb, char *fmt, uint32_t val32) {
  char ibuf[200];
  snprintf(ibuf, 64, fmt, val32);
  return SFStr_append(sb, ibuf);
}

static int SFStr_append_U64(SFStr *sb, char *fmt, uint64_t val64) {
  char ibuf[200];
  snprintf(ibuf, 200, fmt, val64);
  return SFStr_append(sb, ibuf);
  return YES;
}

static int SFStr_append_double(SFStr *sb, char *fmt, double vald) {
  char ibuf[200];
  snprintf(ibuf, 200, fmt, vald);
  return SFStr_append(sb, ibuf);
  return YES;
}

static int SFStr_append_mac(SFStr *sb, uint8_t *mac) {
  return SFStr_append_hex(sb, mac, 6, NO, NO, 0);
}

static int SFStr_append_ip(SFStr *sb, uint8_t *ip) {
  uint32_t array32[4];
  for(int i = 0; i < 4; i++)
    array32[i] = ip[i];
  return SFStr_append_array32(sb, array32, 4, NO, '.');
}

static int SFStr_append_ip6(SFStr *sb, uint8_t *ip6) {
  for(int i = 0; i < 16; i += 2) {
    if(i > 0
       && SFStr_append(sb, ":") == NO)
      return NO;
    if(SFStr_append_hex(sb, (ip6+i), 2, NO, NO, 0) == NO)
      return NO;
  }
  return YES;
}

static int SFStr_append_address(SFStr *sb, SFLAddress *address) {
  if(address->type == SFLADDRESSTYPE_IP_V4)
    return SFStr_append_ip(sb, (uint8_t *)&address->address.ip_v4.addr);
  if(address->type == SFLADDRESSTYPE_IP_V6)
    return SFStr_append_ip6(sb, address->address.ip_v6.addr);
  return SFStr_append(sb, "-");
}

static int SFStr_append_UUID(SFStr *sb, uint8_t *uuid) {
  SFStr_append_hex(sb, uuid, 4, NO, NO, 0);
    SFStr_append(sb, "-");
    SFStr_append_hex(sb, uuid+4, 2, NO, NO, 0);
    SFStr_append(sb, "-");
    SFStr_append_hex(sb, uuid+6, 2, NO, NO, 0);
    SFStr_append(sb, "-");
    SFStr_append_hex(sb, uuid+8, 2, NO, NO, 0);
    SFStr_append(sb, "-");
    return SFStr_append_hex(sb, uuid+10, 6, NO, NO, 0);
}

static int SFStr_append_tag(SFStr *sb, uint32_t tag) {
  uint32_t parts[2];
  parts[0] = (tag >> 12);
  parts[1] = (tag & 0x00000FFF);
  return SFStr_append_array32(sb, parts, 2, NO, ':');
}

static int SFStr_append_timestamp(SFStr *sb, time_t ts) {
  char tstr[200];
  /* ISO8601 compatible localtime */
  strftime(tstr, 200, "%Y-%m-%dT%H:%M:%S%z", localtime(&ts));
  return SFStr_append(sb, tstr);
}

static int SFStr_append_dataSource(SFStr *sb, uint32_t ds_class, uint32_t ds_index) {
  char buf[200];
  snprintf(buf, 200, "%u:%u", ds_class, ds_index);
  return SFStr_append(sb, buf);
}

static int SFStr_copy(SFStr *sb, char *to, int capacity) {
  int max = capacity - 1;
  int bytes = max > sb->len ? sb->len : max;
  memcpy(to, sb->str, bytes);
  to[bytes] = '\0';
  return bytes;
}

/*_________________---------------------------__________________
  _________________     print functions       __________________
  -----------------___________________________------------------
*/

static char *printAddress(SFLAddress *address, SFStr *sb) {
  SFStr_init(sb);
  SFStr_append_address(sb, address);
  return SFStr_str(sb);
}

static char *printMAC(uint8_t *mac, SFStr *sb) {
  SFStr_init(sb);
  SFStr_append_mac(sb, mac);
  return SFStr_str(sb);
}

static char *printTag(uint32_t tag, SFStr *sb) {
  SFStr_init(sb);
  SFStr_append_tag(sb, tag);
  return SFStr_str(sb);
}

static char *printTimestamp(time_t ts, SFStr *sb) {
  SFStr_init(sb);
  SFStr_append_timestamp(sb, ts);
  return SFStr_str(sb);
}

static char *printOUI(uint8_t *oui, SFStr *sb) {
  SFStr_init(sb);
  SFStr_append_hex(sb, oui, 3, NO, YES, '-');
  return SFStr_str(sb);
}

static char *printDataSource(uint32_t ds_class, uint32_t ds_index, SFStr *sb) {
  SFStr_init(sb);
  SFStr_append_dataSource(sb, ds_class, ds_index);
  return SFStr_str(sb);
}

static char *printOutputPort_v2v4(uint32_t outputPort, SFStr *sb) {
  SFStr_init(sb);
  if(outputPort & 0x80000000) {
    uint32_t numOutputs = outputPort & 0x7fffffff;
    if(numOutputs > 0)
      SFStr_append_U32(sb, "multiple %d", numOutputs);
    else
      SFStr_append(sb, "multiple >1");
  }
  else SFStr_append_U32(sb, "%u", outputPort);
  return SFStr_str(sb);
}

static char *printInOutPort(uint32_t port, uint32_t format, SFStr *sb) {
  SFStr_init(sb);
  switch(format) {
  case 3: SFStr_append_U32(sb, "format==3 %u", port); break;
  case 2: SFStr_append_U32(sb, "multiple %u", port); break;
  case 1: SFStr_append_U32(sb, "dropCode %u", port); break;
  case 0: SFStr_append_U32(sb, "%u", port); break;
  }
  return SFStr_str(sb);
}

/*_________________---------------------------__________________
  _________________      JSON utils           __________________
  -----------------___________________________------------------
*/

static void json_indent() {
  if(sfConfig.jsonIndent) {
    putchar('\n');
    for(int ii=0; ii<sfConfig.outputDepth; ii++)
      putchar(' ');
  }
}

static void json_start(char *fname, char bracket) {
  if(sfConfig.jsonStart) {
    sfConfig.jsonStart = NO;
  }
  else if(sfConfig.jsonListStart == NO) {
    putchar(',');
    json_indent();
  }
  if(fname)
    printf("\"%s\":", fname);
  putchar(bracket);
  sfConfig.outputDepth++;
  /* indicate start of list */
  sfConfig.jsonListStart = YES;
}

static void json_end(char bracket) {
  sfConfig.outputDepth--;
  json_indent();
  printf("%c", bracket);
  /* clear list-start flag in case array/obj was emtpy */
  sfConfig.jsonListStart = NO;
}

static void json_start_ob(char *fname) {  json_start(fname, '{'); }
static void json_start_ar(char *fname) { json_start(fname, '['); }
static void json_end_ob() { json_end('}'); }
static void json_end_ar() { json_end(']'); }

/*_________________---------------------------__________________
  _________________        sf_log             __________________
  -----------------___________________________------------------
*/

static void sf_logf_pushPrefix(SFSample *sample, char *prefix) {
  if(sample->s.prefixCount < SA_MAX_FIELD_PREFIX)
    sample->s.fieldPrefix[sample->s.prefixCount++] = prefix;
  else {
    fprintf(ERROUT, "reached field prefix limit with %s\n", prefix);
    SFABORT(sample, SF_ABORT_DECODE_ERROR);
  }
}

static void sf_logf_popPrefix(SFSample *sample) {
  if(sample->s.prefixCount > 0)
    --sample->s.prefixCount;
  else {
    fprintf(ERROUT, "no prefix to pop\n");
    SFABORT(sample, SF_ABORT_DECODE_ERROR);
  }
}

static char *printPrefix(SFSample *sample, SFStr *sb) {
  uint32_t ii;
  SFStr_init(sb);
  for(ii = 0; ii < sample->s.prefixCount; ii++)
    SFStr_append(sb, sample->s.fieldPrefix[ii]);
  return SFStr_str(sb);
}
  
static void sf_log_context(SFSample *sample) {
  SFStr agentIP, tag1, tag2, nowstr;
  time_t now = sample->pcapTimestamp ?: sample->readTimestamp;
  printf("%s %s %u %u %u:%u %s %s ",
	 printTimestamp(now, &nowstr),
	 printAddress(&sample->agent_addr, &agentIP),
	 sample->agentSubId,
	 sample->sequenceNo,
	 sample->s.ds_class,
	 sample->s.ds_index,
	 printTag(sample->s.sampleType, &tag1),
	 printTag(sample->s.elementType, &tag2));
}

static void sf_log(SFSample *sample, char *fmt, ...) {
  /* don't print anything here unless exporting in FULL or SCRIPT formats */

  /* scripts like to have all the context on every line */
  if(sfConfig.outputFormat == SFLFMT_SCRIPT)
    sf_log_context(sample);

  if(sfConfig.outputFormat == SFLFMT_FULL
     || sfConfig.outputFormat == SFLFMT_SCRIPT) {
    va_list args;
    va_start(args, fmt);
    if(vprintf(fmt, args) < 0) {
      exit(-40);
    }
  }
}

static void sf_logf(SFSample *sample, char *fieldName, char *val)
{
  /* This log-field variant prints for the FULL, SCRIPT and JSON formats. */
  SFStr prefix;

  /* scripts like to have all the context on every line */
  if(sfConfig.outputFormat == SFLFMT_SCRIPT)
    sf_log_context(sample);

  if(sfConfig.outputFormat == SFLFMT_FULL
     || sfConfig.outputFormat == SFLFMT_SCRIPT) {
    if(printf("%s%s %s\n", printPrefix(sample, &prefix), fieldName, val) < 0)
      exit(-40);
  }

  if(sfConfig.outputFormat == SFLFMT_JSON) {
    if(sfConfig.jsonListStart == NO)
      putchar(',');
    else
      sfConfig.jsonListStart = NO;

    json_indent();
    /* always print as JSON strings, since value may be 64-bit integer */
    if(printf("\"%s%s\":\"%s\"", printPrefix(sample, &prefix), fieldName, val) < 0)
      exit(-40);
  }

  if(sfConfig.outputFormat == SFLFMT_LINE_CUSTOM) {
    /* build key */
    SFStr buf;
    int slot;
    char *field = fieldName;
    if(sample->s.prefixCount) {
      SFStr_init(&buf);
      SFStr_append(&buf, printPrefix(sample, &prefix));
      SFStr_append(&buf, fieldName);
      field = SFStr_str(&buf);
    }
    /* see if we want this field */
    ENTRY e, *ep;
    e.key = field;
    ep = hsearch(e, FIND);
    if(ep) {
      /* yes, store value in slot */
      int slot = *(int*)ep->data;
      SFStr *value = &sfConfig.outputFieldList.values[slot];
      SFStr_init(value);
      SFStr_append(value, val);
      /* and remember it's scope */
      sfConfig.outputFieldList.fieldScope[slot] = sfConfig.currentFieldScope;
      /* and count the number of sample fields seen */
      if(sfConfig.currentFieldScope == SFSCOPE_SAMPLE)
	sfConfig.outputFieldList.sampleFields++;
    }
  }
}

static void sf_logf_U32_formatted(SFSample *sample, char *fieldPrefix, char *fieldName, char *fmt, uint32_t val32) {
  SFStr buf;
  SFStr_init(&buf);
  SFStr_append_U32(&buf, fmt, val32);
  sf_logf_pushPrefix(sample, fieldPrefix);
  sf_logf(sample, fieldName, SFStr_str(&buf));
  sf_logf_popPrefix(sample);
}

static void sf_logf_U64_formatted(SFSample *sample, char *fieldPrefix, char *fieldName, char *fmt, uint64_t val64) {
  SFStr buf;
  SFStr_init(&buf);
  SFStr_append_U64(&buf, fmt, val64);
  sf_logf_pushPrefix(sample, fieldPrefix);
  sf_logf(sample, fieldName, SFStr_str(&buf));
  sf_logf_popPrefix(sample);
}

static void sf_logf_double_formatted(SFSample *sample, char *fieldPrefix, char *fieldName, char *fmt, double vald) {
  SFStr buf;
  SFStr_init(&buf);
  SFStr_append_double(&buf, fmt, vald);
  sf_logf_pushPrefix(sample, fieldPrefix);
  sf_logf(sample, fieldName, SFStr_str(&buf));
  sf_logf_popPrefix(sample);
}

/* shortcuts for convenience */

static void sf_logf_U32(SFSample *sample, char *fieldName, uint32_t val32) {
  sf_logf_U32_formatted(sample, NULL, fieldName, "%u", val32);
}

static void sf_logf_U64(SFSample *sample, char *fieldName, uint64_t val64) {
  sf_logf_U64_formatted(sample, NULL, fieldName, "%"PRIu64, val64);
}

/*_________________---------------------------__________________
  _________________       URLEncode           __________________
  -----------------___________________________------------------
*/

char *URLEncode(char *in, char *out, int outlen)
{
  register char c, *r = in, *w = out;
  int maxlen = (strlen(in) * 3) + 1;
  if(outlen < maxlen) return "URLEncode: not enough space";
  uint16_t *lookup = (uint16_t *)HexLookupU;
  while ((c = *r++)) {
    if(isalnum(c)) *w++ = c;
    else if(isspace(c)) *w++ = '+';
    else {
      uint16_t word = lookup[c];
      *w++ = '%';
      *w++ = word >> 8;
      *w++ = word & 255;
    }
  }
  *w++ = '\0';
  return out;
}

/*_________________---------------------------__________________
  _________________    sampleFilterOK         __________________
  -----------------___________________________------------------
*/

int sampleFilterOK(SFSample *sample)
{
  /* the vlan filter will only reject a sample if both in_vlan and out_vlan are rejected. If the
     vlan was not reported in an SFLExtended_Switch struct, but was only picked up from the 802.1q header
     then the out_vlan will be 0,  so to be sure you are rejecting vlan 1,  you may need to reject both
     vlan 0 and vlan 1. */
  return(sfConfig.gotVlanFilter == NO
	 || sfConfig.vlanFilter[sample->s.in_vlan]
	 || sfConfig.vlanFilter[sample->s.out_vlan]);
}

/*_________________---------------------------__________________
  _________________    writeFlowLine          __________________
  -----------------___________________________------------------
*/

static void writeFlowLine(SFSample *sample)
{
  SFStr agentIP, srcMAC, dstMAC, srcIP, dstIP;
  /* source */
  if(printf("FLOW,%s,%d,%d,",
	    printAddress(&sample->agent_addr, &agentIP),
	    sample->s.inputPort,
	    sample->s.outputPort) < 0) {
    exit(-41);
  }
  /* layer 2 */
  if(printf("%s,%s,0x%04x,%d,%d",
	    printMAC(sample->s.eth_src, &srcMAC),
	    printMAC(sample->s.eth_dst, &dstMAC),
	    sample->s.eth_type,
	    sample->s.in_vlan,
	    sample->s.out_vlan) < 0) {
    exit(-42);
  }
  /* layer 3/4 */
  if(printf(",%s,%s,%d,0x%02x,%d,%d,%d,0x%02x",
	    printAddress(&sample->s.ipsrc, &srcIP),
	    printAddress(&sample->s.ipdst, &dstIP),
	    sample->s.dcd_ipProtocol,
	    sample->s.dcd_ipTos,
	    sample->s.dcd_ipTTL,
	    sample->s.dcd_sport,
	    sample->s.dcd_dport,
	    sample->s.dcd_tcpFlags) < 0) {
    exit(-43);
  }
  /* bytes */
  if(printf(",%d,%d,%d\n",
	    sample->s.sampledPacketSize,
	    sample->s.sampledPacketSize - sample->s.stripped - sample->s.offsetToIPV4,
	    sample->s.meanSkipCount) < 0) {
    exit(-44);
  }
}

/*_________________---------------------------__________________
  _________________    writeLineCustom        __________________
  -----------------___________________________------------------
*/

static void writeLineCustom(SFSample *sample)
{
  /* don't print anything if we didn't match any sample-level fields */
  if(sfConfig.outputFieldList.sampleFields == 0)
    return;

  for(int ii = 0; ii < sfConfig.outputFieldList.n; ii++) {
    if(ii>0)
      printf(",");
    char *field = sfConfig.outputFieldList.fields[ii];
    SFStr *val = &sfConfig.outputFieldList.values[ii];
    if(val->len)
      printf("%s", SFStr_str(val));
  }
  printf("\n");
}

/*_________________---------------------------__________________
  _________________    clearLineCustom        __________________
  -----------------___________________________------------------
*/

static void clearLineCustom(SFSample *sample, EnumSFScope scope)
{
  for(int ii = 0; ii < sfConfig.outputFieldList.n; ii++) {
    if(sfConfig.outputFieldList.fieldScope[ii] == scope) {
      SFStr *val = &sfConfig.outputFieldList.values[ii];
      SFStr_init(val);
    }
  }
  sfConfig.outputFieldList.sampleFields = 0;
}

/*_________________---------------------------__________________
  _________________    writeCountersLine      __________________
  -----------------___________________________------------------
*/

static void writeCountersLine(SFSample *sample)
{
  /* source */
  SFStr agentIP;
  if(printf("CNTR,%s,", printAddress(&sample->agent_addr, &agentIP)) < 0) {
    exit(-45);
  }
  if(printf("%u,%u,%"PRIu64",%u,%u,%"PRIu64",%u,%u,%u,%u,%u,%u,%"PRIu64",%u,%u,%u,%u,%u,%u\n",
	    sample->s.ifCounters.ifIndex,
	    sample->s.ifCounters.ifType,
	    sample->s.ifCounters.ifSpeed,
	    sample->s.ifCounters.ifDirection,
	    sample->s.ifCounters.ifStatus,
	    sample->s.ifCounters.ifInOctets,
	    sample->s.ifCounters.ifInUcastPkts,
	    sample->s.ifCounters.ifInMulticastPkts,
	    sample->s.ifCounters.ifInBroadcastPkts,
	    sample->s.ifCounters.ifInDiscards,
	    sample->s.ifCounters.ifInErrors,
	    sample->s.ifCounters.ifInUnknownProtos,
	    sample->s.ifCounters.ifOutOctets,
	    sample->s.ifCounters.ifOutUcastPkts,
	    sample->s.ifCounters.ifOutMulticastPkts,
	    sample->s.ifCounters.ifOutBroadcastPkts,
	    sample->s.ifCounters.ifOutDiscards,
	    sample->s.ifCounters.ifOutErrors,
	    sample->s.ifCounters.ifPromiscuousMode) < 0) {
    exit(-46);
  }
}

/*_________________---------------------------__________________
  _________________    receiveError           __________________
  -----------------___________________________------------------
*/

static void receiveError(SFSample *sample, char *errm, int hexdump)
{
  SFStr ipbuf;
  SFStr hex;
  char *msg = "";
  uint32_t markOffset = (uint8_t *)sample->datap - sample->rawSample;
  fprintf(ERROUT, "%s (source IP = %s)\n",
	  errm ?: "ERROR", printAddress(&sample->sourceIP, &ipbuf));
  if(hexdump) {
    int lineN = 16;
    for(int ii = 0; ii < sample->rawSampleLen; ) {
      SFStr_init(&hex);
      int toEnd = sample->rawSampleLen - ii;
      int toEOL = toEnd < lineN ? toEnd : lineN;
      int toMark = markOffset - ii;
      if(toMark >= 0 && toMark < toEOL) {
	SFStr_append_hex(&hex, sample->rawSample + ii, toMark, NO, NO, '-');
	ii += toMark;
	SFStr_append(&hex, "-<*>-");
	toEOL -= toMark;
      }
      SFStr_append_hex(&hex, sample->rawSample + ii, toEOL, NO, NO, '-');
      ii += toEOL;
      fprintf(stderr, "%s\n", SFStr_str(&hex));
    }
  }
  SFABORT(sample, SF_ABORT_DECODE_ERROR);
}

/*_________________---------------------------__________________
  _________________    lengthCheck            __________________
  -----------------___________________________------------------
*/

static void lengthCheck(SFSample *sample, char *description, uint8_t *start, int len) {
  uint32_t actualLen = (uint8_t *)sample->datap - start;
  uint32_t adjustedLen = ((len + 3) >> 2) << 2;
  if(actualLen != adjustedLen) {
    fprintf(ERROUT, "%s length error (expected %d, found %d)\n", description, len, actualLen);
    SFABORT(sample, SF_ABORT_LENGTH_ERROR);
  }
}

/*_________________---------------------------__________________
  _________________     decodeLinkLayer       __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

static void decodeLinkLayer(SFSample *sample)
{
  uint8_t *start = sample->s.header;
  uint8_t *end = start + sample->s.headerLen;
  uint8_t *ptr = start;
  uint16_t type_len;
  uint32_t vlanDepth=0;
  SFStr buf;

  /* assume not found */
  sample->s.gotIPV4 = NO;
  sample->s.gotIPV6 = NO;

  if((end - ptr) < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

  sf_logf(sample, "dstMAC", printMAC(ptr, &buf));
  memcpy(sample->s.eth_dst, ptr, 6);
  ptr += 6;
  sf_logf(sample, "srcMAC", printMAC(ptr, &buf));
  memcpy(sample->s.eth_src, ptr, 6);
  ptr += 6;
  type_len = (ptr[0] << 8) + ptr[1];
  ptr += 2;

  while(type_len == 0x8100
	|| type_len == 0x88A8
	|| type_len == 0x9100
	|| type_len == 0x9200
	|| type_len == 0x9300) {
    if((end - ptr) < 4) return; /* not enough for an 802.1Q header */
    /* VLAN  - next two bytes */
    uint32_t vlanData = (ptr[0] << 8) + ptr[1];
    uint32_t vlan = vlanData & 0x0fff;
    uint32_t priority = vlanData >> 13;
    ptr += 2;
    /*  _____________________________________ */
    /* |   pri  | c |         vlan-id        | */
    /*  ------------------------------------- */
    /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
    if(vlanDepth == 0) {
      sf_logf_U32(sample, "decodedVLAN", vlan);
      sf_logf_U32(sample, "decodedPriority", priority);
    }
    else {
      /* 802.1AD / Q-in-Q: indicate VLAN depth */
      char dotQField[64];
      snprintf(dotQField, 64, "decodedVLAN.%u", vlanDepth);
      sf_logf_U32(sample, dotQField, vlan);
      snprintf(dotQField, 64, "decodedPriority.%u", vlanDepth);
      sf_logf_U32(sample, dotQField, priority);
    }
    sample->s.in_vlan = vlan;
    /* now get the type_len again (next two bytes) */
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;
    vlanDepth++;
  }

  /* now we're just looking for IP */
  if((end - start) < sizeof(struct myiphdr)) return; /* not enough for an IPv4 header (or IPX, or SNAP) */

  /* peek for IPX */
  if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
    int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
    int ipxLen = (ptr[2] << 8) + ptr[3];
    if(ipxChecksum &&
       ipxLen >= IPX_HDR_LEN &&
       ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
      /* we don't do anything with IPX here */
      return;
  }
  if(type_len <= NFT_MAX_8023_LEN) {
    /* assume 802.3+802.2 header */
    /* check for SNAP */
    if(ptr[0] == 0xAA &&
       ptr[1] == 0xAA &&
       ptr[2] == 0x03) {
      ptr += 3;
      if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	sf_logf(sample, "VSNAP_OUI", printOUI(ptr, &buf));
	return; /* no further decode for vendor-specific protocol */
      }
      ptr += 3;
      /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
    }
    else {
      if (ptr[0] == 0x06 &&
	  ptr[1] == 0x06 &&
	  (ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the type_len to be IP so we can inline the IP decode below */
	type_len = 0x0800;
      }
      else return;
    }
  }

  /* assume type_len is an ethernet-type now */
  sample->s.eth_type = type_len;

  if(type_len == 0x0800) {
    /* IPV4 - check again that we have enough header bytes */
    if((end - ptr) < sizeof(struct myiphdr)) return;
    /* look at first byte of header.... */
    /*  ___________________________ */
    /* |   version   |    hdrlen   | */
    /*  --------------------------- */
    if((*ptr >> 4) != 4) return; /* not version 4 */
    if((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */
    /* survived all the tests - store the offset to the start of the ip header */
    sample->s.gotIPV4 = YES;
    sample->s.offsetToIPV4 = (ptr - start);
  }

  if(type_len == 0x86DD) {
    /* IPV6 */
    /* look at first byte of header.... */
    if((*ptr >> 4) != 6) return; /* not version 6 */
    /* survived all the tests - store the offset to the start of the ip6 header */
    sample->s.gotIPV6 = YES;
    sample->s.offsetToIPV6 = (ptr - start);
  }
}

/*_________________---------------------------__________________
  _________________       decode80211MAC      __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found.
*/

#define WIFI_MIN_HDR_SIZ 24

static void decode80211MAC(SFSample *sample)
{
  uint8_t *start = sample->s.header;
  uint8_t *end = start + sample->s.headerLen;
  uint8_t *ptr = start;

  /* assume not found */
  sample->s.gotIPV4 = NO;
  sample->s.gotIPV6 = NO;

  if(sample->s.headerLen < WIFI_MIN_HDR_SIZ) return; /* not enough for an 80211 MAC header */

  uint32_t fc = (ptr[1] << 8) + ptr[0];  /* [b7..b0][b15..b8] */
  uint32_t protocolVersion = fc & 3;
  uint32_t control = (fc >> 2) & 3;
  uint32_t subType = (fc >> 4) & 15;
  uint32_t toDS = (fc >> 8) & 1;
  uint32_t fromDS = (fc >> 9) & 1;
  uint32_t moreFrag = (fc >> 10) & 1;
  uint32_t retry = (fc >> 11) & 1;
  uint32_t pwrMgt = (fc >> 12) & 1;
  uint32_t moreData = (fc >> 13) & 1;
  uint32_t encrypted = (fc >> 14) & 1;
  uint32_t order = fc >> 15;

  ptr += 2;

  uint32_t duration_id = (ptr[1] << 8) + ptr[0]; /* not in network byte order either? */
  ptr += 2;

  switch(control) {
  case 0: /* mgmt */
  case 1: /* ctrl */
  case 3: /* rsvd */
  break;

  case 2: /* data */
    {

      uint8_t *macAddr1 = ptr;
      ptr += 6;
      uint8_t *macAddr2 = ptr;
      ptr += 6;
      uint8_t *macAddr3 = ptr;
      ptr += 6;
      uint32_t sequence = (ptr[0] << 8) + ptr[1];
      ptr += 2;

      /* ToDS   FromDS   Addr1   Addr2  Addr3   Addr4
         0      0        DA      SA     BSSID   N/A (ad-hoc)
         0      1        DA      BSSID  SA      N/A
         1      0        BSSID   SA     DA      N/A
         1      1        RA      TA     DA      SA  (wireless bridge) */

      uint8_t *rxMAC = macAddr1;
      uint8_t *txMAC = macAddr2;
      uint8_t *srcMAC = NULL;
      uint8_t *dstMAC = NULL;
      SFStr buf;

      if(toDS) {
	dstMAC = macAddr3;
	if(fromDS) {
	  srcMAC = ptr; /* macAddr4.  1,1 => (wireless bridge) */
	  ptr += 6;
	}
	else srcMAC = macAddr2;  /* 1,0 */
      }
      else {
	dstMAC = macAddr1;
	if(fromDS) srcMAC = macAddr3; /* 0,1 */
	else srcMAC = macAddr2; /* 0,0 */
      }

      if(srcMAC) {
	sf_logf(sample, "srcMAC", printMAC(srcMAC, &buf));
	memcpy(sample->s.eth_src, srcMAC, 6);
      }
      if(dstMAC) {
	sf_logf(sample, "dstMAC", printMAC(dstMAC, &buf));
	memcpy(sample->s.eth_dst, srcMAC, 6);
      }
      if(txMAC) sf_logf(sample, "txMAC", printMAC(txMAC, &buf));
      if(rxMAC) sf_logf(sample, "rxMAC", printMAC(rxMAC, &buf));
    }
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPLayer4        __________________
  -----------------___________________________------------------
*/

static void decodeIPLayer4(SFSample *sample, uint8_t *ptr) {
  uint8_t *end = sample->s.header + sample->s.headerLen;
  if(ptr > (end - 8)) {
    /* not enough header bytes left */
    return;
  }
  switch(sample->s.dcd_ipProtocol) {
  case 1: /* ICMP */
    {
      struct myicmphdr icmp;
      memcpy(&icmp, ptr, sizeof(icmp));
      sf_logf_U32(sample, "ICMPType", icmp.type);
      sf_logf_U32(sample, "ICMPCode", icmp.code);
      sample->s.dcd_sport = icmp.type;
      sample->s.dcd_dport = icmp.code;
      sample->s.offsetToPayload = ptr + sizeof(icmp) - sample->s.header;
    }
    break;
  case 6: /* TCP */
    {
      struct mytcphdr tcp;
      int headerBytes;
      memcpy(&tcp, ptr, sizeof(tcp));
      sample->s.dcd_sport = ntohs(tcp.th_sport);
      sample->s.dcd_dport = ntohs(tcp.th_dport);
      sample->s.dcd_tcpFlags = tcp.th_flags;
      sf_logf_U32(sample, "TCPSrcPort", sample->s.dcd_sport);
      sf_logf_U32(sample, "TCPDstPort", sample->s.dcd_dport);
      sf_logf_U32(sample, "TCPFlags", sample->s.dcd_tcpFlags);
      headerBytes = (tcp.th_off_and_unused >> 4) * 4;
      ptr += headerBytes;
      sample->s.offsetToPayload = ptr - sample->s.header;
    }
    break;
  case 17: /* UDP */
    {
      struct myudphdr udp;
      memcpy(&udp, ptr, sizeof(udp));
      sample->s.dcd_sport = ntohs(udp.uh_sport);
      sample->s.dcd_dport = ntohs(udp.uh_dport);
      sample->s.udp_pduLen = ntohs(udp.uh_ulen);
      sf_logf_U32(sample, "UDPSrcPort", sample->s.dcd_sport);
      sf_logf_U32(sample, "UDPDstPort", sample->s.dcd_dport);
      sf_logf_U32(sample, "UDPBytes", sample->s.udp_pduLen);
      sample->s.offsetToPayload = ptr + sizeof(udp) - sample->s.header;
    }
    break;
  default: /* some other protcol */
    sample->s.offsetToPayload = ptr - sample->s.header;
    break;
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV4            __________________
  -----------------___________________________------------------
*/

static void decodeIPV4(SFSample *sample)
{
  if(sample->s.gotIPV4) {
    SFStr buf;
    uint8_t *end = sample->s.header + sample->s.headerLen;
    uint8_t *start = sample->s.header + sample->s.offsetToIPV4;
    uint8_t *ptr = start;
    if((end - ptr) < sizeof(struct myiphdr)) return;

    /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
       platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
    struct myiphdr ip;
    memcpy(&ip, ptr, sizeof(ip));
    /* Value copy all ip elements into sample */
    sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V4;
   if (sfConfig.anonymize == YES) {
	ip.saddr=ip.saddr&0xffffff;
    }
    sample->s.ipsrc.address.ip_v4.addr = ip.saddr;
    sample->s.ipdst.type = SFLADDRESSTYPE_IP_V4;
    if (sfConfig.anonymize == YES) {
	ip.daddr=ip.daddr&0xffffff;
    }
    sample->s.ipdst.address.ip_v4.addr = ip.daddr;
    sample->s.dcd_ipProtocol = ip.protocol;
    sample->s.dcd_ipTos = ip.tos;
    sample->s.dcd_ipTTL = ip.ttl;
    sf_logf_U32(sample, "ip.tot_len", ntohs(ip.tot_len));
    /* Log out the decoded IP fields */
    sf_logf(sample, "srcIP", printAddress(&sample->s.ipsrc, &buf));
    sf_logf(sample, "dstIP", printAddress(&sample->s.ipdst, &buf));
    sf_logf_U32(sample, "IPProtocol", sample->s.dcd_ipProtocol);
    sf_logf_U32(sample, "IPTOS", sample->s.dcd_ipTos);
    sf_logf_U32(sample, "IPTTL", sample->s.dcd_ipTTL);
    sf_logf_U32(sample, "IPID", ip.id);
    /* check for fragments */
    sample->s.ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
    if(sample->s.ip_fragmentOffset > 0) {
      sf_logf_U32(sample, "IPFragmentOffset", sample->s.ip_fragmentOffset);
    }
    else {
      /* advance the pointer to the next protocol layer */
      /* ip headerLen is expressed as a number of quads */
      uint32_t headerBytes = (ip.version_and_headerLen & 0x0f) * 4;
      if((end - ptr) < headerBytes) return;
      ptr += headerBytes;
      decodeIPLayer4(sample, ptr);
    }
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV6            __________________
  -----------------___________________________------------------
*/

static void decodeIPV6(SFSample *sample)
{
  uint16_t payloadLen;
  uint32_t nextHeader;
  uint32_t tos;

  uint8_t *end = sample->s.header + sample->s.headerLen;
  uint8_t *start = sample->s.header + sample->s.offsetToIPV6;
  uint8_t *ptr = start;
  if((end - ptr) < sizeof(struct myip6hdr)) return;

  if(sample->s.gotIPV6) {

    /* check the version */
    {
      int ipVersion = (*ptr >> 4);
      if(ipVersion != 6) {
	sf_log(sample,"header decode error: unexpected IP version: %d\n", ipVersion);
	return;
      }
    }

    /* get the tos (priority) */
    sample->s.dcd_ipTos = ((ptr[0] & 15) << 4) + (ptr[1] >> 4);
    ptr++;
    sf_logf_U32(sample, "IPTOS", sample->s.dcd_ipTos);
    /* 20-bit label */
    sample->s.dcd_flowLabel = ((ptr[0] & 15) << 16) + (ptr[1] << 8) + ptr[2];
    ptr += 3;
    sf_logf_U32_formatted(sample, NULL, "IP6_label", "0x%1x", sample->s.dcd_flowLabel);
    /* payload */
    payloadLen = (ptr[0] << 8) + ptr[1];
    ptr += 2;
    /* if payload is zero, that implies a jumbo payload */
    if(payloadLen == 0) sf_logf(sample, "IPV6_payloadLen", "<jumbo>");
    else sf_logf_U32(sample, "IPV6_payloadLen", payloadLen);

    /* next header */
    nextHeader = *ptr++;

    /* TTL */
    sample->s.dcd_ipTTL = *ptr++;
    sf_logf_U32(sample, "IPTTL", sample->s.dcd_ipTTL);

    {/* src and dst address */
      SFStr buf;
      sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V6;
      if (sfConfig.anonymize == YES) {
      bzero(&sample->s.ipsrc.address, 16);
      memcpy(&sample->s.ipsrc.address, ptr, 6);
      }
      else
      memcpy(&sample->s.ipsrc.address, ptr, 16);
      ptr +=16;
      sf_logf(sample, "srcIP6", printAddress(&sample->s.ipsrc, &buf));
      sample->s.ipdst.type = SFLADDRESSTYPE_IP_V6;
      if (sfConfig.anonymize == YES) {
      bzero(&sample->s.ipdst.address, 16);
      memcpy(&sample->s.ipdst.address, ptr, 6);
      }
      else
      memcpy(&sample->s.ipdst.address, ptr, 16);
      ptr +=16;
      sf_logf(sample, "dstIP6", printAddress(&sample->s.ipdst, &buf));
    }

    /* skip over some common header extensions...
       http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html */
    while(nextHeader == 0 ||  /* hop */
	  nextHeader == 43 || /* routing */
	  nextHeader == 44 || /* fragment */
	  /* nextHeader == 50 => encryption - don't bother coz we'll not be able to read any further */
	  nextHeader == 51 || /* auth */
	  nextHeader == 60) { /* destination options */
      uint32_t optionLen;
      sf_logf_U32(sample, "IP6HeaderExtension", nextHeader);
      nextHeader = ptr[0];
      optionLen = 8 * (ptr[1] + 1);  /* second byte gives option len in 8-byte chunks, not counting first 8 */
      ptr += optionLen;
      if(ptr > end) return; /* ran off the end of the header */
    }

    /* now that we have eliminated the extension headers, nextHeader should have what we want to
       remember as the ip protocol... */
    sample->s.dcd_ipProtocol = nextHeader;
    sf_logf_U32(sample, "IPProtocol", sample->s.dcd_ipProtocol);
    decodeIPLayer4(sample, ptr);
  }
}

/*_________________---------------------------__________________
  _________________   readPcapHeader          __________________
  -----------------___________________________------------------
*/

#define TCPDUMP_MAGIC 0xa1b2c3d4  /* from libpcap-0.5: savefile.c */
#define DLT_EN10MB	1	  /* from libpcap-0.5: net/bpf.h */
#define PCAP_VERSION_MAJOR 2      /* from libpcap-0.5: pcap.h */
#define PCAP_VERSION_MINOR 4      /* from libpcap-0.5: pcap.h */

static void readPcapHeader() {
  struct pcap_file_header hdr;
  if(fread(&hdr, sizeof(hdr), 1, sfConfig.readPcapFile) != 1) {
    fprintf(ERROUT, "unable to read pcap header from %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
    exit(-30);
  }
  if(hdr.magic != TCPDUMP_MAGIC) {
    if(hdr.magic == bswap_32(TCPDUMP_MAGIC)) {
      sfConfig.pcapSwap = YES;
      hdr.version_major = bswap_16(hdr.version_major);
      hdr.version_minor = bswap_16(hdr.version_minor);
      hdr.thiszone = bswap_32(hdr.thiszone);
      hdr.sigfigs = bswap_32(hdr.sigfigs);
      hdr.snaplen = bswap_32(hdr.snaplen);
      hdr.linktype = bswap_32(hdr.linktype);
    }
    else {
      fprintf(ERROUT, "%s not recognized as a tcpdump file\n(magic number = %08x instead of %08x)\n",
	      sfConfig.readPcapFileName,
	      hdr.magic,
	      TCPDUMP_MAGIC);
      exit(-31);
    }
  }
  fprintf(ERROUT, "pcap version=%d.%d snaplen=%d linktype=%d \n",
	  hdr.version_major,
	  hdr.version_minor,
	  hdr.snaplen,
	  hdr.linktype);
  sfConfig.readPcapHdr = hdr;
}

/*_________________---------------------------__________________
  _________________   writePcapHeader         __________________
  -----------------___________________________------------------
*/

#define DLT_EN10MB	1	  /* from libpcap-0.5: net/bpf.h */
#define DLT_LINUX_SLL   113       /* Linux "cooked" encapsulation */
#define PCAP_VERSION_MAJOR 2      /* from libpcap-0.5: pcap.h */
#define PCAP_VERSION_MINOR 4      /* from libpcap-0.5: pcap.h */

static void writePcapHeader() {
  struct pcap_file_header hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TCPDUMP_MAGIC;
  hdr.version_major = PCAP_VERSION_MAJOR;
  hdr.version_minor = PCAP_VERSION_MINOR;
  hdr.thiszone = 0;
  hdr.snaplen = SA_MAX_PCAP_PKT;
  hdr.sigfigs = 0;
  hdr.linktype = DLT_EN10MB;
  if (fwrite((char *)&hdr, sizeof(hdr), 1, stdout) != 1) {
    fprintf(ERROUT, "failed to write tcpdump header: %s\n", strerror(errno));
    exit(-1);
  }
  fflush(stdout);
}

/*_________________---------------------------__________________
  _________________   writePcapPacket         __________________
  -----------------___________________________------------------
*/

static void writePcapPacket(SFSample *sample) {
  char buf[SA_MAX_PCAP_PKT];
  int bytes = 0;
  struct pcap_pkthdr hdr;
  hdr.ts_sec = sample->pcapTimestamp ?: sample->readTimestamp;
  hdr.ts_usec = 0;
  hdr.len = sample->s.sampledPacketSize;
  hdr.caplen = sample->s.headerLen;
  if(sfConfig.removeContent && sample->s.offsetToPayload) {
    /* shorten the captured header to ensure no payload bytes are included */
    hdr.caplen = sample->s.offsetToPayload;
  }

  /* prepare the whole thing in a buffer first, in case we are piping the output
     to another process and the reader expects it all to appear at once... */
  memcpy(buf, &hdr, sizeof(hdr));
  bytes = sizeof(hdr);
  memcpy(buf+bytes, sample->s.header, hdr.caplen);
  bytes += hdr.caplen;

  if(fwrite(buf, bytes, 1, stdout) != 1) {
    fprintf(ERROUT, "writePcapPacket: packet write failed: %s\n", strerror(errno));
    exit(-3);
  }
  fflush(stdout);
}

#ifdef SPOOFSOURCE

/*_________________---------------------------__________________
  _________________      in_checksum          __________________
  -----------------___________________________------------------
*/
static uint16_t in_checksum(uint16_t *addr, int len)
{
  int nleft = len;
  uint16_t *w = addr;
  uint16_t answer;
  int sum = 0;

  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) sum += *(uint8_t *)w;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

/*_________________---------------------------__________________
  _________________   openNetFlowSocket_spoof __________________
  -----------------___________________________------------------
*/

static void openNetFlowSocket_spoof()
{
  int on;

  if((sfConfig.netFlowOutputSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
    fprintf(ERROUT, "netflow output raw socket open failed\n");
    exit(-11);
  }
  on = 1;
  if(setsockopt(sfConfig.netFlowOutputSocket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0) {
    fprintf(ERROUT, "setsockopt( IP_HDRINCL ) failed\n");
    exit(-13);
  }
  on = 1;
  if(setsockopt(sfConfig.netFlowOutputSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
    fprintf(ERROUT, "setsockopt( SO_REUSEADDR ) failed\n");
    exit(-14);
  }

  memset(&sfConfig.sendPkt, 0, sizeof(sfConfig.sendPkt));
  sfConfig.sendPkt.ip.version_and_headerLen = 0x45;
  sfConfig.sendPkt.ip.protocol = IPPROTO_UDP;
  sfConfig.sendPkt.ip.ttl = 64; /* IPDEFTTL */
  sfConfig.ipid = 12000; /* start counting from 12000 (just an arbitrary number) */
  /* sfConfig.ip->frag_off = htons(0x4000); */ /* don't fragment */
  /* can't set the source address yet, but the dest address is known */
  sfConfig.sendPkt.ip.daddr = sfConfig.netFlowOutputIP.address.ip_v4.addr;
  /* can't do the ip_len and checksum until we know the size of the packet */
  sfConfig.sendPkt.udp.uh_dport = htons(sfConfig.netFlowOutputPort);
  /* might as well set the source port to be the same */
  sfConfig.sendPkt.udp.uh_sport = htons(sfConfig.netFlowOutputPort);
  /* can't do the udp_len or udp_checksum until we know the size of the packet */
}



/*_________________---------------------------__________________
  _________________ sendNetFlowDatagram_spoof __________________
  -----------------___________________________------------------
*/

static void sendNetFlowDatagram_spoof(SFSample *sample, NFFlowPkt *pkt, int len)
{
  uint16_t packetLen = len + sizeof(struct myiphdr) + sizeof(struct myudphdr);
  memcpy(sfConfig.sendPkt.data, (char *)pkt, len);
  /* increment the ip-id */
  sfConfig.sendPkt.ip.id = htons(++sfConfig.ipid);
  /* set the length fields in the ip and udp headers */
  sfConfig.sendPkt.ip.tot_len = htons(packetLen);
  sfConfig.sendPkt.udp.uh_ulen = htons(packetLen - sizeof(struct myiphdr));
  /* set the source address to the source address of the input event */
  sfConfig.sendPkt.ip.saddr = sample->agent_addr.address.ip_v4.addr;
  /* IP header checksum */
  sfConfig.sendPkt.ip.check = in_checksum((uint16_t *)&sfConfig.sendPkt.ip, sizeof(struct myiphdr));
  if (sfConfig.sendPkt.ip.check == 0) sfConfig.sendPkt.ip.check = 0xffff;
  /* UDP Checksum
     copy out those parts of the IP header that are supposed to be in the UDP checksum,
     and blat them in front of the udp header (after saving what was there before).
     Then compute the udp checksum.  Then patch the saved data back again. */
  {
    char *ptr;
    struct udpmagichdr {
      uint32_t src;
      uint32_t dst;
      uint8_t zero;
      uint8_t proto;
      uint16_t len;
    } h, saved;

    h.src = sfConfig.sendPkt.ip.saddr;
    h.dst = sfConfig.sendPkt.ip.daddr;
    h.zero = 0;
    h.proto = IPPROTO_UDP;
    h.len = sfConfig.sendPkt.udp.uh_ulen;
    /* set the pointer to 12 bytes before the start of the udp header */
    ptr = (char *)&sfConfig.sendPkt.udp;
    ptr -= sizeof(struct udpmagichdr);
    /* save what's there */
    memcpy(&saved, ptr, sizeof(struct udpmagichdr));
    /* blat in the replacement bytes */
    memcpy(ptr, &h, sizeof(struct udpmagichdr));
    /* compute the checksum */
    sfConfig.sendPkt.udp.uh_sum = 0;
    sfConfig.sendPkt.udp.uh_sum = in_checksum((uint16_t *)ptr,
					      ntohs(sfConfig.sendPkt.udp.uh_ulen) + sizeof(struct udpmagichdr));
    if (sfConfig.sendPkt.udp.uh_sum == 0) sfConfig.sendPkt.udp.uh_sum = 0xffff;
    /* copy the save bytes back again */
    memcpy(ptr, &saved, sizeof(struct udpmagichdr));

    { /* now send the packet */
      int bytesSent;
      struct sockaddr dest;
      struct sockaddr_in *to = (struct sockaddr_in *)&dest;
      memset(&dest, 0, sizeof(dest));
      to->sin_family = AF_INET;
      to->sin_addr.s_addr = sfConfig.sendPkt.ip.daddr;
      if((bytesSent = sendto(sfConfig.netFlowOutputSocket,
			     &sfConfig.sendPkt,
			     packetLen,
			     0,
			     &dest,
			     sizeof(dest))) != packetLen) {
	fprintf(ERROUT, "sendto returned %d (expected %d): %s\n", bytesSent, packetLen, strerror(errno));
      }
    }
  }
}

#endif /* SPOOFSOURCE */

/*_________________---------------------------__________________
  _________________   openNetFlowSocket       __________________
  -----------------___________________________------------------
*/

static void openNetFlowSocket()
{
  int family = (sfConfig.netFlowOutputIP.type == SFLADDRESSTYPE_IP_V6) ? AF_INET6 : AF_INET;

#ifdef SPOOFSOURCE
  if(sfConfig.spoofSource) {
    if(family == AF_INET6) {
      fprintf(ERROUT, "IPv6 source spoofing not supported\n");
      sfConfig.spoofSource = NO;
    }
    else {
      openNetFlowSocket_spoof();
      return;
    }
  }
#endif

  /* set the port (we could have getaddrinfo() do this for us too) */
  if(family == AF_INET6)
    sfConfig.netFlowOutputSA.sa6.sin6_port = ntohs(sfConfig.netFlowOutputPort);
  else
    sfConfig.netFlowOutputSA.sa4.sin_port = ntohs(sfConfig.netFlowOutputPort);

  /* open the socket */
  if((sfConfig.netFlowOutputSocket = socket(family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    fprintf(ERROUT, "netflow output socket open failed : %s\n", strerror(errno));
    exit(-4);
  }

  /* connect to it so we can just use send() or write() to send on it */
  if(connect(sfConfig.netFlowOutputSocket,
	     (struct sockaddr *)&sfConfig.netFlowOutputSA,
	     family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) != 0) {
    fprintf(ERROUT, "connect() to netflow output socket failed: %s\n",
	    strerror(errno));
    exit(-5);
  }
}

/*_________________---------------------------__________________
  _________________   sendNetFlowV5Datagram   __________________
  -----------------___________________________------------------
*/

static int NFFlowSequenceNo = 0;

static void sendNetFlowV5Datagram(SFSample *sample)
{
  NFFlowPkt5 pkt;
  uint32_t now = (uint32_t)time(NULL);
  uint32_t bytes;
  /* ignore fragments */
  if(sample->s.ip_fragmentOffset > 0) return;
  /* count the bytes from the start of IP header, with the exception that
     for udp packets we use the udp_pduLen. This is because the udp_pduLen
     can be up tp 65535 bytes, which causes fragmentation at the IP layer.
     Since the sampled fragments are discarded, we have to use this field
     to get the total bytes estimates right. */
  if(sample->s.udp_pduLen > 0) bytes = sample->s.udp_pduLen;
  else bytes = sample->s.sampledPacketSize - sample->s.stripped - sample->s.offsetToIPV4;

  memset(&pkt, 0, sizeof(pkt));
  pkt.hdr.version = htons(5);
  pkt.hdr.count = htons(1);
  pkt.hdr.sysUpTime = htonl(now % (3600 * 24)) * 1000;  /* pretend we started at midnight (milliseconds) */
  pkt.hdr.unixSeconds = htonl(now);
  pkt.hdr.unixNanoSeconds = 0; /* no need to be more accurate than 1 second */
  pkt.hdr.flowSequence = htonl(NFFlowSequenceNo++);

  pkt.flow.srcIP = sample->s.ipsrc.address.ip_v4.addr;
  pkt.flow.dstIP = sample->s.ipdst.address.ip_v4.addr;
  pkt.flow.nextHop = sample->s.nextHop.address.ip_v4.addr;
  pkt.flow.if_in = htons((uint16_t)sample->s.inputPort);
  pkt.flow.if_out= htons((uint16_t)sample->s.outputPort);

  if(!sfConfig.disableNetFlowScale) {
    pkt.flow.frames = htonl(sample->s.meanSkipCount);
    pkt.flow.bytes = htonl(sample->s.meanSkipCount * bytes);
  }
  else {
    /* set the sampling_interval header field too (used to be a 16-bit reserved field) */
    uint16_t samp_ival = (uint16_t)sample->s.meanSkipCount;
    pkt.hdr.sampling_interval = htons(samp_ival | 0x4000);
    pkt.flow.frames = htonl(1);
    pkt.flow.bytes = htonl(bytes);
  }

  pkt.flow.firstTime = pkt.hdr.sysUpTime;  /* set the start and end time to be now (in milliseconds since last boot) */
  pkt.flow.lastTime =  pkt.hdr.sysUpTime;
  pkt.flow.srcPort = htons((uint16_t)sample->s.dcd_sport);
  pkt.flow.dstPort = htons((uint16_t)sample->s.dcd_dport);
  pkt.flow.tcpFlags = sample->s.dcd_tcpFlags;
  pkt.flow.ipProto = sample->s.dcd_ipProtocol;
  pkt.flow.ipTos = sample->s.dcd_ipTos;

  if(sfConfig.netFlowPeerAS) {
    pkt.flow.srcAS = htons((uint16_t)sample->s.src_peer_as);
    pkt.flow.dstAS = htons((uint16_t)sample->s.dst_peer_as);
  }
  else {
    pkt.flow.srcAS = htons((uint16_t)sample->s.src_as);
    pkt.flow.dstAS = htons((uint16_t)sample->s.dst_as);
  }

  pkt.flow.srcMask = (uint8_t)sample->s.srcMask;
  pkt.flow.dstMask = (uint8_t)sample->s.dstMask;

#ifdef SPOOFSOURCE
  if(sfConfig.spoofSource) {
    sendNetFlowDatagram_spoof(sample, (NFFlowPkt *)&pkt, sizeof(pkt));
    return;
  }
#endif /* SPOOFSOURCE */

  /* send non-blocking */
  send(sfConfig.netFlowOutputSocket, (char *)&pkt, sizeof(pkt), 0);

}

/*_________________---------------------------__________________
  _________________   sendNetFlowV9Datagram   __________________
  -----------------___________________________------------------
*/

static void sendNetFlowV9Datagram(SFSample *sample)
{
  NFFlowPkt9 pkt;

  uint32_t now = (uint32_t)time(NULL);
  uint32_t bytes;
  uint16_t i = 0;
  const size_t fieldCount = NFFLOW9_NUM_ELEMENTS;
  /* ignore fragments */
  if(sample->s.ip_fragmentOffset > 0) return;
  /* count the bytes from the start of IP header, with the exception that
     for udp packets we use the udp_pduLen. This is because the udp_pduLen
     can be up tp 65535 bytes, which causes fragmentation at the IP layer.
     Since the sampled fragments are discarded, we have to use this field
     to get the total bytes estimates right. */
  if(sample->s.udp_pduLen > 0) bytes = sample->s.udp_pduLen;
  else bytes = sample->s.sampledPacketSize - sample->s.stripped - sample->s.offsetToIPV4;

  memset(&pkt, 0, sizeof(pkt));

  /* Fill packet header */
  pkt.hdr.version = htons(9);
  pkt.hdr.count = htons(2);  /* one template + one flow record */
  pkt.hdr.sysUpTime = htonl(now % (3600 * 24)) * 1000;  /* pretend we started at midnight (milliseconds) */
  pkt.hdr.unixSeconds = htonl(now);
  pkt.hdr.flowSequence = htonl(NFFlowSequenceNo++);

  /* Fill template flowset */
  pkt.tmpl.setId = 0;
  pkt.tmpl.length = htons(sizeof(pkt.tmpl));
  pkt.tmpl.templateId = htons(NFTEMPLATE_IPV4);
  pkt.tmpl.fieldCount = htons(fieldCount);
  for(i=0; i<fieldCount; i++) {
    pkt.tmpl.field[i].id = htons(nfField9[i].id);
    pkt.tmpl.field[i].sz = htons(nfField9[i].sz);
  }

  /* Fill data flowset */
  pkt.data.templateId = htons(NFTEMPLATE_IPV4);
  pkt.data.length = htons(sizeof(pkt.data));
  pkt.data.flow.srcIP = sample->s.ipsrc.address.ip_v4.addr;
  pkt.data.flow.dstIP = sample->s.ipdst.address.ip_v4.addr;
  pkt.data.flow.nextHop = sample->s.nextHop.address.ip_v4.addr;
  /* We are no longer truncating these interface fields as with NetFlow v5 */
  pkt.data.flow.if_in = htonl(sample->s.inputPort);
  pkt.data.flow.if_out= htonl(sample->s.outputPort);

  if(!sfConfig.disableNetFlowScale) {
    pkt.data.flow.packets = htonl(sample->s.meanSkipCount);
    pkt.data.flow.bytes = htonl(sample->s.meanSkipCount * bytes);
  }
  else {
    /* set the sampling_interval header field */
    pkt.data.flow.samplingInterval = htonl(sample->s.meanSkipCount);
    pkt.data.flow.packets = htonl(1);
    pkt.data.flow.bytes = htonl(bytes);
  }

  /* set the start and end time to be now (in milliseconds since last boot) */
  pkt.data.flow.firstTime = pkt.hdr.sysUpTime;
  pkt.data.flow.lastTime =  pkt.hdr.sysUpTime;
  pkt.data.flow.srcPort = htons((uint16_t)sample->s.dcd_sport);
  pkt.data.flow.dstPort = htons((uint16_t)sample->s.dcd_dport);
  pkt.data.flow.tcpFlags = sample->s.dcd_tcpFlags;
  pkt.data.flow.ipProto = sample->s.dcd_ipProtocol;
  pkt.data.flow.ipTos = sample->s.dcd_ipTos;

  if(sfConfig.netFlowPeerAS) {
    pkt.data.flow.srcAS = htonl(sample->s.src_peer_as);
    pkt.data.flow.dstAS = htonl(sample->s.dst_peer_as);
  }
  else {
    pkt.data.flow.srcAS = htonl(sample->s.src_as);
    pkt.data.flow.dstAS = htonl(sample->s.dst_as);
  }

  pkt.data.flow.srcMask = (uint8_t)sample->s.srcMask;
  pkt.data.flow.dstMask = (uint8_t)sample->s.dstMask;

  #ifdef SPOOFSOURCE
  if(sfConfig.spoofSource) {
    sendNetFlowDatagram_spoof(sample, (NFFlowPkt *)&pkt, sizeof(pkt));
    return;
  }
  #endif /* SPOOFSOURCE */

  /* send non-blocking */
  send(sfConfig.netFlowOutputSocket, (char *)&pkt, sizeof(pkt), 0);
}

/*_________________---------------------------__________________
  _________________  sendNetFlowV9V6Datagram  __________________
  -----------------___________________________------------------
*/

static void sendNetFlowV9V6Datagram(SFSample *sample)
{
  NFFlowPkt9_v6 pkt;

  uint32_t now = (uint32_t)time(NULL);
  uint32_t bytes;
  uint16_t i = 0;
  const size_t fieldCount = NFFLOW9_V6_NUM_ELEMENTS;
  /* ignore fragments */
  if(sample->s.ip_fragmentOffset > 0) return; // TODO: in v6 decode?
  /* count the bytes from the start of IP header, with the exception that
     for udp packets we use the udp_pduLen. This is because the udp_pduLen
     can be up tp 65535 bytes, which causes fragmentation at the IP layer.
     Since the sampled fragments are discarded, we have to use this field
     to get the total bytes estimates right. */
  if(sample->s.udp_pduLen > 0) bytes = sample->s.udp_pduLen;
  else bytes = sample->s.sampledPacketSize - sample->s.stripped - sample->s.offsetToIPV6;

  memset(&pkt, 0, sizeof(pkt));

  /* Fill packet header */
  pkt.hdr.version = htons(9);
  pkt.hdr.count = htons(2);  /* one template + one flow record */
  pkt.hdr.sysUpTime = htonl(now % (3600 * 24)) * 1000;  /* pretend we started at midnight (milliseconds) */
  pkt.hdr.unixSeconds = htonl(now);
  pkt.hdr.flowSequence = htonl(NFFlowSequenceNo++);

  /* Fill template flowset */
  pkt.tmpl.setId = 0;
  pkt.tmpl.length = htons(sizeof(pkt.tmpl));
  pkt.tmpl.templateId = htons(NFTEMPLATE_IPV6);
  pkt.tmpl.fieldCount = htons(fieldCount);
  for(i=0; i<fieldCount; i++) {
    pkt.tmpl.field[i].id = htons(nfField9_v6[i].id);
    pkt.tmpl.field[i].sz = htons(nfField9_v6[i].sz);
  }

  /* Fill data flowset */
  pkt.data.templateId = htons(NFTEMPLATE_IPV6);
  pkt.data.length = htons(sizeof(pkt.data));
  memcpy(pkt.data.flow.srcIP6, sample->s.ipsrc.address.ip_v6.addr, 16);
  memcpy(pkt.data.flow.dstIP6, sample->s.ipdst.address.ip_v6.addr, 16);
  memcpy(pkt.data.flow.nextHopIP6, sample->s.nextHop.address.ip_v6.addr, 16);
  /* We are no longer truncating these interface fields as with NetFlow v5 */
  pkt.data.flow.if_in = htonl(sample->s.inputPort);
  pkt.data.flow.if_out= htonl(sample->s.outputPort);

  if(!sfConfig.disableNetFlowScale) {
    pkt.data.flow.packets = htonl(sample->s.meanSkipCount);
    pkt.data.flow.bytes = htonl(sample->s.meanSkipCount * bytes);
  }
  else {
    /* set the sampling_interval header field */
    pkt.data.flow.samplingInterval = htonl(sample->s.meanSkipCount);
    pkt.data.flow.packets = htonl(1);
    pkt.data.flow.bytes = htonl(bytes);
  }

  /* set the start and end time to be now (in milliseconds since last boot) */
  pkt.data.flow.firstTime = pkt.hdr.sysUpTime;
  pkt.data.flow.lastTime =  pkt.hdr.sysUpTime;
  pkt.data.flow.srcPort = htons((uint16_t)sample->s.dcd_sport);
  pkt.data.flow.dstPort = htons((uint16_t)sample->s.dcd_dport);
  pkt.data.flow.tcpFlags = sample->s.dcd_tcpFlags;
  pkt.data.flow.ipProto = sample->s.dcd_ipProtocol;
  pkt.data.flow.ipTos = sample->s.dcd_ipTos;

  if(sfConfig.netFlowPeerAS) {
    pkt.data.flow.srcAS = htonl(sample->s.src_peer_as);
    pkt.data.flow.dstAS = htonl(sample->s.dst_peer_as);
  }
  else {
    pkt.data.flow.srcAS = htonl(sample->s.src_as);
    pkt.data.flow.dstAS = htonl(sample->s.dst_as);
  }

  pkt.data.flow.srcMask = (uint8_t)sample->s.srcMask;
  pkt.data.flow.dstMask = (uint8_t)sample->s.dstMask;

  pkt.data.flow.flowLabel = htonl(sample->s.dcd_flowLabel);
  #ifdef SPOOFSOURCE
  if(sfConfig.spoofSource) {
    sendNetFlowDatagram_spoof(sample, (NFFlowPkt *)&pkt, sizeof(pkt));
    return;
  }
  #endif /* SPOOFSOURCE */

  /* send non-blocking */
  send(sfConfig.netFlowOutputSocket, (char *)&pkt, sizeof(pkt), 0);
}

/*_________________---------------------------__________________
  _________________   read data fns           __________________
  -----------------___________________________------------------
*/

static uint32_t getData32_nobswap(SFSample *sample) {
  uint32_t ans = *(sample->datap)++;
  /* make sure we didn't run off the end of the datagram.  Thanks to
     Sven Eschenberg for spotting a bug/overrun-vulnerabilty that was here before. */
  if((uint8_t *)sample->datap > sample->endp) {
    SFABORT(sample, SF_ABORT_EOS);
  }
  return ans;
}

static uint32_t getData32(SFSample *sample) {
  return ntohl(getData32_nobswap(sample));
}

static float getFloat(SFSample *sample) {
  float fl;
  uint32_t reg = getData32(sample);
  memcpy(&fl, &reg, 4);
  return fl;
}

static uint64_t getData64(SFSample *sample) {
  uint64_t tmpLo, tmpHi;
  tmpHi = getData32(sample);
  tmpLo = getData32(sample);
  return (tmpHi << 32) + tmpLo;
}

static double getDouble(SFSample *sample) {
  double dbl;
  uint64_t reg = getData64(sample);
  memcpy(&dbl, &reg, 8);
  return dbl;
}

static void skipBytes(SFSample *sample, uint32_t skip) {
  int quads = (skip + 3) / 4;
  sample->datap += quads;
  if(skip > sample->rawSampleLen || (uint8_t *)sample->datap > sample->endp) {
    SFABORT(sample, SF_ABORT_EOS);
  }
}

static uint32_t sf_log_next32(SFSample *sample, char *fieldName) {
  uint32_t val = getData32(sample);
  sf_logf_U32(sample, fieldName, val);
  return val;
}

static uint64_t sf_log_next64(SFSample *sample, char *fieldName) {
  uint64_t val64 = getData64(sample);
  sf_logf_U64(sample, fieldName, val64);
  return val64;
}

void sf_log_percentage(SFSample *sample, char *fieldName)
{
  char buf[64];
  uint32_t hundredths = getData32(sample);
  if(hundredths == (uint32_t)-1)
    sf_logf(sample, fieldName, "unknown");
  else {
    float percent = (float)hundredths / (float)100.0;
    snprintf(buf, 64, "%.2f", percent);
    sf_logf(sample, fieldName, buf);
  }
}

static float sf_log_nextFloat(SFSample *sample, char *fieldName) {
  char buf[64];
  float val = getFloat(sample);
  snprintf(buf, 64, "%.3f", val);
  sf_logf(sample, fieldName, buf);
  return val;
}

void sf_log_nextMAC(SFSample *sample, char *fieldName)
{
  uint8_t *mac = (uint8_t *)sample->datap;
  skipBytes(sample, 6);
  SFStr macstr;
  SFStr_init(&macstr);
  SFStr_append_mac(&macstr, mac);
  sf_logf(sample, fieldName, SFStr_str(&macstr));
}

static uint32_t getString(SFSample *sample, char *buf, uint32_t bufLen) {
  uint32_t len, read_len;
  len = getData32(sample);
  /* check the bytes are there first */
  uint32_t *dp = sample->datap;
  skipBytes(sample, len);
  /* truncate if too long */
  read_len = (len >= bufLen) ? (bufLen - 1) : len;
  memcpy(buf, dp, read_len);
  buf[read_len] = '\0';   /* null terminate */
  return len;
}

static uint32_t getAddress(SFSample *sample, SFLAddress *address) {
  address->type = getData32(sample);
  switch(address->type) {
  case SFLADDRESSTYPE_IP_V4:
    address->address.ip_v4.addr = getData32_nobswap(sample);
    break;
  case SFLADDRESSTYPE_IP_V6:
    {
      /* make sure the data is there before we memcpy */
      uint32_t *dp = sample->datap;
      skipBytes(sample, 16);
      memcpy(&address->address.ip_v6.addr, dp, 16);
    }
    break;
  default:
    /* undefined address type - bail out */
    fprintf(ERROUT, "unknown address type = %d\n", address->type);
    SFABORT(sample, SF_ABORT_EOS);
  }
  return address->type;
}

static void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description) {
  SFStr buf;
  sf_log(sample,"skipping unknown %s: %s len=%d\n", description, printTag(tag, &buf), len);
  skipBytes(sample, len);
}

/*_________________---------------------------__________________
  _________________    readExtendedSwitch     __________________
  -----------------___________________________------------------
*/

static void readExtendedSwitch(SFSample *sample)
{
  sf_logf(sample, "extendedType", "SWITCH");
  sample->s.in_vlan = getData32(sample);
  sample->s.in_priority = getData32(sample);
  sample->s.out_vlan = getData32(sample);
  sample->s.out_priority = getData32(sample);

  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;

  sf_logf_U32(sample, "in_vlan", sample->s.in_vlan);
  sf_logf_U32(sample, "in_priority", sample->s.in_priority);
  sf_logf_U32(sample, "out_vlan", sample->s.out_vlan);
  sf_logf_U32(sample, "out_priority", sample->s.out_priority);
}

/*_________________---------------------------__________________
  _________________    readExtendedRouter     __________________
  -----------------___________________________------------------
*/

static void readExtendedRouter(SFSample *sample)
{
  SFStr buf;
  sf_logf(sample, "extendedType", "ROUTER");
  getAddress(sample, &sample->s.nextHop);
  sample->s.srcMask = getData32(sample);
  sample->s.dstMask = getData32(sample);

  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;

  sf_logf(sample, "nextHop", printAddress(&sample->s.nextHop, &buf));
  sf_logf_U32(sample, "srcSubnetMask", sample->s.srcMask);
  sf_logf_U32(sample, "dstSubnetMask", sample->s.dstMask);
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway_v2   __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway_v2(SFSample *sample)
{
  sf_logf(sample, "extendedType", "GATEWAY");

  sample->s.my_as = getData32(sample);
  sample->s.src_as = getData32(sample);
  sample->s.src_peer_as = getData32(sample);

  /* clear dst_peer_as and dst_as to make sure we are not
     remembering values from a previous sample - (thanks Marc Lavine) */
  sample->s.dst_peer_as = 0;
  sample->s.dst_as = 0;

  sample->s.dst_as_path_len = getData32(sample);
  /* just point at the dst_as_path array */
  if(sample->s.dst_as_path_len > 0) {
    sample->s.dst_as_path = sample->datap;
    /* and skip over it in the input */
    skipBytes(sample, sample->s.dst_as_path_len * 4);
    /* fill in the dst and dst_peer fields too */
    sample->s.dst_peer_as = ntohl(sample->s.dst_as_path[0]);
    sample->s.dst_as = ntohl(sample->s.dst_as_path[sample->s.dst_as_path_len - 1]);
  }

  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;

  sf_logf_U32(sample, "my_as", sample->s.my_as);
  sf_logf_U32(sample, "src_as", sample->s.src_as);
  sf_logf_U32(sample, "src_peer_as", sample->s.src_peer_as);
  sf_logf_U32(sample, "dst_as", sample->s.dst_as);
  sf_logf_U32(sample, "dst_peer_as", sample->s.dst_peer_as);
  sf_logf_U32(sample, "dst_as_path_len", sample->s.dst_as_path_len);
  if(sample->s.dst_as_path_len > 0) {
    SFStr dst_as_path;
    SFStr_init(&dst_as_path);
    SFStr_append_array32(&dst_as_path, sample->s.dst_as_path, sample->s.dst_as_path_len, YES, '-');
    sf_logf(sample, "dst_as_path", SFStr_str(&dst_as_path));
  }
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway      __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway(SFSample *sample)
{
  uint32_t segments;
  uint32_t seg;
  SFStr buf;

  sf_logf(sample, "extendedType", "GATEWAY");

  if(sample->datagramVersion >= 5) {
    getAddress(sample, &sample->s.bgp_nextHop);
    sf_logf(sample, "bgp_nexthop", printAddress(&sample->s.bgp_nextHop, &buf));
  }

  sample->s.my_as = getData32(sample);
  sample->s.src_as = getData32(sample);
  sample->s.src_peer_as = getData32(sample);
  sf_logf_U32(sample, "my_as", sample->s.my_as);
  sf_logf_U32(sample, "src_as", sample->s.src_as);
  sf_logf_U32(sample, "src_peer_as", sample->s.src_peer_as);
  segments = getData32(sample);

  /* clear dst_peer_as and dst_as to make sure we are not
     remembering values from a previous sample - (thanks Marc Lavine) */
  sample->s.dst_peer_as = 0;
  sample->s.dst_as = 0;

  if(segments > 0) {
    SFStr dst_as_path;
    SFStr_init(&dst_as_path);
    for(seg = 0; seg < segments; seg++) {
      uint32_t seg_type;
      uint32_t seg_len;
      uint32_t *seg_data;
      seg_type = getData32(sample);
      seg_len = getData32(sample);
      seg_data = sample->datap;
      skipBytes(sample, seg_len * 4);
      /* mark the first ASN as the dst_peer_as */
      if(seg == 0)
	sample->s.dst_peer_as = ntohl(seg_data[0]);
      /* make sure the AS sets are in parentheses */
      if(seg_type == SFLEXTENDED_AS_SET)
	SFStr_append(&dst_as_path, "(");
      SFStr_append_array32(&dst_as_path, seg_data, seg_len, YES, '-');
      if(seg_type == SFLEXTENDED_AS_SET)
	SFStr_append(&dst_as_path, ")");
      /* mark the last ASN as the dst_as */
      if(seg == (segments - 1))
	sample->s.dst_as = ntohl(seg_data[seg_len - 1]);
    }
    sf_logf(sample, "dst_as_path", SFStr_str(&dst_as_path));
  }
  sf_logf_U32(sample, "dst_as", sample->s.dst_as);
  sf_logf_U32(sample, "dst_peer_as", sample->s.dst_peer_as);

  sample->s.communities_len = getData32(sample);
  /* just point at the communities array */
  if(sample->s.communities_len > 0) sample->s.communities = sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, sample->s.communities_len * 4);

  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
  if(sample->s.communities_len > 0) {
    SFStr communities;
    SFStr_init(&communities);
    SFStr_append_array32(&communities, sample->s.communities, sample->s.communities_len, YES, '-');
    sf_logf(sample, "BGP_communities", SFStr_str(&communities));
  }

  sample->s.localpref = getData32(sample);
  sf_logf_U32(sample, "BGP_localpref", sample->s.localpref);
}

/*_________________---------------------------__________________
  _________________    readExtendedUser       __________________
  -----------------___________________________------------------
*/

static void readExtendedUser(SFSample *sample)
{
#define SA_MAX_EXTENDED_USER_LEN 200
  uint32_t src_user_charset;
  uint32_t src_user_len;
  char src_user[SA_MAX_EXTENDED_USER_LEN+1];
  uint32_t dst_user_charset;
  uint32_t dst_user_len;
  char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

  sf_logf(sample, "extendedType", "USER");

  if(sample->datagramVersion >= 5) {
    src_user_charset = getData32(sample);
    sf_logf_U32(sample, "src_user_charset", src_user_charset);
  }

  src_user_len = getString(sample, src_user, SA_MAX_EXTENDED_USER_LEN);

  if(sample->datagramVersion >= 5) {
    dst_user_charset = getData32(sample);
    sf_logf_U32(sample, "dst_user_charset", dst_user_charset);
  }

  dst_user_len = getString(sample, dst_user, SA_MAX_EXTENDED_USER_LEN);

  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;

  sf_logf(sample, "src_user", src_user);
  sf_logf(sample, "dst_user", dst_user);
}

/*_________________---------------------------__________________
  _________________    readExtendedUrl        __________________
  -----------------___________________________------------------
*/

static void readExtendedUrl(SFSample *sample)
{
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
  uint32_t url_direction;
  uint32_t url_len;
  char url[SA_MAX_EXTENDED_URL_LEN+1];
  uint32_t host_len;
  char host[SA_MAX_EXTENDED_HOST_LEN+1];

  sf_logf(sample, "extendedType", "URL");

  url_direction = getData32(sample);
  sf_logf_U32(sample, "url_direction", url_direction);
  url_len = getString(sample, url, SA_MAX_EXTENDED_URL_LEN);
  sf_logf(sample, "url", url);
  if(sample->datagramVersion >= 5) {
    host_len = getString(sample, host, SA_MAX_EXTENDED_HOST_LEN);
    sf_logf(sample, "host", host);
  }
  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
  _________________       mplsLabelStack      __________________
  -----------------___________________________------------------
*/

static void mplsLabelStack(SFSample *sample, char *fieldName)
{
  SFLLabelStack lstk;
  uint32_t lab;
  lstk.depth = getData32(sample);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (uint32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);

  if(lstk.depth > 0) {
    SFStr lsstr;
    SFStr_init(&lsstr);
    for(uint32_t j = 0; j < lstk.depth; j++) {
      if(j > 0)
	SFStr_append(&lsstr, "-");
      lab = ntohl(lstk.stack[j]);
      uint32_t parts[4];
      parts[0] = (lab >> 12);    /* label */
      parts[1] = (lab >> 9) & 7; /* experimental */
      parts[2] = (lab >> 8) & 1; /* bottom of stack */
      parts[3] = (lab &  255);   /* TTL */
      SFStr_append_array32(&lsstr, parts, 4, NO, '.');
    }
    sf_logf(sample, fieldName, SFStr_str(&lsstr));
  }
}

/*_________________---------------------------__________________
  _________________    readExtendedMpls       __________________
  -----------------___________________________------------------
*/

static void readExtendedMpls(SFSample *sample)
{
  SFStr buf;
  sf_logf(sample, "extendedType", "MPLS");
  getAddress(sample, &sample->s.mpls_nextHop);
  sf_logf(sample, "mpls_nexthop", printAddress(&sample->s.mpls_nextHop, &buf));

  mplsLabelStack(sample, "mpls_input_stack");
  mplsLabelStack(sample, "mpls_output_stack");

  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
  _________________    readExtendedNat        __________________
  -----------------___________________________------------------
*/

static void readExtendedNat(SFSample *sample)
{
  SFStr buf;
  sf_logf(sample, "extendedType", "NAT");
  getAddress(sample, &sample->s.nat_src);
  sf_logf(sample, "nat_src", printAddress(&sample->s.nat_src, &buf));
  getAddress(sample, &sample->s.nat_dst);
  sf_logf(sample, "nat_dst", printAddress(&sample->s.nat_dst, &buf));
  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}

/*_________________---------------------------__________________
  _________________    readExtendedNatPort    __________________
  -----------------___________________________------------------
*/

static void readExtendedNatPort(SFSample *sample)
{
  sf_logf(sample, "extendedType", "NAT PORT");
  sf_log_next32(sample, "nat_src_port");
  sf_log_next32(sample, "nat_dst_port");
}


/*_________________---------------------------__________________
  _________________    readExtendedMplsTunnel __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsTunnel(SFSample *sample)
{
#define SA_MAX_TUNNELNAME_LEN 100
  char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
  uint32_t tunnel_id, tunnel_cos;

  if(getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN) > 0)
    sf_logf(sample, "mpls_tunnel_lsp_name", tunnel_name);
  tunnel_id = getData32(sample);
  sf_logf_U32(sample, "mpls_tunnel_id", tunnel_id);
  tunnel_cos = getData32(sample);
  sf_logf_U32(sample, "mpls_tunnel_cos", tunnel_cos);
  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsVC     __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsVC(SFSample *sample)
{
#define SA_MAX_VCNAME_LEN 100
  char vc_name[SA_MAX_VCNAME_LEN+1];
  uint32_t vll_vc_id, vc_cos;
  if(getString(sample, vc_name, SA_MAX_VCNAME_LEN) > 0)
    sf_logf(sample, "mpls_vc_name", vc_name);
  vll_vc_id = getData32(sample);
  sf_logf_U32(sample, "mpls_vll_vc_id", vll_vc_id);
  vc_cos = getData32(sample);
  sf_logf_U32(sample, "mpls_vc_cos", vc_cos);
  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsFTN    __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsFTN(SFSample *sample)
{
#define SA_MAX_FTN_LEN 100
  char ftn_descr[SA_MAX_FTN_LEN+1];
  uint32_t ftn_mask;
  if(getString(sample, ftn_descr, SA_MAX_FTN_LEN) > 0)
    sf_logf(sample, "mpls_ftn_descr", ftn_descr);
  ftn_mask = getData32(sample);
  sf_logf_U32(sample, "mpls_ftn_mask", ftn_mask);
  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
  _________________  readExtendedMplsLDP_FEC  __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsLDP_FEC(SFSample *sample)
{
  uint32_t fec_addr_prefix_len = getData32(sample);
  sf_logf_U32(sample, "mpls_fec_addr_prefix_len", fec_addr_prefix_len);
  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
  _________________  readExtendedVlanTunnel   __________________
  -----------------___________________________------------------
*/

static void readExtendedVlanTunnel(SFSample *sample)
{
  uint32_t lab;
  SFLLabelStack lstk;
  lstk.depth = getData32(sample);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (uint32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);

  if(lstk.depth > 0) {
    SFStr vtstr;
    SFStr_init(&vtstr);
    uint32_t j = 0;
    for(; j < lstk.depth; j++) {
      if(j > 0)
	SFStr_append(&vtstr, "-");
      lab = ntohl(lstk.stack[j]);
      uint8_t TPI[2];
      uint32_t parts[3];
      TPI[0] = (lab >> 24);
      TPI[1] = (lab >> 16) & 255;
      parts[0] = (lab >> 13) & 7;  /* priority */
      parts[1] = (lab >> 12) & 1;  /* CFI */
      parts[2] = (lab & 4095);     /* VLAN */
      SFStr_append_hex(&vtstr, TPI, 2, YES, NO, 0);
      SFStr_append_array32(&vtstr, parts, 3, NO, '.');
    }
    sf_logf(sample, "vlan_tunnel", SFStr_str(&vtstr));
  }
  sample->s.extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiPayload  __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiPayload(SFSample *sample)
{
  sf_log_next32(sample, "cipher_suite");
  readFlowSample_header(sample);
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiRx       __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiRx(SFSample *sample)
{
  uint32_t i;
  uint8_t *bssid;
  SFStr buf;
  char ssid[SFL_MAX_SSID_LEN+1];
  if(getString(sample, ssid, SFL_MAX_SSID_LEN) > 0) {
    sf_logf(sample, "rx_SSID", ssid);
  }

  bssid = (uint8_t *)sample->datap;
  skipBytes(sample, 6);
  sf_logf(sample, "rx_BSSID", printMAC(bssid, &buf));
  sf_log_next32(sample, "rx_version");
  sf_log_next32(sample, "rx_channel");
  sf_log_next64(sample, "rx_speed");
  sf_log_next32(sample, "rx_rsni");
  sf_log_next32(sample, "rx_rcpi");
  sf_log_next32(sample, "rx_packet_uS");
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiTx       __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiTx(SFSample *sample)
{
  uint32_t i;
  uint8_t *bssid;
  SFStr buf;
  char ssid[SFL_MAX_SSID_LEN+1];
  if(getString(sample, ssid, SFL_MAX_SSID_LEN) > 0) {
    sf_logf(sample, "tx_SSID", ssid);
  }

  bssid = (uint8_t *)sample->datap;
  skipBytes(sample, 6);
  sf_logf(sample, "tx_BSSID", printMAC(bssid, &buf));
  sf_log_next32(sample, "tx_version");
  sf_log_next32(sample, "tx_transmissions");
  sf_log_next32(sample, "tx_packet_uS");
  sf_log_next32(sample, "tx_retrans_uS");
  sf_log_next32(sample, "tx_channel");
  sf_log_next64(sample, "tx_speed");
  sf_log_next32(sample, "tx_power_mW");
}

/*_________________---------------------------__________________
  _________________  readExtendedAggregation  __________________
  -----------------___________________________------------------
*/

#if 0 /* commenting this out until its caller is uncommented too */
static void readExtendedAggregation(SFSample *sample)
{
  uint32_t i, num_pdus = getData32(sample);
  sf_logf_U32(sample, "aggregation_num_pdus", num_pdus);
  for(i = 0; i < num_pdus; i++) {
    sf_logf_U32(sample, "aggregation_pdu", i);
    readFlowSample(sample, NO); /* not sure if this the right one here */
  }
}
#endif

/*_________________---------------------------__________________
  _________________  readFlowSample_header    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_header(SFSample *sample)
{
  SFStr scratch;
  sf_logf(sample, "flowSampleType", "HEADER");
  sample->s.headerProtocol = getData32(sample);
  sf_logf_U32(sample, "headerProtocol", sample->s.headerProtocol);
  sample->s.sampledPacketSize = getData32(sample);
  sf_logf_U32(sample, "sampledPacketSize", sample->s.sampledPacketSize);
  if(sample->datagramVersion > 4) {
    /* stripped count introduced in sFlow version 5 */
    sample->s.stripped = getData32(sample);
    sf_logf_U32(sample, "strippedBytes", sample->s.stripped);
  }
  sample->s.headerLen = getData32(sample);
  sf_logf_U32(sample, "headerLen", sample->s.headerLen);

  sample->s.header = (uint8_t *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->s.headerLen);
  SFStr_init(&scratch);
  SFStr_append_hex(&scratch, sample->s.header, sample->s.headerLen, NO, YES, '-');
  sf_logf(sample, "headerBytes", SFStr_str(&scratch));

  switch(sample->s.headerProtocol) {
    /* the header protocol tells us where to jump into the decode */
  case SFLHEADER_ETHERNET_ISO8023:
    decodeLinkLayer(sample);
    break;
  case SFLHEADER_IPv4:
    sample->s.gotIPV4 = YES;
    sample->s.offsetToIPV4 = 0;
    break;
  case SFLHEADER_IPv6:
    sample->s.gotIPV6 = YES;
    sample->s.offsetToIPV6 = 0;
    break;
  case SFLHEADER_IEEE80211MAC:
    decode80211MAC(sample);
    break;
  case SFLHEADER_ISO88024_TOKENBUS:
  case SFLHEADER_ISO88025_TOKENRING:
  case SFLHEADER_FDDI:
  case SFLHEADER_FRAME_RELAY:
  case SFLHEADER_X25:
  case SFLHEADER_PPP:
  case SFLHEADER_SMDS:
  case SFLHEADER_AAL5:
  case SFLHEADER_AAL5_IP:
  case SFLHEADER_MPLS:
  case SFLHEADER_POS:
  case SFLHEADER_IEEE80211_AMPDU:
  case SFLHEADER_IEEE80211_AMSDU_SUBFRAME:
    sf_log(sample,"NO_DECODE headerProtocol=%d\n", sample->s.headerProtocol);
    break;
  default:
    fprintf(ERROUT, "undefined headerProtocol = %d\n", sample->s.headerProtocol);
    exit(-12);
  }

  if(sample->s.gotIPV4) {
    /* report the size of the original IPPdu (including the IP header) */
    sf_logf_U32_formatted(sample, NULL, "IPSize", "%d", sample->s.sampledPacketSize - sample->s.stripped - sample->s.offsetToIPV4);
    decodeIPV4(sample);
  }
  else if(sample->s.gotIPV6) {
    /* report the size of the original IPPdu (including the IP header) */
    sf_logf_U32_formatted(sample, NULL, "IPSize", "%d", sample->s.sampledPacketSize - sample->s.stripped - sample->s.offsetToIPV6);
    decodeIPV6(sample);
  }

}

/*_________________---------------------------__________________
  _________________  readFlowSample_ethernet  __________________
  -----------------___________________________------------------
*/

static void readFlowSample_ethernet(SFSample *sample, char *prefix)
{
  SFStr buf;
  SFStr_init(&buf);
  SFStr_append(&buf, prefix);
  SFStr_append(&buf, "ETHERNET");
  sf_logf(sample, "flowSampleType", SFStr_str(&buf));
  sample->s.eth_len = getData32(sample);
  memcpy(sample->s.eth_src, sample->datap, 6);
  skipBytes(sample, 6);
  memcpy(sample->s.eth_dst, sample->datap, 6);
  skipBytes(sample, 6);
  sample->s.eth_type = getData32(sample);
  sf_logf_pushPrefix(sample, prefix);
  sf_logf_U32(sample, "ethernet_type", sample->s.eth_type);
  sf_logf_U32(sample, "ethernet_len", sample->s.eth_len);
  sf_logf(sample, "ethernet_src", printMAC(sample->s.eth_src, &buf));
  sf_logf(sample, "ethernet_dst", printMAC(sample->s.eth_dst, &buf));
  sf_logf_popPrefix(sample);
}


/*_________________---------------------------__________________
  _________________    readFlowSample_IPv4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv4(SFSample *sample, char *prefix)
{
  SFStr buf;
  SFStr_init(&buf);
  SFStr_append(&buf, prefix);
  SFStr_append(&buf, "IPV4");
  sf_logf(sample, "flowSampleType", SFStr_str(&buf));
  sample->s.headerLen = sizeof(SFLSampled_ipv4);
  sample->s.header = (uint8_t *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->s.headerLen);
  sf_logf_pushPrefix(sample, prefix);
  {
    SFStr buf;
    SFLSampled_ipv4 nfKey;
    memcpy(&nfKey, sample->s.header, sizeof(nfKey));
    sample->s.sampledPacketSize = ntohl(nfKey.length);
    sf_logf_U32(sample, "sampledPacketSize", sample->s.sampledPacketSize);
    sf_logf_U32(sample, "IPSize", sample->s.sampledPacketSize);
    sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V4;
    sample->s.ipsrc.address.ip_v4 = nfKey.src_ip;
    sample->s.ipdst.type = SFLADDRESSTYPE_IP_V4;
    sample->s.ipdst.address.ip_v4 = nfKey.dst_ip;
    sample->s.dcd_ipProtocol = ntohl(nfKey.protocol);
    sample->s.dcd_ipTos = ntohl(nfKey.tos);
    sf_logf(sample, "srcIP", printAddress(&sample->s.ipsrc, &buf));
    sf_logf(sample, "dstIP", printAddress(&sample->s.ipdst, &buf));
    sf_logf_U32(sample, "IPProtocol", sample->s.dcd_ipProtocol);
    sf_logf_U32(sample, "IPTOS", sample->s.dcd_ipTos);
    sample->s.dcd_sport = ntohl(nfKey.src_port);
    sample->s.dcd_dport = ntohl(nfKey.dst_port);
    switch(sample->s.dcd_ipProtocol) {
    case 1: /* ICMP */
      sf_logf_U32(sample, "ICMPType", sample->s.dcd_dport);
      /* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
      break;
    case 6: /* TCP */
      sf_logf_U32(sample, "TCPSrcPort", sample->s.dcd_sport);
      sf_logf_U32(sample, "TCPDstPort", sample->s.dcd_dport);
      sample->s.dcd_tcpFlags = ntohl(nfKey.tcp_flags);
      sf_logf_U32(sample, "TCPFlags", sample->s.dcd_tcpFlags);
      break;
    case 17: /* UDP */
      sf_logf_U32(sample, "UDPSrcPort", sample->s.dcd_sport);
      sf_logf_U32(sample, "UDPDstPort", sample->s.dcd_dport);
      break;
    default: /* some other protcol */
      break;
    }
  }
  sf_logf_popPrefix(sample);
  sample->s.gotIPV4Struct = YES;
}

/*_________________---------------------------__________________
  _________________    readFlowSample_IPv6    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv6(SFSample *sample, char *prefix)
{
  SFStr buf;
  SFStr_init(&buf);
  SFStr_append(&buf, prefix);
  SFStr_append(&buf, "IPV6");
  sf_logf(sample, "flowSampleType", SFStr_str(&buf));
  sample->s.header = (uint8_t *)sample->datap; /* just point at the header */
  sample->s.headerLen = sizeof(SFLSampled_ipv6);
  skipBytes(sample, sample->s.headerLen);
  sf_logf_pushPrefix(sample, prefix);
  {
    SFStr buf;
    SFLSampled_ipv6 nfKey6;
    memcpy(&nfKey6, sample->s.header, sizeof(nfKey6));
    sample->s.sampledPacketSize = ntohl(nfKey6.length);
    sf_logf_U32(sample, "sampledPacketSize", sample->s.sampledPacketSize); 
    sf_logf_U32(sample, "IPSize", sample->s.sampledPacketSize); 
    sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->s.ipsrc.address.ip_v6, &nfKey6.src_ip, 16);
    sample->s.ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->s.ipdst.address.ip_v6, &nfKey6.dst_ip, 16);
    sample->s.dcd_ipProtocol = ntohl(nfKey6.protocol);
    sf_logf(sample, "srcIP6", printAddress(&sample->s.ipsrc, &buf));
    sf_logf(sample, "dstIP6", printAddress(&sample->s.ipdst, &buf));
    sf_logf_U32(sample, "IPProtocol", sample->s.dcd_ipProtocol);
    sf_logf_U32(sample, "priority", ntohl(nfKey6.priority));
    sample->s.dcd_sport = ntohl(nfKey6.src_port);
    sample->s.dcd_dport = ntohl(nfKey6.dst_port);
    switch(sample->s.dcd_ipProtocol) {
    case 1: /* ICMP */
      sf_logf_U32(sample, "ICMPType", sample->s.dcd_dport);
      /* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
      break;
    case 6: /* TCP */
      sf_logf_U32(sample, "TCPSrcPort", sample->s.dcd_sport);
      sf_logf_U32(sample, "TCPDstPort", sample->s.dcd_dport);
      sample->s.dcd_tcpFlags = ntohl(nfKey6.tcp_flags);
      sf_logf_U32(sample, "TCPFlags", sample->s.dcd_tcpFlags);
      break;
    case 17: /* UDP */
      sf_logf_U32(sample, "UDPSrcPort", sample->s.dcd_sport);
      sf_logf_U32(sample, "UDPDstPort", sample->s.dcd_dport);
      break;
    default: /* some other protcol */
      break;
    }
  }
  sf_logf_popPrefix(sample);
  sample->s.gotIPV6Struct = YES;
}

/*_________________----------------------------__________________
  _________________  readFlowSample_memcache   __________________
  -----------------____________________________------------------
*/

static void readFlowSample_memcache(SFSample *sample)
{
  char key[SFL_MAX_MEMCACHE_KEY+1];
#define ENC_KEY_BYTES (SFL_MAX_MEMCACHE_KEY * 3) + 1
  char enc_key[ENC_KEY_BYTES];
  sf_logf(sample, "flowSampleType", "memcache");
  sf_log_next32(sample, "memcache_op_protocol");
  sf_log_next32(sample, "memcache_op_cmd");
  if(getString(sample, key, SFL_MAX_MEMCACHE_KEY) > 0) {
    sf_logf(sample, "memcache_op_key", URLEncode(key, enc_key, ENC_KEY_BYTES));
  }
  sf_log_next32(sample, "memcache_op_nkeys");
  sf_log_next32(sample, "memcache_op_value_bytes");
  sf_log_next32(sample, "memcache_op_duration_uS");
  sf_log_next32(sample, "memcache_op_status");
}

/*_________________----------------------------__________________
  _________________  readFlowSample_http       __________________
  -----------------____________________________------------------
*/

/* absorb compiler warning about strftime printing */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"

static void readFlowSample_http(SFSample *sample, uint32_t tag)
{
  char uri[SFL_MAX_HTTP_URI+1];
  char host[SFL_MAX_HTTP_HOST+1];
  char referrer[SFL_MAX_HTTP_REFERRER+1];
  char useragent[SFL_MAX_HTTP_USERAGENT+1];
  char xff[SFL_MAX_HTTP_XFF+1];
  char authuser[SFL_MAX_HTTP_AUTHUSER+1];
  char mimetype[SFL_MAX_HTTP_MIMETYPE+1];
  uint32_t method;
  uint32_t protocol;
  uint32_t status;
  uint64_t req_bytes;
  uint64_t resp_bytes;

  sf_logf(sample, "flowSampleType", "http");
  method = sf_log_next32(sample, "http_method");
  protocol = sf_log_next32(sample, "http_protocol");
  if(getString(sample, uri, SFL_MAX_HTTP_URI) > 0) {
    sf_logf(sample, "http_uri", uri);
  }
  if(getString(sample, host, SFL_MAX_HTTP_HOST) > 0) {
    sf_logf(sample, "http_host", host);
  }
  if(getString(sample, referrer, SFL_MAX_HTTP_REFERRER) > 0) {
    sf_logf(sample, "http_referrer", referrer);
  }
  if(getString(sample, useragent, SFL_MAX_HTTP_USERAGENT) > 0) {
    sf_logf(sample, "http_useragent", useragent);
  }
  if(tag == SFLFLOW_HTTP2) {
    if(getString(sample, xff, SFL_MAX_HTTP_XFF) > 0) {
      sf_logf(sample, "http_xff", xff);
    }
  }
  if(getString(sample, authuser, SFL_MAX_HTTP_AUTHUSER) > 0) {
    sf_logf(sample, "http_authuser", authuser);
  }
  if(getString(sample, mimetype, SFL_MAX_HTTP_MIMETYPE) > 0) {
    sf_logf(sample, "http_mimetype", mimetype);
  }
  if(tag == SFLFLOW_HTTP2) {
    req_bytes = sf_log_next64(sample, "http_request_bytes");
  }
  resp_bytes = sf_log_next64(sample, "http_bytes");
  sf_log_next32(sample, "http_duration_uS");
  status = sf_log_next32(sample, "http_status");

  if(sfConfig.outputFormat == SFLFMT_CLF) {
    time_t now = time(NULL);
    char nowstr[200];
    strftime(nowstr, 200, "%d/%b/%Y:%H:%M:%S %z", localtime(&now)); /* there seems to be no simple portable equivalent to %z */
    snprintf(sfCLF.http_log, SFLFMT_CLF_MAX_LINE, "- %s [%s] \"%s %s HTTP/%u.%u\" %u %"PRIu64" \"%s\" \"%s\"",
	     authuser[0] ? authuser : "-",
	     nowstr,
	     SFHTTP_method_names[method],
	     uri[0] ? uri : "-",
	     protocol / 1000,
	     protocol % 1000,
	     status,
	     resp_bytes,
	     referrer[0] ? referrer : "-",
	     useragent[0] ? useragent : "-");
    sfCLF.valid = YES;
  }
}

#pragma GCC diagnostic pop

/*_________________----------------------------__________________
  _________________  readFlowSample_APP        __________________
  -----------------____________________________------------------
*/

static void readFlowSample_APP(SFSample *sample)
{
  char application[SFLAPP_MAX_APPLICATION_LEN];
  char operation[SFLAPP_MAX_OPERATION_LEN];
  char attributes[SFLAPP_MAX_ATTRIBUTES_LEN];
  char status[SFLAPP_MAX_STATUS_LEN];
  uint32_t status32;

  sf_logf(sample, "flowSampleType", "applicationOperation");

  if(getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
    sf_logf(sample, "application", application);
  }
  if(getString(sample, operation, SFLAPP_MAX_OPERATION_LEN) > 0) {
    sf_logf(sample, "operation", operation);
  }
  if(getString(sample, attributes, SFLAPP_MAX_ATTRIBUTES_LEN) > 0) {
    sf_logf(sample, "attributes", attributes);
  }
  if(getString(sample, status, SFLAPP_MAX_STATUS_LEN) > 0) {
    sf_logf(sample, "status_descr", status);
  }
  sf_log_next64(sample, "request_bytes");
  sf_log_next64(sample, "response_bytes");
  sf_log_next32(sample, "duration_uS");
  status32 = getData32(sample);
  if(status32 >= SFLAPP_NUM_STATUS_CODES) {
    char buf[64];
    snprintf(buf, 64, "<out-of-range=%u>", status32);
    sf_logf(sample, "status", buf);
  }
  else {
    sf_logf(sample, "status", (char *)SFL_APP_STATUS_names[status32]);
  }
}


/*_________________----------------------------__________________
  _________________  readFlowSample_APP_CTXT   __________________
  -----------------____________________________------------------
*/

static void readFlowSample_APP_CTXT(SFSample *sample)
{
  char application[SFLAPP_MAX_APPLICATION_LEN];
  char operation[SFLAPP_MAX_OPERATION_LEN];
  char attributes[SFLAPP_MAX_ATTRIBUTES_LEN];
  if(getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
    sf_logf(sample, "server_context_application", application);
  }
  if(getString(sample, operation, SFLAPP_MAX_OPERATION_LEN) > 0) {
    sf_logf(sample, "server_context_operation", operation);
  }
  if(getString(sample, attributes, SFLAPP_MAX_ATTRIBUTES_LEN) > 0) {
    sf_logf(sample, "server_context_attributes", attributes);
  }
}

/*_________________---------------------------------__________________
  _________________  readFlowSample_APP_ACTOR_INIT  __________________
  -----------------_________________________________------------------
*/

static void readFlowSample_APP_ACTOR_INIT(SFSample *sample)
{
  char actor[SFLAPP_MAX_ACTOR_LEN];
  if(getString(sample, actor, SFLAPP_MAX_ACTOR_LEN) > 0) {
    sf_logf(sample, "actor_initiator", actor);
  }
}

/*_________________---------------------------------__________________
  _________________  readFlowSample_APP_ACTOR_TGT   __________________
  -----------------_________________________________------------------
*/

static void readFlowSample_APP_ACTOR_TGT(SFSample *sample)
{
  char actor[SFLAPP_MAX_ACTOR_LEN];
  if(getString(sample, actor, SFLAPP_MAX_ACTOR_LEN) > 0) {
    sf_logf(sample, "actor_target", actor);
  }
}

/*_________________----------------------------__________________
  _________________   readExtendedSocket4      __________________
  -----------------____________________________------------------
*/

static void readExtendedSocket4(SFSample *sample)
{
  SFStr buf;
  sf_logf(sample, "extendedType", "socket4");
  sf_log_next32(sample, "socket4_ip_protocol");
  sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V4;
  sample->s.ipsrc.address.ip_v4.addr = getData32_nobswap(sample);
  sample->s.ipdst.type = SFLADDRESSTYPE_IP_V4;
  sample->s.ipdst.address.ip_v4.addr = getData32_nobswap(sample);
  sf_logf(sample, "socket4_local_ip", printAddress(&sample->s.ipsrc, &buf));
  sf_logf(sample, "socket4_remote_ip", printAddress(&sample->s.ipdst, &buf));
  sf_log_next32(sample, "socket4_local_port");
  sf_log_next32(sample, "socket4_remote_port");

  if(sfConfig.outputFormat == SFLFMT_CLF)
    SFStr_copy(&buf, sfCLF.client, SFLFMT_CLF_MAX_CLIENT_LEN);
}

/*_________________----------------------------__________________
  _________________ readExtendedProxySocket4   __________________
  -----------------____________________________------------------
*/

static void readExtendedProxySocket4(SFSample *sample)
{
  SFStr buf;
  SFLAddress ipsrc,ipdst;
  sf_logf(sample, "extendedType", "proxy_socket4");
  sf_log_next32(sample, "proxy_socket4_ip_protocol");
  ipsrc.type = SFLADDRESSTYPE_IP_V4;
  ipsrc.address.ip_v4.addr = getData32_nobswap(sample);
  ipdst.type = SFLADDRESSTYPE_IP_V4;
  ipdst.address.ip_v4.addr = getData32_nobswap(sample);
  sf_logf(sample, "proxy_socket4_local_ip", printAddress(&ipsrc, &buf));
  sf_logf(sample, "proxy_socket4_remote_ip", printAddress(&ipdst, &buf));
  sf_log_next32(sample, "proxy_socket4_local_port");
  sf_log_next32(sample, "proxy_socket4_remote_port");
}

/*_________________----------------------------__________________
  _________________  readExtendedSocket6       __________________
  -----------------____________________________------------------
*/

static void readExtendedSocket6(SFSample *sample)
{
  SFStr buf;
  sf_logf(sample, "extendedType", "socket6");
  sf_log_next32(sample, "socket6_ip_protocol");
  sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&sample->s.ipsrc.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  sample->s.ipdst.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&sample->s.ipdst.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  sf_logf(sample, "socket6_local_ip", printAddress(&sample->s.ipsrc, &buf));
  sf_logf(sample, "socket6_remote_ip", printAddress(&sample->s.ipdst, &buf));
  sf_log_next32(sample, "socket6_local_port");
  sf_log_next32(sample, "socket6_remote_port");

  if(sfConfig.outputFormat == SFLFMT_CLF)
    SFStr_copy(&buf, sfCLF.client, SFLFMT_CLF_MAX_CLIENT_LEN);
}

/*_________________----------------------------__________________
  _________________ readExtendedProxySocket6   __________________
  -----------------____________________________------------------
*/

static void readExtendedProxySocket6(SFSample *sample)
{
  SFStr buf;
  SFLAddress ipsrc, ipdst;
  sf_logf(sample, "extendedType", "proxy_socket6");
  sf_log_next32(sample, "proxy_socket6_ip_protocol");
  ipsrc.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&ipsrc.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  ipdst.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&ipdst.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  sf_logf(sample, "proxy_socket6_local_ip", printAddress(&ipsrc, &buf));
  sf_logf(sample, "proxy_socket6_remote_ip", printAddress(&ipdst, &buf));
  sf_log_next32(sample, "proxy_socket6_local_port");
  sf_log_next32(sample, "proxy_socket6_remote_port");
}

/*_________________----------------------------__________________
  _________________    readExtendedDecap       __________________
  -----------------____________________________------------------
*/

static void readExtendedDecap(SFSample *sample, char *prefix)
{
  SFStr buf;
  SFStr_init(&buf);
  SFStr_append(&buf, prefix);
  SFStr_append(&buf, "decap");
  sf_logf(sample, "extendedType", SFStr_str(&buf));
  uint32_t offset = getData32(sample);
  sf_logf_U32_formatted(sample, prefix, "decap_inner_header_offset", "%u", offset);
}

/*_________________----------------------------__________________
  _________________    readExtendedVNI         __________________
  -----------------____________________________------------------
*/

static void readExtendedVNI(SFSample *sample, char *prefix)
{
  SFStr buf;
  SFStr_init(&buf);
  SFStr_append(&buf, prefix);
  SFStr_append(&buf, "VNI");
  sf_logf(sample, "extendedType", SFStr_str(&buf));
  uint32_t vni = getData32(sample);
  sf_logf_U32_formatted(sample, prefix, "VNI", "%u", vni);
}

/*_________________----------------------------__________________
  _________________    readExtendedTCPInfo     __________________
  -----------------____________________________------------------
*/

static void readExtendedTCPInfo(SFSample *sample)
{
  char *direction;
  EnumPktDirection dirn = getData32(sample);
  switch(dirn) {
  case PKTDIR_unknown: direction = "unknown"; break;
  case PKTDIR_received: direction = "received"; break;
  case PKTDIR_sent: direction = "sent"; break;
  default: direction = "<bad value>"; break;
  }
  sf_logf(sample, "tcpinfo_direction", direction);
  sf_log_next32(sample, "tcpinfo_send_mss");
  sf_log_next32(sample, "tcpinfo_receive_mss");
  sf_log_next32(sample, "tcpinfo_unacked_pkts");
  sf_log_next32(sample, "tcpinfo_lost_pkts");
  sf_log_next32(sample, "tcpinfo_retrans_pkts");
  sf_log_next32(sample, "tcpinfo_path_mtu");
  sf_log_next32(sample, "tcpinfo_rtt_uS");
  sf_log_next32(sample, "tcpinfo_rtt_uS_var");
  sf_log_next32(sample, "tcpinfo_send_congestion_win");
  sf_log_next32(sample, "tcpinfo_reordering");
  sf_log_next32(sample, "tcpinfo_rtt_uS_min");
}

/*_________________----------------------------__________________
  _________________    readExtendedEntities    __________________
  -----------------____________________________------------------
*/

static void readExtendedEntities(SFSample *sample)
{
  sf_logf(sample, "extendedType", "entities");
  sf_log_next32(sample, "entities_src_class");
  sf_log_next32(sample, "entities_src_index");
  sf_log_next32(sample, "entities_dst_class");
  sf_log_next32(sample, "entities_dst_index");
}

/*_________________----------------------------__________________
  _________________    readExtendedEgressQueue __________________
  -----------------____________________________------------------
*/

static void readExtendedEgressQueue(SFSample *sample)
{
  sf_logf(sample, "extendedType", "egress_queue");
  sf_log_next32(sample, "egress_queue_id");
}

/*_________________----------------------------__________________
  _________________    readExtendedFunction    __________________
  -----------------____________________________------------------
*/

static void readExtendedFunction(SFSample *sample)
{
  sf_logf(sample, "extendedType", "function");
  char fnSymbol[SFL_MAX_FUNCTION_SYMBOL_LEN+1];
  if(getString(sample, fnSymbol, SFL_MAX_FUNCTION_SYMBOL_LEN) > 0) {
    sf_logf(sample, "symbol", fnSymbol);
  }
}

/*_________________----------------------------__________________
  _________________  readExtendedTransitDelay  __________________
  -----------------____________________________------------------
*/

static void readExtendedTransitDelay(SFSample *sample)
{
  sf_logf(sample, "extendedType", "transit_delay");
  sf_log_next32(sample, "transit_delay_nS");
}

/*_________________----------------------------__________________
  _________________  readExtendedQueueDepth    __________________
  -----------------____________________________------------------
*/

static void readExtendedQueueDepth(SFSample *sample)
{
  sf_logf(sample, "extendedType", "queue_depth");
  sf_log_next32(sample, "queue_depth_bytes");
}

/*_________________----------------------------__________________
  _________________  readExtendedHardwareTrap  __________________
  -----------------____________________________------------------
*/

static void readExtendedHardwareTrap(SFSample *sample)
{
  sf_logf(sample, "extendedType", "hw_trap");
  char groupName[SFL_MAX_HW_TRAP_LEN+1];
  char trapName[SFL_MAX_HW_TRAP_LEN+1];
  if(getString(sample, groupName, SFL_MAX_HW_TRAP_LEN) > 0) {
    sf_logf(sample, "hw_trap_group", groupName);
  }
  if(getString(sample, trapName, SFL_MAX_HW_TRAP_LEN) > 0) {
    sf_logf(sample, "hw_trap_name", trapName);
  }
}

/*_________________----------------------------__________________
  _________________  readExtendedLinuxReason   __________________
  -----------------____________________________------------------
*/

static void readExtendedLinuxReason(SFSample *sample)
{
  sf_logf(sample, "extendedType", "linux_reason");
  char reason[SFL_MAX_LINUX_REASON_LEN+1];
  if(getString(sample, reason, SFL_MAX_LINUX_REASON_LEN) > 0) {
    sf_logf(sample, "linux_drop_reason", reason);
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample_v2v4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_v2v4(SFSample *sample)
{
  SFStr buf;
  sf_logf(sample, "sampleType", "FLOWSAMPLE");

  sample->s.samplesGenerated = getData32(sample);
  sf_logf_U32(sample, "sampleSequenceNo", sample->s.samplesGenerated);
  {
    uint32_t samplerId = getData32(sample);
    sample->s.ds_class = samplerId >> 24;
    sample->s.ds_index = samplerId & 0x00ffffff;
    sf_logf(sample, "sourceId", printDataSource(sample->s.ds_class, sample->s.ds_index, &buf));
  }

  sample->s.meanSkipCount = getData32(sample);
  sample->s.samplePool = getData32(sample);
  sample->s.dropEvents = getData32(sample);
  sample->s.inputPort = getData32(sample);
  sample->s.outputPort = getData32(sample);
  sf_logf_U32(sample, "meanSkipCount", sample->s.meanSkipCount);
  sf_logf_U32(sample, "samplePool", sample->s.samplePool);
  sf_logf_U32(sample, "dropEvents", sample->s.dropEvents);
  sf_logf_U32(sample, "inputPort", sample->s.inputPort);
  sf_logf(sample, "outputPort", printOutputPort_v2v4(sample->s.outputPort, &buf));

  sample->s.packet_data_tag = getData32(sample);

  if(sfConfig.outputFormat == SFLFMT_JSON) {
    json_start_ar("elements");
    json_start_ob(NULL);
  }

  switch(sample->s.packet_data_tag) {

  case INMPACKETTYPE_HEADER: readFlowSample_header(sample); break;
  case INMPACKETTYPE_IPV4:
    readFlowSample_IPv4(sample, "");
    break;
  case INMPACKETTYPE_IPV6:
    readFlowSample_IPv6(sample, "");
    break;
  default: receiveError(sample, "unexpected packet_data_tag", YES); break;
  }

  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_end_ob();

  sample->s.extended_data_tag = 0;
  {
    uint32_t x;
    sample->s.num_extended = getData32(sample);
    for(x = 0; x < sample->s.num_extended; x++) {
      uint32_t extended_tag;
      if(sfConfig.outputFormat == SFLFMT_JSON) {
	json_start_ob(NULL);
      }
      extended_tag = getData32(sample);
      switch(extended_tag) {
      case INMEXTENDED_SWITCH: readExtendedSwitch(sample); break;
      case INMEXTENDED_ROUTER: readExtendedRouter(sample); break;
      case INMEXTENDED_GATEWAY:
	if(sample->datagramVersion == 2) readExtendedGateway_v2(sample);
	else readExtendedGateway(sample);
	break;
      case INMEXTENDED_USER: readExtendedUser(sample); break;
      case INMEXTENDED_URL: readExtendedUrl(sample); break;
      default: receiveError(sample, "unrecognized extended data tag", YES); break;
      }
      if(sfConfig.outputFormat == SFLFMT_JSON)
	json_end_ob();
    }
  }
  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_end_ar();

  if(sampleFilterOK(sample)) {
    switch(sfConfig.outputFormat) {
    case SFLFMT_NETFLOW:
      /* if we are exporting netflow and we have an IPv4 layer, compose the datagram now */
      if(sfConfig.netFlowOutputSocket) {
	if((sample->s.gotIPV4 || sample->s.gotIPV4Struct)
	   && sendNetFlowDatagram != NULL)
	  sendNetFlowDatagram(sample);
	/* If we have an IPv6 layer, compose the datagram now */
	if((sample->s.gotIPV6 || sample->s.gotIPV6Struct)
	   && sendNetFlowDatagram_v6 != NULL)
	  sendNetFlowDatagram_v6(sample);
      }
      break;
    case SFLFMT_PCAP:
      /* if we are writing tcpdump format, write the next packet record now */
      writePcapPacket(sample);
      break;
    case SFLFMT_PCAP_DISCARD:
      break;
    case SFLFMT_LINE:
      /* or line-by-line output... */
      writeFlowLine(sample);
      break;
    case SFLFMT_LINE_CUSTOM:
      /* or custom line-by-line output... */
      writeLineCustom(sample);
      break;
    case SFLFMT_CLF:
    case SFLFMT_FULL:
    case SFLFMT_SCRIPT:
    case SFLFMT_JSON:
    default:
      /* if it was full-detail output then it was done as we went along */
      break;
    }
  }
  if(sfConfig.outputFormat == SFLFMT_LINE_CUSTOM) {
    /* do this here in case sampleFilter rejected sample above */
    clearLineCustom(sample, SFSCOPE_SAMPLE);
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample         __________________
  -----------------___________________________------------------
*/

static void readFlowSample(SFSample *sample, int expanded)
{
  SFStr buf;
  uint32_t num_elements, sampleLength;
  uint8_t *sampleStart;

  sf_logf(sample, "sampleType", "FLOWSAMPLE");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  sample->s.samplesGenerated = getData32(sample);
  if(expanded) {
    sample->s.ds_class = getData32(sample);
    sample->s.ds_index = getData32(sample);
  }
  else {
    uint32_t samplerId = getData32(sample);
    sample->s.ds_class = samplerId >> 24;
    sample->s.ds_index = samplerId & 0x00ffffff;
  }
  sf_logf_U32(sample, "sampleSequenceNo", sample->s.samplesGenerated);
  sf_logf(sample, "sourceId", printDataSource(sample->s.ds_class, sample->s.ds_index, &buf));

  sample->s.meanSkipCount = getData32(sample);
  sample->s.samplePool = getData32(sample);
  sample->s.dropEvents = getData32(sample);
  sf_logf_U32(sample, "meanSkipCount", sample->s.meanSkipCount);
  sf_logf_U32(sample, "samplePool", sample->s.samplePool);
  sf_logf_U32(sample, "dropEvents", sample->s.dropEvents);
  if(expanded) {
    sample->s.inputPortFormat = getData32(sample);
    sample->s.inputPort = getData32(sample);
    sample->s.outputPortFormat = getData32(sample);
    sample->s.outputPort = getData32(sample);
  }
  else {
    uint32_t inp, outp;
    inp = getData32(sample);
    outp = getData32(sample);
    sample->s.inputPortFormat = inp >> 30;
    sample->s.outputPortFormat = outp >> 30;
    sample->s.inputPort = inp & 0x3fffffff;
    sample->s.outputPort = outp & 0x3fffffff;
  }

  sf_logf(sample, "inputPort", printInOutPort(sample->s.inputPort, sample->s.inputPortFormat, &buf));
  sf_logf(sample, "outputPort", printInOutPort(sample->s.outputPort, sample->s.outputPortFormat, &buf));

  /* clear the CLF record */
  sfCLF.valid = NO;
  sfCLF.client[0] = '\0';

  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_start_ar("elements");

  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      uint32_t tag, length;
      uint8_t *start;
      SFStr buf;
      if(sfConfig.outputFormat == SFLFMT_JSON) {
	json_start_ob(NULL);
      }
      tag = sample->s.elementType = getData32(sample);
      sf_logf(sample, "flowBlock_tag", printTag(tag, &buf));
      length = getData32(sample);
      start = (uint8_t *)sample->datap;

      switch(tag) {
      case SFLFLOW_HEADER:     readFlowSample_header(sample); break;
      case SFLFLOW_ETHERNET:   readFlowSample_ethernet(sample, ""); break;
      case SFLFLOW_IPV4:       readFlowSample_IPv4(sample, ""); break;
      case SFLFLOW_IPV6:       readFlowSample_IPv6(sample, ""); break;
      case SFLFLOW_MEMCACHE:   readFlowSample_memcache(sample); break;
      case SFLFLOW_HTTP:       readFlowSample_http(sample, tag); break;
      case SFLFLOW_HTTP2:      readFlowSample_http(sample, tag); break;
      case SFLFLOW_APP:        readFlowSample_APP(sample); break;
      case SFLFLOW_APP_CTXT:   readFlowSample_APP_CTXT(sample); break;
      case SFLFLOW_APP_ACTOR_INIT: readFlowSample_APP_ACTOR_INIT(sample); break;
      case SFLFLOW_APP_ACTOR_TGT: readFlowSample_APP_ACTOR_TGT(sample); break;
      case SFLFLOW_EX_SWITCH:  readExtendedSwitch(sample); break;
      case SFLFLOW_EX_ROUTER:  readExtendedRouter(sample); break;
      case SFLFLOW_EX_GATEWAY: readExtendedGateway(sample); break;
      case SFLFLOW_EX_USER:    readExtendedUser(sample); break;
      case SFLFLOW_EX_URL:     readExtendedUrl(sample); break;
      case SFLFLOW_EX_MPLS:    readExtendedMpls(sample); break;
      case SFLFLOW_EX_NAT:     readExtendedNat(sample); break;
      case SFLFLOW_EX_NAT_PORT:     readExtendedNatPort(sample); break;
      case SFLFLOW_EX_MPLS_TUNNEL:  readExtendedMplsTunnel(sample); break;
      case SFLFLOW_EX_MPLS_VC:      readExtendedMplsVC(sample); break;
      case SFLFLOW_EX_MPLS_FTN:     readExtendedMplsFTN(sample); break;
      case SFLFLOW_EX_MPLS_LDP_FEC: readExtendedMplsLDP_FEC(sample); break;
      case SFLFLOW_EX_VLAN_TUNNEL:  readExtendedVlanTunnel(sample); break;
      case SFLFLOW_EX_80211_PAYLOAD: readExtendedWifiPayload(sample); break;
      case SFLFLOW_EX_80211_RX: readExtendedWifiRx(sample); break;
      case SFLFLOW_EX_80211_TX: readExtendedWifiTx(sample); break;
	/* case SFLFLOW_EX_AGGREGATION: readExtendedAggregation(sample); break; */
      case SFLFLOW_EX_SOCKET4: readExtendedSocket4(sample); break;
      case SFLFLOW_EX_SOCKET6: readExtendedSocket6(sample); break;
      case SFLFLOW_EX_PROXYSOCKET4: readExtendedProxySocket4(sample); break;
      case SFLFLOW_EX_PROXYSOCKET6: readExtendedProxySocket6(sample); break;
      case SFLFLOW_EX_L2_TUNNEL_OUT: readFlowSample_ethernet(sample, "tunnel_l2_out_"); break;
      case SFLFLOW_EX_L2_TUNNEL_IN: readFlowSample_ethernet(sample, "tunnel_l2_in_"); break;
      case SFLFLOW_EX_IPV4_TUNNEL_OUT: readFlowSample_IPv4(sample, "tunnel_ipv4_out_"); break;
      case SFLFLOW_EX_IPV4_TUNNEL_IN: readFlowSample_IPv4(sample, "tunnel_ipv4_in_"); break;
      case SFLFLOW_EX_IPV6_TUNNEL_OUT: readFlowSample_IPv6(sample, "tunnel_ipv6_out_"); break;
      case SFLFLOW_EX_IPV6_TUNNEL_IN: readFlowSample_IPv6(sample, "tunnel_ipv6_in_"); break;
      case SFLFLOW_EX_DECAP_OUT: readExtendedDecap(sample, "out_"); break;
      case SFLFLOW_EX_DECAP_IN: readExtendedDecap(sample, "in_"); break;
      case SFLFLOW_EX_VNI_OUT: readExtendedVNI(sample, "out_"); break;
      case SFLFLOW_EX_VNI_IN: readExtendedVNI(sample, "in_"); break;
      case SFLFLOW_EX_TCP_INFO: readExtendedTCPInfo(sample); break;
      case SFLFLOW_EX_ENTITIES: readExtendedEntities(sample); break;
      case SFLFLOW_EX_EGRESS_Q: readExtendedEgressQueue(sample); break;
      case SFLFLOW_EX_TRANSIT: readExtendedTransitDelay(sample); break;
      case SFLFLOW_EX_Q_DEPTH: readExtendedQueueDepth(sample); break;
      default: skipTLVRecord(sample, tag, length, "flow_sample_element"); break;
      }
      lengthCheck(sample, "flow_sample_element", start, length);
      if(sfConfig.outputFormat == SFLFMT_JSON)
	json_end_ob();
    }
  }
  lengthCheck(sample, "flow_sample", sampleStart, sampleLength);
  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_end_ar();

  if(sampleFilterOK(sample)) {
    switch(sfConfig.outputFormat) {
    case SFLFMT_NETFLOW:
      if(sfConfig.netFlowOutputSocket) {
	/* if we are exporting netflow and we have an IPv4 layer, compose the datagram now */
	if((sample->s.gotIPV4 || sample->s.gotIPV4Struct)
	   && sendNetFlowDatagram != NULL)
	  sendNetFlowDatagram(sample);
	/* If we have an IPv6 layer, compose the datagram now */
	if((sample->s.gotIPV6 || sample->s.gotIPV6Struct)
	   && sendNetFlowDatagram_v6 != NULL)
	  sendNetFlowDatagram_v6(sample);
      }
      break;
    case SFLFMT_PCAP:
      /* if we are writing tcpdump format, write the next packet record now */
      writePcapPacket(sample);
      break;
    case SFLFMT_PCAP_DISCARD:
      break;
    case SFLFMT_LINE:
      /* or line-by-line output... */
      writeFlowLine(sample);
      break;
    case SFLFMT_LINE_CUSTOM:
      /* or custom line-by-line output... */
      writeLineCustom(sample);
      break;
    case SFLFMT_CLF:
      if(sfCLF.valid) {
	if(printf("%s %s\n", sfCLF.client, sfCLF.http_log) < 0) {
	  exit(-48);
	}
      }
      break;
    case SFLFMT_FULL:
    case SFLFMT_SCRIPT:
    case SFLFMT_JSON:
    default:
      /* if it was full-detail output then it was done as we went along */
      break;
    }
  }
  if(sfConfig.outputFormat == SFLFMT_LINE_CUSTOM) {
    /* do this here in case sampleFilter rejected sample above */
    clearLineCustom(sample, SFSCOPE_SAMPLE);
  }
}

/*_________________---------------------------__________________
  _________________   discard reason codes    __________________
  -----------------___________________________------------------
*/

#define SFL_DROP(nm,cd) { .name=#nm, .code=cd },
  static struct { char *name; int code; } sflow_codes[] = {
#include "sflow_drop.h"
  };
#undef SFL_DROP

static char *getReasonCodeName(int reasonCode) {
  int entries = sizeof(sflow_codes) / sizeof(sflow_codes[0]);
  for(int ii = 0; ii < entries; ii++) {
    if((reasonCode == sflow_codes[ii].code))
      return sflow_codes[ii].name;
  }
  return NULL;
}

/*_________________---------------------------__________________
  _________________    readDiscardSample      __________________
  -----------------___________________________------------------
*/

static void readDiscardSample(SFSample *sample)
{
  SFStr buf;
  uint32_t num_elements, sampleLength, discardCode;
  uint8_t *sampleStart;
  char *discardReason;

  sf_logf(sample, "sampleType", "DISCARD");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  sample->s.samplesGenerated = getData32(sample);
  sample->s.ds_class = getData32(sample);
  sample->s.ds_index = getData32(sample);
  sf_logf_U32(sample, "sampleSequenceNo", sample->s.samplesGenerated);
  sf_logf(sample, "sourceId", printDataSource(sample->s.ds_class, sample->s.ds_index, &buf));
  sample->s.dropEvents = getData32(sample);
  sf_logf_U32(sample, "dropEvents", sample->s.dropEvents);
  sample->s.inputPort = getData32(sample);
  sample->s.outputPort = getData32(sample);
  sf_logf(sample, "inputPort", printInOutPort(sample->s.inputPort, sample->s.inputPortFormat, &buf));
  sf_logf(sample, "outputPort", printInOutPort(sample->s.outputPort, sample->s.outputPortFormat, &buf));
  discardCode = getData32(sample);
  sf_logf_U32(sample, "discardCode", discardCode);
  discardReason = getReasonCodeName(discardCode);
  sf_logf(sample, "discardReason", discardReason ?: "NotFound");

  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_start_ar("elements");

  sf_logf_pushPrefix(sample, "discarded_");
  
  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      uint32_t tag, length;
      uint8_t *start;
      SFStr buf;
      if(sfConfig.outputFormat == SFLFMT_JSON) {
	json_start_ob(NULL);
      }
      tag = sample->s.elementType = getData32(sample);
      sf_logf(sample, "flowBlock_tag", printTag(tag, &buf));
      length = getData32(sample);
      start = (uint8_t *)sample->datap;

      // TODO: separate fn for flow-sample elements?
      switch(tag) {
      case SFLFLOW_HEADER:     readFlowSample_header(sample); break;
      case SFLFLOW_EX_FUNCTION: readExtendedFunction(sample); break;
      case SFLFLOW_EX_EGRESS_Q: readExtendedEgressQueue(sample); break;
      case SFLFLOW_EX_HW_TRAP: readExtendedHardwareTrap(sample); break;
      case SFLFLOW_EX_LINUX_REASON: readExtendedLinuxReason(sample); break;
      default: skipTLVRecord(sample, tag, length, "discard_sample_element"); break;
      }
      lengthCheck(sample, "discard_sample_element", start, length);
      if(sfConfig.outputFormat == SFLFMT_JSON)
	json_end_ob();
    }
  }

  sf_logf_popPrefix(sample);

  lengthCheck(sample, "discard_sample", sampleStart, sampleLength);
  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_end_ar();

  if(sampleFilterOK(sample)) {
    switch(sfConfig.outputFormat) {
    case SFLFMT_NETFLOW:
      break;
    case SFLFMT_PCAP:
      break;
    case SFLFMT_PCAP_DISCARD:
      /* if we are writing tcpdump format, write the next packet record now */
      writePcapPacket(sample);
      break;
    case SFLFMT_LINE:
      /* or line-by-line output... */
      /* TODO: writeDiscardLine(sample)? */
      break;
    case SFLFMT_LINE_CUSTOM:
      /* or custom line-by-line output... */
      writeLineCustom(sample);
      break;
    case SFLFMT_CLF:
    case SFLFMT_FULL:
    case SFLFMT_SCRIPT:
    case SFLFMT_JSON:
    default:
      /* if it was full-detail output then it was done as we went along */
      break;
    }
  }
  if(sfConfig.outputFormat == SFLFMT_LINE_CUSTOM) {
    /* do this here in case sampleFilter rejected sample above */
    clearLineCustom(sample, SFSCOPE_SAMPLE);
  }
}

/*_________________---------------------------__________________
  _________________  readCounters_generic     __________________
  -----------------___________________________------------------
*/

static void readCounters_generic(SFSample *sample)
{
  /* the first part of the generic counters block is really just more info about the interface. */
  sample->s.ifCounters.ifIndex = sf_log_next32(sample, "ifIndex");
  sample->s.ifCounters.ifType = sf_log_next32(sample, "networkType");
  sample->s.ifCounters.ifSpeed = sf_log_next64(sample, "ifSpeed");
  sample->s.ifCounters.ifDirection = sf_log_next32(sample, "ifDirection");
  sample->s.ifCounters.ifStatus = sf_log_next32(sample, "ifStatus");
  /* the generic counters always come first */
  sample->s.ifCounters.ifInOctets = sf_log_next64(sample, "ifInOctets");
  sample->s.ifCounters.ifInUcastPkts = sf_log_next32(sample, "ifInUcastPkts");
  sample->s.ifCounters.ifInMulticastPkts = sf_log_next32(sample, "ifInMulticastPkts");
  sample->s.ifCounters.ifInBroadcastPkts = sf_log_next32(sample, "ifInBroadcastPkts");
  sample->s.ifCounters.ifInDiscards = sf_log_next32(sample, "ifInDiscards");
  sample->s.ifCounters.ifInErrors = sf_log_next32(sample, "ifInErrors");
  sample->s.ifCounters.ifInUnknownProtos = sf_log_next32(sample, "ifInUnknownProtos");
  sample->s.ifCounters.ifOutOctets = sf_log_next64(sample, "ifOutOctets");
  sample->s.ifCounters.ifOutUcastPkts = sf_log_next32(sample, "ifOutUcastPkts");
  sample->s.ifCounters.ifOutMulticastPkts = sf_log_next32(sample, "ifOutMulticastPkts");
  sample->s.ifCounters.ifOutBroadcastPkts = sf_log_next32(sample, "ifOutBroadcastPkts");
  sample->s.ifCounters.ifOutDiscards = sf_log_next32(sample, "ifOutDiscards");
  sample->s.ifCounters.ifOutErrors = sf_log_next32(sample, "ifOutErrors");
  sample->s.ifCounters.ifPromiscuousMode = sf_log_next32(sample, "ifPromiscuousMode");
}

/*_________________---------------------------__________________
  _________________  readCounters_ethernet    __________________
  -----------------___________________________------------------
*/

static  void readCounters_ethernet(SFSample *sample)
{
  sf_log_next32(sample, "dot3StatsAlignmentErrors");
  sf_log_next32(sample, "dot3StatsFCSErrors");
  sf_log_next32(sample, "dot3StatsSingleCollisionFrames");
  sf_log_next32(sample, "dot3StatsMultipleCollisionFrames");
  sf_log_next32(sample, "dot3StatsSQETestErrors");
  sf_log_next32(sample, "dot3StatsDeferredTransmissions");
  sf_log_next32(sample, "dot3StatsLateCollisions");
  sf_log_next32(sample, "dot3StatsExcessiveCollisions");
  sf_log_next32(sample, "dot3StatsInternalMacTransmitErrors");
  sf_log_next32(sample, "dot3StatsCarrierSenseErrors");
  sf_log_next32(sample, "dot3StatsFrameTooLongs");
  sf_log_next32(sample, "dot3StatsInternalMacReceiveErrors");
  sf_log_next32(sample, "dot3StatsSymbolErrors");
}


/*_________________---------------------------__________________
  _________________  readCounters_tokenring   __________________
  -----------------___________________________------------------
*/

static void readCounters_tokenring(SFSample *sample)
{
  sf_log_next32(sample, "dot5StatsLineErrors");
  sf_log_next32(sample, "dot5StatsBurstErrors");
  sf_log_next32(sample, "dot5StatsACErrors");
  sf_log_next32(sample, "dot5StatsAbortTransErrors");
  sf_log_next32(sample, "dot5StatsInternalErrors");
  sf_log_next32(sample, "dot5StatsLostFrameErrors");
  sf_log_next32(sample, "dot5StatsReceiveCongestions");
  sf_log_next32(sample, "dot5StatsFrameCopiedErrors");
  sf_log_next32(sample, "dot5StatsTokenErrors");
  sf_log_next32(sample, "dot5StatsSoftErrors");
  sf_log_next32(sample, "dot5StatsHardErrors");
  sf_log_next32(sample, "dot5StatsSignalLoss");
  sf_log_next32(sample, "dot5StatsTransmitBeacons");
  sf_log_next32(sample, "dot5StatsRecoverys");
  sf_log_next32(sample, "dot5StatsLobeWires");
  sf_log_next32(sample, "dot5StatsRemoves");
  sf_log_next32(sample, "dot5StatsSingles");
  sf_log_next32(sample, "dot5StatsFreqErrors");
}


/*_________________---------------------------__________________
  _________________  readCounters_vg          __________________
  -----------------___________________________------------------
*/

static void readCounters_vg(SFSample *sample)
{
  sf_log_next32(sample, "dot12InHighPriorityFrames");
  sf_log_next64(sample, "dot12InHighPriorityOctets");
  sf_log_next32(sample, "dot12InNormPriorityFrames");
  sf_log_next64(sample, "dot12InNormPriorityOctets");
  sf_log_next32(sample, "dot12InIPMErrors");
  sf_log_next32(sample, "dot12InOversizeFrameErrors");
  sf_log_next32(sample, "dot12InDataErrors");
  sf_log_next32(sample, "dot12InNullAddressedFrames");
  sf_log_next32(sample, "dot12OutHighPriorityFrames");
  sf_log_next64(sample, "dot12OutHighPriorityOctets");
  sf_log_next32(sample, "dot12TransitionIntoTrainings");
  sf_log_next64(sample, "dot12HCInHighPriorityOctets");
  sf_log_next64(sample, "dot12HCInNormPriorityOctets");
  sf_log_next64(sample, "dot12HCOutHighPriorityOctets");
}



/*_________________---------------------------__________________
  _________________  readCounters_vlan        __________________
  -----------------___________________________------------------
*/

static void readCounters_vlan(SFSample *sample)
{
  sample->s.in_vlan = getData32(sample);
  sf_logf_U32(sample, "in_vlan", sample->s.in_vlan);
  sf_log_next64(sample, "octets");
  sf_log_next32(sample, "ucastPkts");
  sf_log_next32(sample, "multicastPkts");
  sf_log_next32(sample, "broadcastPkts");
  sf_log_next32(sample, "discards");
}

/*_________________---------------------------__________________
  _________________  readCounters_80211       __________________
  -----------------___________________________------------------
*/

static void readCounters_80211(SFSample *sample)
{
  sf_log_next32(sample, "dot11TransmittedFragmentCount");
  sf_log_next32(sample, "dot11MulticastTransmittedFrameCount");
  sf_log_next32(sample, "dot11FailedCount");
  sf_log_next32(sample, "dot11RetryCount");
  sf_log_next32(sample, "dot11MultipleRetryCount");
  sf_log_next32(sample, "dot11FrameDuplicateCount");
  sf_log_next32(sample, "dot11RTSSuccessCount");
  sf_log_next32(sample, "dot11RTSFailureCount");
  sf_log_next32(sample, "dot11ACKFailureCount");
  sf_log_next32(sample, "dot11ReceivedFragmentCount");
  sf_log_next32(sample, "dot11MulticastReceivedFrameCount");
  sf_log_next32(sample, "dot11FCSErrorCount");
  sf_log_next32(sample, "dot11TransmittedFrameCount");
  sf_log_next32(sample, "dot11WEPUndecryptableCount");
  sf_log_next32(sample, "dot11QoSDiscardedFragmentCount");
  sf_log_next32(sample, "dot11AssociatedStationCount");
  sf_log_next32(sample, "dot11QoSCFPollsReceivedCount");
  sf_log_next32(sample, "dot11QoSCFPollsUnusedCount");
  sf_log_next32(sample, "dot11QoSCFPollsUnusableCount");
  sf_log_next32(sample, "dot11QoSCFPollsLostCount");
}

/*_________________---------------------------__________________
  _________________  readCounters_processor   __________________
  -----------------___________________________------------------
*/

static void readCounters_processor(SFSample *sample)
{
  sf_log_percentage(sample, "5s_cpu");
  sf_log_percentage(sample, "1m_cpu");
  sf_log_percentage(sample, "5m_cpu");
  sf_log_next64(sample, "total_memory_bytes");
  sf_log_next64(sample, "free_memory_bytes");
}

/*_________________---------------------------__________________
  _________________  readCounters_radio       __________________
  -----------------___________________________------------------
*/

static void readCounters_radio(SFSample *sample)
{
  sf_log_next32(sample, "radio_elapsed_time");
  sf_log_next32(sample, "radio_on_channel_time");
  sf_log_next32(sample, "radio_on_channel_busy_time");
}

/*_________________---------------------------__________________
  _________________  readCounters_OFPort      __________________
  -----------------___________________________------------------
*/

static void readCounters_OFPort(SFSample *sample)
{
  uint64_t dpid = getData64(sample);
  char buf[64];
  snprintf(buf, 64, "%016"PRIx64"", dpid);
  sf_logf(sample,  "openflow_datapath_id", buf);
  sf_log_next32(sample, "openflow_port");
}

/*_________________---------------------------__________________
  _________________  readCounters_portName    __________________
  -----------------___________________________------------------
*/

static void readCounters_portName(SFSample *sample)
{
  char ifname[SFL_MAX_PORTNAME_LEN+1];
  if(getString(sample, ifname, SFL_MAX_PORTNAME_LEN) > 0) {
    sf_logf(sample, "ifName", ifname);
  }
}

/*_________________---------------------------__________________
  _________________  readCounters_OVSDP       __________________
  -----------------___________________________------------------
*/

static void readCounters_OVSDP(SFSample *sample)
{
  sf_log_next32(sample, "OVS_dp_hits");
  sf_log_next32(sample, "OVS_dp_misses");
  sf_log_next32(sample, "OVS_dp_lost");
  sf_log_next32(sample, "OVS_dp_mask_hits");
  sf_log_next32(sample, "OVS_dp_flows");
  sf_log_next32(sample, "OVS_dp_masks");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_hid    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_hid(SFSample *sample)
{
  uint32_t i;
  uint8_t *uuid;
  char hostname[SFL_MAX_HOSTNAME_LEN+1];
  char os_release[SFL_MAX_OSRELEASE_LEN+1];
  if(getString(sample, hostname, SFL_MAX_HOSTNAME_LEN) > 0) {
    sf_logf(sample, "hostname", hostname);
  }
  SFStr uuidstr;
  SFStr_init(&uuidstr);
  uuid = (uint8_t *)sample->datap;
  SFStr_append_UUID(&uuidstr, uuid);
  sf_logf(sample, "UUID", SFStr_str(&uuidstr));
  skipBytes(sample, 16);
  sf_log_next32(sample, "machine_type");
  sf_log_next32(sample, "os_name");
  if(getString(sample, os_release, SFL_MAX_OSRELEASE_LEN) > 0) {
    sf_logf(sample, "os_release", os_release);
  }
}

/*_________________---------------------------__________________
  _________________  readCounters_adaptors    __________________
  -----------------___________________________------------------
*/

static void readCounters_adaptors(SFSample *sample)
{
  uint8_t *mac;
  uint32_t i, j, ifindex, num_macs, num_adaptors = getData32(sample);
  if(sfConfig.outputFormat == SFLFMT_JSON) {
    /* JSON - print as array of adaptors with nested arrays of MACs */
    json_start_ar("adaptor_list");
    for(i = 0; i < num_adaptors; i++) {
      ifindex = getData32(sample);
      json_start_ob(NULL);
      sf_logf_U32(sample, "ifIndex", ifindex);
      num_macs = getData32(sample);
      sf_logf_U32(sample, "MACs", num_macs);
      json_start_ar("mac_list");
      for(j = 0; j < num_macs; j++) {
	if(j > 0)
	  printf(",");
	mac = (uint8_t *)sample->datap;
	skipBytes(sample, 8);
	SFStr macstr;
	SFStr_init(&macstr);
	SFStr_append_mac(&macstr, mac);
	json_indent();
	printf("\"%s\" ", SFStr_str(&macstr));
      }
      json_end_ar(); /* end mac_list */
      json_end_ob(); /* end adaptor */
    }
    json_end_ar(); /* end adaptor_list */
  }
  else {
    /* print as flat list of fields, with adaptor and mac index numbers */
    for(i = 0; i < num_adaptors; i++) {
      ifindex = getData32(sample);
      char prefix[64];
      snprintf(prefix, 64, "adaptor_%u_", i);
      sf_logf_U32_formatted(sample, prefix, "ifIndex", "%u", ifindex);
      num_macs = getData32(sample);
      sf_logf_U32_formatted(sample, prefix, "MACs", "%u", num_macs);
      for(j = 0; j < num_macs; j++) {
	mac = (uint8_t *)sample->datap;
	skipBytes(sample, 8);
	SFStr macstr;
	SFStr_init(&macstr);
	SFStr_append_mac(&macstr, mac);
	char fieldName[64];
	snprintf(fieldName, 64, "MAC_%u", j);
	sf_logf_pushPrefix(sample, prefix);
	sf_logf(sample, fieldName, SFStr_str(&macstr));
	sf_logf_popPrefix(sample);
      }
    }
  }
}

/*_________________----------------------------__________________
  _________________  readCounters_host_parent  __________________
  -----------------____________________________------------------
*/

static void readCounters_host_parent(SFSample *sample)
{
  sf_log_next32(sample, "parent_dsClass");
  sf_log_next32(sample, "parent_dsIndex");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_cpu    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_cpu(SFSample *sample, uint32_t length)
{
  sf_log_nextFloat(sample, "cpu_load_one");
  sf_log_nextFloat(sample, "cpu_load_five");
  sf_log_nextFloat(sample, "cpu_load_fifteen");
  sf_log_next32(sample, "cpu_proc_run");
  sf_log_next32(sample, "cpu_proc_total");
  sf_log_next32(sample, "cpu_num");
  sf_log_next32(sample, "cpu_speed");
  sf_log_next32(sample, "cpu_uptime");
  sf_log_next32(sample, "cpu_user");
  sf_log_next32(sample, "cpu_nice");
  sf_log_next32(sample, "cpu_system");
  sf_log_next32(sample, "cpu_idle");
  sf_log_next32(sample, "cpu_wio");
  sf_log_next32(sample, "cpuintr");
  sf_log_next32(sample, "cpu_sintr");
  sf_log_next32(sample, "cpuinterrupts");
  sf_log_next32(sample, "cpu_contexts");
  if(length > 68) {
    /* these three fields were added in December 2014 */
    sf_log_next32(sample, "cpu_steal");
    sf_log_next32(sample, "cpu_guest");
    sf_log_next32(sample, "cpu_guest_nice");
  }
}

/*_________________---------------------------__________________
  _________________  readCounters_host_mem    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_mem(SFSample *sample)
{
  sf_log_next64(sample, "mem_total");
  sf_log_next64(sample, "mem_free");
  sf_log_next64(sample, "mem_shared");
  sf_log_next64(sample, "mem_buffers");
  sf_log_next64(sample, "mem_cached");
  sf_log_next64(sample, "swap_total");
  sf_log_next64(sample, "swap_free");
  sf_log_next32(sample, "page_in");
  sf_log_next32(sample, "page_out");
  sf_log_next32(sample, "swap_in");
  sf_log_next32(sample, "swap_out");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_dsk    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_dsk(SFSample *sample)
{
  sf_log_next64(sample, "disk_total");
  sf_log_next64(sample, "disk_free");
  sf_log_percentage(sample, "disk_partition_max_used");
  sf_log_next32(sample, "disk_reads");
  sf_log_next64(sample, "disk_bytes_read");
  sf_log_next32(sample, "disk_read_time");
  sf_log_next32(sample, "disk_writes");
  sf_log_next64(sample, "disk_bytes_written");
  sf_log_next32(sample, "disk_write_time");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_nio    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_nio(SFSample *sample)
{
  sf_log_next64(sample, "nio_bytes_in");
  sf_log_next32(sample, "nio_pkts_in");
  sf_log_next32(sample, "nio_errs_in");
  sf_log_next32(sample, "nio_drops_in");
  sf_log_next64(sample, "nio_bytes_out");
  sf_log_next32(sample, "nio_pkts_out");
  sf_log_next32(sample, "nio_errs_out");
  sf_log_next32(sample, "nio_drops_out");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_ip     __________________
  -----------------___________________________------------------
*/

static void readCounters_host_ip(SFSample *sample)
{
  sf_log_next32(sample, "ipForwarding");
  sf_log_next32(sample, "ipDefaultTTL");
  sf_log_next32(sample, "ipInReceives");
  sf_log_next32(sample, "ipInHdrErrors");
  sf_log_next32(sample, "ipInAddrErrors");
  sf_log_next32(sample, "ipForwDatagrams");
  sf_log_next32(sample, "ipInUnknownProtos");
  sf_log_next32(sample, "ipInDiscards");
  sf_log_next32(sample, "ipInDelivers");
  sf_log_next32(sample, "ipOutRequests");
  sf_log_next32(sample, "ipOutDiscards");
  sf_log_next32(sample, "ipOutNoRoutes");
  sf_log_next32(sample, "ipReasmTimeout");
  sf_log_next32(sample, "ipReasmReqds");
  sf_log_next32(sample, "ipReasmOKs");
  sf_log_next32(sample, "ipReasmFails");
  sf_log_next32(sample, "ipFragOKs");
  sf_log_next32(sample, "ipFragFails");
  sf_log_next32(sample, "ipFragCreates");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_icmp   __________________
  -----------------___________________________------------------
*/

static void readCounters_host_icmp(SFSample *sample)
{
  sf_log_next32(sample, "icmpInMsgs");
  sf_log_next32(sample, "icmpInErrors");
  sf_log_next32(sample, "icmpInDestUnreachs");
  sf_log_next32(sample, "icmpInTimeExcds");
  sf_log_next32(sample, "icmpInParamProbs");
  sf_log_next32(sample, "icmpInSrcQuenchs");
  sf_log_next32(sample, "icmpInRedirects");
  sf_log_next32(sample, "icmpInEchos");
  sf_log_next32(sample, "icmpInEchoReps");
  sf_log_next32(sample, "icmpInTimestamps");
  sf_log_next32(sample, "icmpInAddrMasks");
  sf_log_next32(sample, "icmpInAddrMaskReps");
  sf_log_next32(sample, "icmpOutMsgs");
  sf_log_next32(sample, "icmpOutErrors");
  sf_log_next32(sample, "icmpOutDestUnreachs");
  sf_log_next32(sample, "icmpOutTimeExcds");
  sf_log_next32(sample, "icmpOutParamProbs");
  sf_log_next32(sample, "icmpOutSrcQuenchs");
  sf_log_next32(sample, "icmpOutRedirects");
  sf_log_next32(sample, "icmpOutEchos");
  sf_log_next32(sample, "icmpOutEchoReps");
  sf_log_next32(sample, "icmpOutTimestamps");
  sf_log_next32(sample, "icmpOutTimestampReps");
  sf_log_next32(sample, "icmpOutAddrMasks");
  sf_log_next32(sample, "icmpOutAddrMaskReps");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_tcp     __________________
  -----------------___________________________------------------
*/

static void readCounters_host_tcp(SFSample *sample)
{
  sf_log_next32(sample, "tcpRtoAlgorithm");
  sf_log_next32(sample, "tcpRtoMin");
  sf_log_next32(sample, "tcpRtoMax");
  sf_log_next32(sample, "tcpMaxConn");
  sf_log_next32(sample, "tcpActiveOpens");
  sf_log_next32(sample, "tcpPassiveOpens");
  sf_log_next32(sample, "tcpAttemptFails");
  sf_log_next32(sample, "tcpEstabResets");
  sf_log_next32(sample, "tcpCurrEstab");
  sf_log_next32(sample, "tcpInSegs");
  sf_log_next32(sample, "tcpOutSegs");
  sf_log_next32(sample, "tcpRetransSegs");
  sf_log_next32(sample, "tcpInErrs");
  sf_log_next32(sample, "tcpOutRsts");
  sf_log_next32(sample, "tcpInCsumErrors");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_udp    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_udp(SFSample *sample)
{
  sf_log_next32(sample, "udpInDatagrams");
  sf_log_next32(sample, "udpNoPorts");
  sf_log_next32(sample, "udpInErrors");
  sf_log_next32(sample, "udpOutDatagrams");
  sf_log_next32(sample, "udpRcvbufErrors");
  sf_log_next32(sample, "udpSndbufErrors");
  sf_log_next32(sample, "udpInCsumErrors");
}

/*_________________-----------------------------__________________
  _________________  readCounters_host_vnode    __________________
  -----------------_____________________________------------------
*/

static void readCounters_host_vnode(SFSample *sample)
{
  sf_log_next32(sample, "vnode_mhz");
  sf_log_next32(sample, "vnode_cpus");
  sf_log_next64(sample, "vnode_memory");
  sf_log_next64(sample, "vnode_memory_free");
  sf_log_next32(sample, "vnode_num_domains");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vcpu    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vcpu(SFSample *sample)
{
  sf_log_next32(sample, "vcpu_state");
  sf_log_next32(sample, "vcpu_cpu_mS");
  sf_log_next32(sample, "vcpu_cpuCount");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vmem    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vmem(SFSample *sample)
{
  sf_log_next64(sample, "vmem_memory");
  sf_log_next64(sample, "vmem_maxMemory");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vdsk    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vdsk(SFSample *sample)
{
  sf_log_next64(sample, "vdsk_capacity");
  sf_log_next64(sample, "vdsk_allocation");
  sf_log_next64(sample, "vdsk_available");
  sf_log_next32(sample, "vdsk_rd_req");
  sf_log_next64(sample, "vdsk_rd_bytes");
  sf_log_next32(sample, "vdsk_wr_req");
  sf_log_next64(sample, "vdsk_wr_bytes");
  sf_log_next32(sample, "vdsk_errs");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vnio    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vnio(SFSample *sample)
{
  sf_log_next64(sample, "vnio_bytes_in");
  sf_log_next32(sample, "vnio_pkts_in");
  sf_log_next32(sample, "vnio_errs_in");
  sf_log_next32(sample, "vnio_drops_in");
  sf_log_next64(sample, "vnio_bytes_out");
  sf_log_next32(sample, "vnio_pkts_out");
  sf_log_next32(sample, "vnio_errs_out");
  sf_log_next32(sample, "vnio_drops_out");
}

/*_________________------------------------------__________________
  _________________  readCounters_host_gpu_nvml  __________________
  -----------------______________________________------------------
*/

static void readCounters_host_gpu_nvml(SFSample *sample)
{
  sf_log_next32(sample, "nvml_device_count");
  sf_log_next32(sample, "nvml_processes");
  sf_log_next32(sample, "nvml_gpu_mS");
  sf_log_next32(sample, "nvml_mem_mS");
  sf_log_next64(sample, "nvml_mem_bytes_total");
  sf_log_next64(sample, "nvml_mem_bytes_free");
  sf_log_next32(sample, "nvml_ecc_errors");
  sf_log_next32(sample, "nvml_energy_mJ");
  sf_log_next32(sample, "nvml_temperature_C");
  sf_log_next32(sample, "nvml_fan_speed_pc");
}

/*_________________------------------------------__________________
  _________________  readCounters_bcm_tables     __________________
  -----------------______________________________------------------
*/

static void readCounters_bcm_tables(SFSample *sample)
{
  sf_log_next32(sample, "bcm_asic_host_entries");
  sf_log_next32(sample, "bcm_host_entries_max");
  sf_log_next32(sample, "bcm_ipv4_entries");
  sf_log_next32(sample, "bcm_ipv4_entries_max");
  sf_log_next32(sample, "bcm_ipv6_entries");
  sf_log_next32(sample, "bcm_ipv6_entries_max");
  sf_log_next32(sample, "bcm_ipv4_ipv6_entries");
  sf_log_next32(sample, "bcm_ipv4_ipv6_entries_max");
  sf_log_next32(sample, "bcm_long_ipv6_entries");
  sf_log_next32(sample, "bcm_long_ipv6_entries_max");
  sf_log_next32(sample, "bcm_total_routes");
  sf_log_next32(sample, "bcm_total_routes_max");
  sf_log_next32(sample, "bcm_ecmp_nexthops");
  sf_log_next32(sample, "bcm_ecmp_nexthops_max");
  sf_log_next32(sample, "bcm_mac_entries");
  sf_log_next32(sample, "bcm_mac_entries_max");
  sf_log_next32(sample, "bcm_ipv4_neighbors");
  sf_log_next32(sample, "bcm_ipv6_neighbors");
  sf_log_next32(sample, "bcm_ipv4_routes");
  sf_log_next32(sample, "bcm_ipv6_routes");
  sf_log_next32(sample, "bcm_acl_ingress_entries");
  sf_log_next32(sample, "bcm_acl_ingress_entries_max");
  sf_log_next32(sample, "bcm_acl_ingress_counters");
  sf_log_next32(sample, "bcm_acl_ingress_counters_max");
  sf_log_next32(sample, "bcm_acl_ingress_meters");
  sf_log_next32(sample, "bcm_acl_ingress_meters_max");
  sf_log_next32(sample, "bcm_acl_ingress_slices");
  sf_log_next32(sample, "bcm_acl_ingress_slices_max");
  sf_log_next32(sample, "bcm_acl_egress_entries");
  sf_log_next32(sample, "bcm_acl_egress_entries_max");
  sf_log_next32(sample, "bcm_acl_egress_counters");
  sf_log_next32(sample, "bcm_acl_egress_counters_max");
  sf_log_next32(sample, "bcm_acl_egress_meters");
  sf_log_next32(sample, "bcm_acl_egress_meters_max");
  sf_log_next32(sample, "bcm_acl_egress_slices");
  sf_log_next32(sample, "bcm_acl_egress_slices_max");
}

/*_________________----------------------------__________________
  _________________  readCounters_memcache     __________________
  -----------------____________________________------------------
 for structure 2200 (deprecated)
*/

static void readCounters_memcache(SFSample *sample)
{
  sf_log_next32(sample, "memcache_uptime");
  sf_log_next32(sample, "memcache_rusage_user");
  sf_log_next32(sample, "memcache_rusage_system");
  sf_log_next32(sample, "memcache_curr_connections");
  sf_log_next32(sample, "memcache_total_connections");
  sf_log_next32(sample, "memcache_connection_structures");
  sf_log_next32(sample, "memcache_cmd_get");
  sf_log_next32(sample, "memcache_cmd_set");
  sf_log_next32(sample, "memcache_cmd_flush");
  sf_log_next32(sample, "memcache_get_hits");
  sf_log_next32(sample, "memcache_get_misses");
  sf_log_next32(sample, "memcache_delete_misses");
  sf_log_next32(sample, "memcache_delete_hits");
  sf_log_next32(sample, "memcache_incr_misses");
  sf_log_next32(sample, "memcache_incr_hits");
  sf_log_next32(sample, "memcache_decr_misses");
  sf_log_next32(sample, "memcache_decr_hits");
  sf_log_next32(sample, "memcache_cas_misses");
  sf_log_next32(sample, "memcache_cas_hits");
  sf_log_next32(sample, "memcache_cas_badval");
  sf_log_next32(sample, "memcache_auth_cmds");
  sf_log_next32(sample, "memcache_auth_errors");
  sf_log_next64(sample, "memcache_bytes_read");
  sf_log_next64(sample, "memcache_bytes_written");
  sf_log_next32(sample, "memcache_limit_maxbytes");
  sf_log_next32(sample, "memcache_accepting_conns");
  sf_log_next32(sample, "memcache_listen_disabled_num");
  sf_log_next32(sample, "memcache_threads");
  sf_log_next32(sample, "memcache_conn_yields");
  sf_log_next64(sample, "memcache_bytes");
  sf_log_next32(sample, "memcache_curr_items");
  sf_log_next32(sample, "memcache_total_items");
  sf_log_next32(sample, "memcache_evictions");
}

/*_________________----------------------------__________________
  _________________  readCounters_memcache2    __________________
  -----------------____________________________------------------
  for structure 2204
*/

static void readCounters_memcache2(SFSample *sample)
{
  sf_log_next32(sample, "memcache_cmd_set");
  sf_log_next32(sample, "memcache_cmd_touch");
  sf_log_next32(sample, "memcache_cmd_flush");
  sf_log_next32(sample, "memcache_get_hits");
  sf_log_next32(sample, "memcache_get_misses");
  sf_log_next32(sample, "memcache_delete_hits");
  sf_log_next32(sample, "memcache_delete_misses");
  sf_log_next32(sample, "memcache_incr_hits");
  sf_log_next32(sample, "memcache_incr_misses");
  sf_log_next32(sample, "memcache_decr_hits");
  sf_log_next32(sample, "memcache_decr_misses");
  sf_log_next32(sample, "memcache_cas_hits");
  sf_log_next32(sample, "memcache_cas_misses");
  sf_log_next32(sample, "memcache_cas_badval");
  sf_log_next32(sample, "memcache_auth_cmds");
  sf_log_next32(sample, "memcache_auth_errors");
  sf_log_next32(sample, "memcache_threads");
  sf_log_next32(sample, "memcache_conn_yields");
  sf_log_next32(sample, "memcache_listen_disabled_num");
  sf_log_next32(sample, "memcache_curr_connections");
  sf_log_next32(sample, "memcache_rejected_connections");
  sf_log_next32(sample, "memcache_total_connections");
  sf_log_next32(sample, "memcache_connection_structures");
  sf_log_next32(sample, "memcache_evictions");
  sf_log_next32(sample, "memcache_reclaimed");
  sf_log_next32(sample, "memcache_curr_items");
  sf_log_next32(sample, "memcache_total_items");
  sf_log_next64(sample, "memcache_bytes_read");
  sf_log_next64(sample, "memcache_bytes_written");
  sf_log_next64(sample, "memcache_bytes");
  sf_log_next64(sample, "memcache_limit_maxbytes");
}

/*_________________----------------------------__________________
  _________________  readCounters_http         __________________
  -----------------____________________________------------------
*/

static void readCounters_http(SFSample *sample)
{
  sf_log_next32(sample, "http_method_option_count");
  sf_log_next32(sample, "http_method_get_count");
  sf_log_next32(sample, "http_method_head_count");
  sf_log_next32(sample, "http_method_post_count");
  sf_log_next32(sample, "http_method_put_count");
  sf_log_next32(sample, "http_method_delete_count");
  sf_log_next32(sample, "http_method_trace_count");
  sf_log_next32(sample, "http_methd_connect_count");
  sf_log_next32(sample, "http_method_other_count");
  sf_log_next32(sample, "http_status_1XX_count");
  sf_log_next32(sample, "http_status_2XX_count");
  sf_log_next32(sample, "http_status_3XX_count");
  sf_log_next32(sample, "http_status_4XX_count");
  sf_log_next32(sample, "http_status_5XX_count");
  sf_log_next32(sample, "http_status_other_count");
}

/*_________________----------------------------__________________
  _________________  readCounters_JVM          __________________
  -----------------____________________________------------------
*/

static void readCounters_JVM(SFSample *sample)
{
  char vm_name[SFLJVM_MAX_VMNAME_LEN];
  char vendor[SFLJVM_MAX_VENDOR_LEN];
  char version[SFLJVM_MAX_VERSION_LEN];
  if(getString(sample, vm_name, SFLJVM_MAX_VMNAME_LEN) > 0) {
    sf_logf(sample, "jvm_name", vm_name);
  }
  if(getString(sample, vendor, SFLJVM_MAX_VENDOR_LEN) > 0) {
    sf_logf(sample, "jvm_vendor", vendor);
  }
  if(getString(sample, version, SFLJVM_MAX_VERSION_LEN) > 0) {
    sf_logf(sample, "jvm_version", version);
  }
}

/*_________________----------------------------__________________
  _________________  readCounters_JMX          __________________
  -----------------____________________________------------------
*/

static void readCounters_JMX(SFSample *sample, uint32_t length)
{
  sf_log_next64(sample, "heap_mem_initial");
  sf_log_next64(sample, "heap_mem_used");
  sf_log_next64(sample, "heap_mem_committed");
  sf_log_next64(sample, "heap_mem_max");
  sf_log_next64(sample, "non_heap_mem_initial");
  sf_log_next64(sample, "non_heap_mem_used");
  sf_log_next64(sample, "non_heap_mem_committed");
  sf_log_next64(sample, "non_heap_mem_max");
  sf_log_next32(sample, "gc_count");
  sf_log_next32(sample, "gc_mS");
  sf_log_next32(sample, "classes_loaded");
  sf_log_next32(sample, "classes_total");
  sf_log_next32(sample, "classes_unloaded");
  sf_log_next32(sample, "compilation_mS");
  sf_log_next32(sample, "threads_live");
  sf_log_next32(sample, "threads_daemon");
  sf_log_next32(sample, "threads_started");
  if(length > 100) {
    sf_log_next32(sample, "fds_open");
    sf_log_next32(sample, "fds_max");
  }
}

/*_________________----------------------------__________________
  _________________  readCounters_APP          __________________
  -----------------____________________________------------------
*/

static void readCounters_APP(SFSample *sample)
{
  char application[SFLAPP_MAX_APPLICATION_LEN];
  if(getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
    sf_logf(sample, "application", application);
  }
  sf_log_next32(sample, "status_OK");
  sf_log_next32(sample, "errors_OTHER");
  sf_log_next32(sample, "errors_TIMEOUT");
  sf_log_next32(sample, "errors_INTERNAL_ERROR");
  sf_log_next32(sample, "errors_BAD_REQUEST");
  sf_log_next32(sample, "errors_FORBIDDEN");
  sf_log_next32(sample, "errors_TOO_LARGE");
  sf_log_next32(sample, "errors_NOT_IMPLEMENTED");
  sf_log_next32(sample, "errors_NOT_FOUND");
  sf_log_next32(sample, "errors_UNAVAILABLE");
  sf_log_next32(sample, "errors_UNAUTHORIZED");
}

/*_________________----------------------------__________________
  _________________  readCounters_APP_RESOURCE __________________
  -----------------____________________________------------------
*/

static void readCounters_APP_RESOURCE(SFSample *sample)
{
  sf_log_next32(sample, "user_time");
  sf_log_next32(sample, "system_time");
  sf_log_next64(sample, "memory_used");
  sf_log_next64(sample, "memory_max");
  sf_log_next32(sample, "files_open");
  sf_log_next32(sample, "files_max");
  sf_log_next32(sample, "connections_open");
  sf_log_next32(sample, "connections_max");
}

/*_________________----------------------------__________________
  _________________  readCounters_APP_WORKERS  __________________
  -----------------____________________________------------------
*/

static void readCounters_APP_WORKERS(SFSample *sample)
{
  sf_log_next32(sample, "workers_active");
  sf_log_next32(sample, "workers_idle");
  sf_log_next32(sample, "workers_max");
  sf_log_next32(sample, "requests_delayed");
  sf_log_next32(sample, "requests_dropped");
}

/*_________________----------------------------__________________
  _________________       readCounters_VDI     __________________
  -----------------____________________________------------------
*/

static void readCounters_VDI(SFSample *sample)
{
  sf_log_next32(sample, "vdi_sessions_current");
  sf_log_next32(sample, "vdi_sessions_total");
  sf_log_next32(sample, "vdi_sessions_duration");
  sf_log_next32(sample, "vdi_rx_bytes");
  sf_log_next32(sample, "vdi_tx_bytes");
  sf_log_next32(sample, "vdi_rx_packets");
  sf_log_next32(sample, "vdi_tx_packets");
  sf_log_next32(sample, "vdi_rx_packets_lost");
  sf_log_next32(sample, "vdi_tx_packets_lost");
  sf_log_next32(sample, "vdi_rtt_min_ms");
  sf_log_next32(sample, "vdi_rtt_max_ms");
  sf_log_next32(sample, "vdi_rtt_avg_ms");
  sf_log_next32(sample, "vdi_audio_rx_bytes");
  sf_log_next32(sample, "vdi_audio_tx_bytes");
  sf_log_next32(sample, "vdi_audio_tx_limit");
  sf_log_next32(sample, "vdi_img_rx_bytes");
  sf_log_next32(sample, "vdi_img_tx_bytes");
  sf_log_next32(sample, "vdi_img_frames");
  sf_log_next32(sample, "vdi_img_qual_min");
  sf_log_next32(sample, "vdi_img_qual_max");
  sf_log_next32(sample, "vdi_img_qual_avg");
  sf_log_next32(sample, "vdi_usb_rx_bytes");
  sf_log_next32(sample, "vdi_usb_tx_bytes");
}

/*_________________------------------------------__________________
  _________________     readCounters_LACP        __________________
  -----------------______________________________------------------
*/

static void readCounters_LACP(SFSample *sample)
{
  SFLLACP_portState portState;
  sf_log_nextMAC(sample, "actorSystemID");
  sf_log_nextMAC(sample, "partnerSystemID");
  sf_log_next32(sample, "attachedAggID");
  portState.all = getData32_nobswap(sample);
  sf_logf_U32(sample, "actorAdminPortState", portState.v.actorAdmin);
  sf_logf_U32(sample, "actorOperPortState", portState.v.actorOper);
  sf_logf_U32(sample, "partnerAdminPortState", portState.v.partnerAdmin);
  sf_logf_U32(sample, "partnerOperPortState", portState.v.partnerOper);
  sf_log_next32(sample, "LACPDUsRx");
  sf_log_next32(sample, "markerPDUsRx");
  sf_log_next32(sample, "markerResponsePDUsRx");
  sf_log_next32(sample, "unknownRx");
  sf_log_next32(sample, "illegalRx");
  sf_log_next32(sample, "LACPDUsTx");
  sf_log_next32(sample, "markerPDUsTx");
  sf_log_next32(sample, "markerResponsePDUsTx");
}

/*_________________----------------------------__________________
  _________________  readCounters_SFP          __________________
  -----------------____________________________------------------
*/

static void sf_logf_SFP(SFSample *sample, char *field, uint32_t lane, uint32_t val32)
{
  if(sfConfig.outputFormat == SFLFMT_JSON) {
    sf_logf_U32(sample, field, val32);
  }
  char fieldName[64];
  snprintf(fieldName, 64, "%s.%u", field, lane);
  sf_logf_U32_formatted(sample, "sfp_lane_", fieldName, "%u", val32);
}

static void readCounters_SFP(SFSample *sample)
{
  uint32_t num_lanes,ll;
  sf_log_next32(sample, "sfp_module_id");
  sf_log_next32(sample, "sfp_module_total_lanes");
  sf_log_next32(sample, "sfp_module_supply_voltage");
  sf_log_next32(sample, "sfp_module_temperature");
  num_lanes = getData32(sample);
  sf_logf_U32(sample, "sfp_module_active_lanes", num_lanes);

  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_start_ar("sfp_lanes");

  for(ll=0; ll < num_lanes; ll++) {

    if(sfConfig.outputFormat == SFLFMT_JSON) {
      json_start_ob(NULL);
    }
    sf_logf_SFP(sample, "index", ll, getData32(sample));
    sf_logf_SFP(sample, "tx_bias_current_uA", ll, getData32(sample));
    sf_logf_SFP(sample, "tx_power_uW.%u", ll, getData32(sample));
    sf_logf_SFP(sample, "tx_power_min_uW.%u", ll, getData32(sample));
    sf_logf_SFP(sample, "tx_power_max_uW.%u", ll, getData32(sample));
    sf_logf_SFP(sample, "tx_wavelength_nM.%u", ll, getData32(sample));
    sf_logf_SFP(sample, "rx_power_uW.%u", ll, getData32(sample));
    sf_logf_SFP(sample, "rx_power_min_uW.%u", ll, getData32(sample));
    sf_logf_SFP(sample, "rx_power_max_uW.%u", ll, getData32(sample));
    sf_logf_SFP(sample, "rx_wavelength_nM.%u", ll, getData32(sample));
    if(sfConfig.outputFormat == SFLFMT_JSON)
      json_end_ob();
  }

  if(ll > 0 && sfConfig.outputFormat == SFLFMT_JSON)
    json_end_ar();
}

/*_________________---------------------------__________________
  _________________  readCountersSample_v2v4  __________________
  -----------------___________________________------------------
*/

static void readCountersSample_v2v4(SFSample *sample)
{
  SFStr buf;
  sf_logf(sample, "sampleType", "COUNTERSSAMPLE");
  sample->s.samplesGenerated = getData32(sample);
  sf_logf_U32(sample, "sampleSequenceNo", sample->s.samplesGenerated);
  {
    uint32_t samplerId = getData32(sample);
    sample->s.ds_class = samplerId >> 24;
    sample->s.ds_index = samplerId & 0x00ffffff;
  }
  sf_logf(sample, "sourceId", printDataSource(sample->s.ds_class, sample->s.ds_index, &buf));

  sample->s.statsSamplingInterval = getData32(sample);
  sf_logf_U32(sample, "statsSamplingInterval", sample->s.statsSamplingInterval);
  /* now find out what sort of counter blocks we have here... */
  sample->s.counterBlockVersion = getData32(sample);
  sf_logf_U32(sample, "counterBlockVersion", sample->s.counterBlockVersion);

  if(sfConfig.outputFormat == SFLFMT_JSON) {
    json_start_ar("elements");
    json_start_ob(NULL);
  }

  /* first see if we should read the generic stats */
  switch(sample->s.counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC:
  case INMCOUNTERSVERSION_ETHERNET:
  case INMCOUNTERSVERSION_TOKENRING:
  case INMCOUNTERSVERSION_FDDI:
  case INMCOUNTERSVERSION_VG:
  case INMCOUNTERSVERSION_WAN: readCounters_generic(sample); break;
  case INMCOUNTERSVERSION_VLAN: break;
  default: receiveError(sample, "unknown stats version", YES); break;
  }

  if(sfConfig.outputFormat == SFLFMT_JSON) {
    json_end_ob();
    json_start_ob(NULL);
  }

  /* now see if there are any specific counter blocks to add */
  switch(sample->s.counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC: /* nothing more */ break;
  case INMCOUNTERSVERSION_ETHERNET: readCounters_ethernet(sample); break;
  case INMCOUNTERSVERSION_TOKENRING: readCounters_tokenring(sample); break;
  case INMCOUNTERSVERSION_FDDI: break;
  case INMCOUNTERSVERSION_VG: readCounters_vg(sample); break;
  case INMCOUNTERSVERSION_WAN: break;
  case INMCOUNTERSVERSION_VLAN: readCounters_vlan(sample); break;
  default: receiveError(sample, "unknown INMCOUNTERSVERSION", YES); break;
  }

  switch(sfConfig.outputFormat) {
  case SFLFMT_JSON:
    json_end_ob();
    json_end_ar();
    break;
  case SFLFMT_LINE:
    writeCountersLine(sample);
    break;
  case SFLFMT_LINE_CUSTOM:
    writeLineCustom(sample);
    clearLineCustom(sample, SFSCOPE_SAMPLE);
    break;
  default:
    break;
  }
}

/*_________________---------------------------__________________
  _________________   readCountersSample      __________________
  -----------------___________________________------------------
*/

static void readCountersSample(SFSample *sample, int expanded)
{
  SFStr buf;
  uint32_t sampleLength;
  uint32_t num_elements;
  uint8_t *sampleStart;
  sf_logf(sample, "sampleType", "COUNTERSSAMPLE");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  sample->s.samplesGenerated = getData32(sample);

  sf_logf_U32(sample, "sampleSequenceNo", sample->s.samplesGenerated);
  if(expanded) {
    sample->s.ds_class = getData32(sample);
    sample->s.ds_index = getData32(sample);
  }
  else {
    uint32_t samplerId = getData32(sample);
    sample->s.ds_class = samplerId >> 24;
    sample->s.ds_index = samplerId & 0x00ffffff;
  }
  sf_logf(sample, "sourceId", printDataSource(sample->s.ds_class, sample->s.ds_index, &buf));

  num_elements = getData32(sample);

  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_start_ar("elements");

  for(uint32_t el = 0; el < num_elements; el++) {
    uint32_t tag, length;
    uint8_t *start;
    SFStr buf;
    if(sfConfig.outputFormat == SFLFMT_JSON) {
      json_start_ob(NULL);
    }
    tag = sample->s.elementType = getData32(sample);
    sf_logf(sample, "counterBlock_tag", printTag(tag, &buf));
    length = getData32(sample);
    start = (uint8_t *)sample->datap;

    switch(tag) {
    case SFLCOUNTERS_GENERIC: readCounters_generic(sample); break;
    case SFLCOUNTERS_ETHERNET: readCounters_ethernet(sample); break;
    case SFLCOUNTERS_TOKENRING:readCounters_tokenring(sample); break;
    case SFLCOUNTERS_VG: readCounters_vg(sample); break;
    case SFLCOUNTERS_VLAN: readCounters_vlan(sample); break;
    case SFLCOUNTERS_80211: readCounters_80211(sample); break;
    case SFLCOUNTERS_LACP: readCounters_LACP(sample); break;
    case SFLCOUNTERS_SFP: readCounters_SFP(sample); break;
    case SFLCOUNTERS_PROCESSOR: readCounters_processor(sample); break;
    case SFLCOUNTERS_RADIO: readCounters_radio(sample); break;
    case SFLCOUNTERS_OFPORT: readCounters_OFPort(sample); break;
    case SFLCOUNTERS_PORTNAME: readCounters_portName(sample); break;
    case SFLCOUNTERS_HOST_HID: readCounters_host_hid(sample); break;
    case SFLCOUNTERS_ADAPTORS: readCounters_adaptors(sample); break;
    case SFLCOUNTERS_HOST_PAR: readCounters_host_parent(sample); break;
    case SFLCOUNTERS_HOST_CPU: readCounters_host_cpu(sample, length); break;
    case SFLCOUNTERS_HOST_MEM: readCounters_host_mem(sample); break;
    case SFLCOUNTERS_HOST_DSK: readCounters_host_dsk(sample); break;
    case SFLCOUNTERS_HOST_NIO: readCounters_host_nio(sample); break;
    case SFLCOUNTERS_HOST_IP: readCounters_host_ip(sample); break;
    case SFLCOUNTERS_HOST_ICMP: readCounters_host_icmp(sample); break;
    case SFLCOUNTERS_HOST_TCP: readCounters_host_tcp(sample); break;
    case SFLCOUNTERS_HOST_UDP: readCounters_host_udp(sample); break;
    case SFLCOUNTERS_HOST_VRT_NODE: readCounters_host_vnode(sample); break;
    case SFLCOUNTERS_HOST_VRT_CPU: readCounters_host_vcpu(sample); break;
    case SFLCOUNTERS_HOST_VRT_MEM: readCounters_host_vmem(sample); break;
    case SFLCOUNTERS_HOST_VRT_DSK: readCounters_host_vdsk(sample); break;
    case SFLCOUNTERS_HOST_VRT_NIO: readCounters_host_vnio(sample); break;
    case SFLCOUNTERS_HOST_GPU_NVML: readCounters_host_gpu_nvml(sample); break;
    case SFLCOUNTERS_BCM_TABLES: readCounters_bcm_tables(sample); break;
    case SFLCOUNTERS_MEMCACHE: readCounters_memcache(sample); break;
    case SFLCOUNTERS_MEMCACHE2: readCounters_memcache2(sample); break;
    case SFLCOUNTERS_HTTP: readCounters_http(sample); break;
    case SFLCOUNTERS_JVM: readCounters_JVM(sample); break;
    case SFLCOUNTERS_JMX: readCounters_JMX(sample, length); break;
    case SFLCOUNTERS_APP: readCounters_APP(sample); break;
    case SFLCOUNTERS_APP_RESOURCE: readCounters_APP_RESOURCE(sample); break;
    case SFLCOUNTERS_APP_WORKERS: readCounters_APP_WORKERS(sample); break;
    case SFLCOUNTERS_VDI: readCounters_VDI(sample); break;
    case SFLCOUNTERS_OVSDP: readCounters_OVSDP(sample); break;
    default: skipTLVRecord(sample, tag, length, "counters_sample_element"); break;
    }
    lengthCheck(sample, "counters_sample_element", start, length);
    if(sfConfig.outputFormat == SFLFMT_JSON)
      json_end_ob();
  }
  lengthCheck(sample, "counters_sample", sampleStart, sampleLength);
  if(sfConfig.outputFormat == SFLFMT_JSON)
    json_end_ar();

  switch(sfConfig.outputFormat) {
  case SFLFMT_LINE:
    writeCountersLine(sample);
    break;
  case SFLFMT_LINE_CUSTOM:
    writeLineCustom(sample);
    clearLineCustom(sample, SFSCOPE_SAMPLE);
    break;
  default:
    break;
  }
}

/*_________________---------------------------__________________
  _________________       readRTMetric        __________________
  -----------------___________________________------------------
*/

static void readRTMetric(SFSample *sample)
{
#define SFL_MAX_RTMETRIC_KEY_LEN 64
#define SFL_MAX_RTMETRIC_VAL_LEN 255
  char dsName[SFL_MAX_RTMETRIC_KEY_LEN];
  uint32_t sampleLength;
  uint32_t num_elements;
  uint8_t *sampleStart;
  sf_logf(sample, "sampleType", "RTMETRIC");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  if(getString(sample, dsName, SFL_MAX_RTMETRIC_KEY_LEN) > 0) {
    sf_logf(sample, "rtmetric_datasource_name", dsName);
  }
  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      char mname[SFL_MAX_RTMETRIC_KEY_LEN];
      uint32_t mtype;
      char mvalstr[SFL_MAX_RTMETRIC_VAL_LEN];
      uint32_t mvali32;
      uint64_t mvali64;
      float mvalfloat;
      double mvaldouble;
      getString(sample, mname, SFL_MAX_RTMETRIC_KEY_LEN);
      mtype = getData32(sample);
      switch(mtype) {
      case 0:
	getString(sample, mvalstr, SFL_MAX_RTMETRIC_VAL_LEN);
	sf_logf_pushPrefix(sample, "rtmetric_string_");
	sf_logf(sample, mname, mvalstr);
	sf_logf_popPrefix(sample);
	break;
      case 1:
	mvali32 = getData32(sample);
	sf_logf_U32_formatted(sample, "rtmetric_counter32_", mname, "%u", mvali32);
	break;
      case 2:
	mvali64 = getData64(sample);
	sf_logf_U64_formatted(sample, "rtmetric_counter64_", mname, "%"PRIu64, mvali64);
	break;
      case 3:
	mvali32 = getData32(sample);
	sf_logf_U32_formatted(sample, "rtmetric_gauge32_", mname, "%u", mvali32);
	break;
      case 4:
	mvali64 = getData64(sample);
	sf_logf_U64_formatted(sample, "rtmetric_gauge64_", mname, "%"PRIu64, mvali64);
	break;
      case 5:
	mvalfloat = getFloat(sample);
	sf_logf_double_formatted(sample, "rtmetric_gaugeFloat_", mname, "%.3f", (double)mvalfloat);
	break;
      case 6:
	mvaldouble = getDouble(sample);
	sf_logf_double_formatted(sample, "rtmetric_gaugeDouble_", mname, "%.3f", mvaldouble);
	break;
      default:
	sf_log(sample, "rtmetric unknown_type %u\n", mtype);
	SFABORT(sample, SF_ABORT_DECODE_ERROR);
	break;
      }
    }
  }
  lengthCheck(sample, "rtmetric_sample", sampleStart, sampleLength);
}

/*_________________---------------------------__________________
  _________________       readRTFlow          __________________
  -----------------___________________________------------------
*/

static void readRTFlow(SFSample *sample)
{
  char dsName[SFL_MAX_RTMETRIC_KEY_LEN];
  uint32_t sampleLength;
  uint32_t num_elements;
  uint8_t *sampleStart;
  sf_logf(sample, "sampleType", "RTFLOW");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  if(getString(sample, dsName, SFL_MAX_RTMETRIC_KEY_LEN) > 0) {
    sf_logf(sample, "rtflow_datasource_name", dsName);
  }
  sf_log_next32(sample, "rtflow_sampling_rate");
  sf_log_next32(sample, "rtflow_sample_pool");
  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      char fname[SFL_MAX_RTMETRIC_KEY_LEN];
      uint32_t ftype;
      char fvalstr[SFL_MAX_RTMETRIC_VAL_LEN];
      uint32_t fvali32;
      uint64_t fvali64;
      float fvalfloat;
      double fvaldouble;
      SFLAddress fvaladdr;
      SFStr addrstr;
      u_char fvalmac[6];
      char fvalmacstr[64];
      getString(sample, fname, SFL_MAX_RTMETRIC_KEY_LEN);
      ftype = getData32(sample);
      switch(ftype) {
      case 0:
	getString(sample, fvalstr, SFL_MAX_RTMETRIC_VAL_LEN);
	sf_logf_pushPrefix(sample, "rtflow_string_");
	sf_logf(sample, fname, fvalstr);
	sf_logf_popPrefix(sample);
	break;
      case 1:
	memcpy(fvalmac, sample->datap, 6);
	skipBytes(sample, 6);
	sf_logf_pushPrefix(sample, "rtflow_mac_");
	sf_logf(sample, fname, printMAC(fvalmac, &addrstr));
	sf_logf_popPrefix(sample);
	break;
      case 2:
	fvaladdr.type = SFLADDRESSTYPE_IP_V4;
	fvaladdr.address.ip_v4.addr = getData32_nobswap(sample);
	sf_logf_pushPrefix(sample, "rtflow_ip_");
	sf_logf(sample, fname, printAddress(&fvaladdr, &addrstr));
	sf_logf_popPrefix(sample);
	break;
      case 3:
	fvaladdr.type = SFLADDRESSTYPE_IP_V6;
	memcpy(fvaladdr.address.ip_v6.addr, sample->datap, 16);
	skipBytes(sample, 16);
	sf_logf_pushPrefix(sample, "rtflow_ip6_");
	sf_logf(sample, fname, printAddress(&fvaladdr, &addrstr));
	sf_logf_popPrefix(sample);
	break;
      case 4:
	fvali32 = getData32(sample);
	sf_logf_U32_formatted(sample, "rtflow_int32_", fname, "%u", fvali32);
	break;
      case 5:
	fvali64 = getData64(sample);
	sf_logf_U64_formatted(sample, "rtflow_int64_", fname, "%"PRIu64, fvali64);
	break;
      case 6:
	fvalfloat = getFloat(sample);
	sf_logf_double_formatted(sample, "rtflow_float_", fname, "%.3f", (double)fvalfloat);
	break;
      case 7:
	fvaldouble = getDouble(sample);
	sf_logf_double_formatted(sample, "rtflow_double_", fname, "%.3f", fvaldouble);
	break;
      default:
	sf_log(sample, "rtflow unknown_type %u\n", ftype);
	SFABORT(sample, SF_ABORT_DECODE_ERROR);
	break;
      }
    }
  }
  lengthCheck(sample, "rtflow_sample", sampleStart, sampleLength);
}

/*_________________---------------------------__________________
  _________________      readSFlowDatagram    __________________
  -----------------___________________________------------------
*/

static void readSFlowDatagram(SFSample *sample)
{
  uint32_t samplesInPacket;
  SFStr buf;

  /* log some datagram info */
  sfConfig.currentFieldScope = SFSCOPE_DATAGRAM;
  sf_logf(sample, "datagramSourceIP", printAddress(&sample->sourceIP, &buf));
  sf_logf_U32(sample, "datagramSize", sample->rawSampleLen);
  sf_logf_U32(sample, "unixSecondsUTC", sample->readTimestamp);
  sf_logf(sample, "localtime", printTimestamp(sample->readTimestamp, &buf));
  if(sample->pcapTimestamp) {
    /* thanks to Richard Clayton for this bugfix */
    sf_logf(sample, "pcapTimestamp", printTimestamp(sample->pcapTimestamp, &buf));
  }

  /* check the version */
  sample->datagramVersion = getData32(sample);
  sf_logf_U32(sample, "datagramVersion", sample->datagramVersion);
  if(sample->datagramVersion != 2 &&
     sample->datagramVersion != 4 &&
     sample->datagramVersion != 5) {
    receiveError(sample,  "unexpected datagram version number\n", YES);
  }

  /* get the agent address */
  getAddress(sample, &sample->agent_addr);

  /* version 5 has an agent sub-id as well */
  if(sample->datagramVersion >= 5) {
    sample->agentSubId = getData32(sample);
    sf_logf_U32(sample, "agentSubId", sample->agentSubId);
  }

  sample->sequenceNo = getData32(sample);  /* this is the packet sequence number */
  sample->sysUpTime = getData32(sample);
  samplesInPacket = getData32(sample);
  sf_logf(sample, "agent", printAddress(&sample->agent_addr, &buf));
  sf_logf_U32(sample, "packetSequenceNo", sample->sequenceNo);
  sf_logf_U32(sample, "sysUpTime", sample->sysUpTime);
  sf_logf_U32(sample, "samplesInPacket", samplesInPacket);

  /* now iterate and pull out the flows and counters samples */
  sfConfig.currentFieldScope = SFSCOPE_SAMPLE;
  {
    uint32_t samp = 0;
    if(sfConfig.outputFormat == SFLFMT_JSON)
      json_start_ar("samples");

    for(; samp < samplesInPacket; samp++) {
      if((uint8_t *)sample->datap >= sample->endp) {
	fprintf(ERROUT, "unexpected end of datagram after sample %d of %d\n", samp, samplesInPacket);
	SFABORT(sample, SF_ABORT_EOS);
      }
      // clear all per-sample fields
      memset(&sample->s, 0, sizeof(sample->s));
      /* just read the tag, then call the approriate decode fn */
      sample->s.elementType = 0;
      sample->s.sampleType = getData32(sample);

      if(sfConfig.outputFormat == SFLFMT_JSON) {
	json_start_ob(NULL);
      }
      else
	sf_log(sample,"startSample ----------------------\n");

      sf_logf(sample, "sampleType_tag", printTag(sample->s.sampleType, &buf));
      if(sample->datagramVersion >= 5) {
	switch(sample->s.sampleType) {
	case SFLFLOW_SAMPLE: readFlowSample(sample, NO); break;
	case SFLCOUNTERS_SAMPLE: readCountersSample(sample, NO); break;
	case SFLFLOW_SAMPLE_EXPANDED: readFlowSample(sample, YES); break;
	case SFLCOUNTERS_SAMPLE_EXPANDED: readCountersSample(sample, YES); break;
	case SFLEVENT_DISCARDED_PACKET: readDiscardSample(sample); break;
	case SFLRTMETRIC: readRTMetric(sample); break;
	case SFLRTFLOW: readRTFlow(sample); break;
	default: skipTLVRecord(sample, sample->s.sampleType, getData32(sample), "sample"); break;
	}
      }
      else {
	switch(sample->s.sampleType) {
	case FLOWSAMPLE: readFlowSample_v2v4(sample); break;
	case COUNTERSSAMPLE: readCountersSample_v2v4(sample); break;
	default: receiveError(sample, "unexpected sample type", YES); break;
	}
      }
      if(sfConfig.outputFormat == SFLFMT_JSON)
	json_end_ob();
      else
	sf_log(sample,"endSample   ----------------------\n");
    }
    if(sfConfig.outputFormat == SFLFMT_JSON)
      json_end_ar();
  }
}

/*_________________---------------------------__________________
  _________________  receiveSFlowDatagram     __________________
  -----------------___________________________------------------
*/

static void receiveSFlowDatagram(SFSample *sample)
{
  if(sfConfig.forwardingTargets || sfConfig.forwardingTargets6) {
    /* if we are forwarding, then do nothing else (it might
       be important from a performance point of view). */
    SFForwardingTarget *tgt = sfConfig.forwardingTargets;
    for( ; tgt != NULL; tgt = tgt->nxt) {
      int bytesSent;
      if((bytesSent = sendto(tgt->sock,
			     (const char *)sample->rawSample,
			     sample->rawSampleLen,
			     0,
			     (struct sockaddr *)(&tgt->addr),
			     sizeof(tgt->addr))) != sample->rawSampleLen) {
	fprintf(ERROUT, "sendto returned %d (expected %d): %s\n",
		bytesSent,
		sample->rawSampleLen,
		strerror(errno));
      }
    }
    SFForwardingTarget6 *tgt6 = sfConfig.forwardingTargets6;
    for( ; tgt6 != NULL; tgt6 = tgt6->nxt) {
      int bytesSent;
      if((bytesSent = sendto(tgt6->sock,
			     (const char *)sample->rawSample,
			     sample->rawSampleLen,
			     0,
			     (struct sockaddr *)(&tgt6->addr),
			     sizeof(tgt6->addr))) != sample->rawSampleLen) {
	fprintf(ERROUT, "sendto returned %d (expected %d): %s\n",
		bytesSent,
		sample->rawSampleLen,
		strerror(errno));
      }
    }
  }
  else {
    int exceptionVal;
    sample->readTimestamp = (long)time(NULL);
    if(sfConfig.outputFormat == SFLFMT_JSON) {
      sfConfig.jsonStart = YES;
      json_start_ob(NULL);
    }
    else {
      sf_log(sample,"startDatagram =================================\n");
    }

    if((exceptionVal = setjmp(sample->env)) == 0)  {
      /* TRY */
      sample->datap = (uint32_t *)sample->rawSample;
      sample->endp = (uint8_t *)sample->rawSample + sample->rawSampleLen;
      readSFlowDatagram(sample);
    }
    else {
      /* CATCH */
      fprintf(ERROUT, "caught exception: %d\n", exceptionVal);
    }
    if(sfConfig.outputFormat == SFLFMT_JSON) {
      json_end_ob();
      printf("\n");
    }
    else {
      sf_log(sample, "endDatagram   =================================\n");
    }
    fflush(stdout);

    if(sfConfig.outputFormat == SFLFMT_JSON) {
      /* reset depth in case an exception left it hanging */
      sfConfig.outputDepth = 0;
      /* add blank line if pretty-printing */
      if(sfConfig.jsonIndent)
	putchar('\n');

    }
    else if(sfConfig.outputFormat == SFLFMT_LINE_CUSTOM) {
      /* clear datagram-scoped field values */
      clearLineCustom(sample, SFSCOPE_DATAGRAM);
    }
  }
}

/*_________________---------------------------__________________
  _________________  sendSFlowDatagram        __________________
  -----------------___________________________------------------
  This variant comes from SFDDgram and uses vectored I/O
*/

static void sendSFlowDatagram(void *magic, struct iovec *iov, int iovcnt)
{
  if(sfConfig.forwardingTargets || sfConfig.forwardingTargets6) {
    SFForwardingTarget *tgt = sfConfig.forwardingTargets;
    for( ; tgt != NULL; tgt = tgt->nxt) {
      struct msghdr msg = { .msg_name = &tgt->addr,
			    .msg_namelen = sizeof(tgt->addr),
			    .msg_iov = iov,
			    .msg_iovlen = iovcnt };
      if(sendmsg(tgt->sock, &msg, 0) == -1) {
	fprintf(ERROUT, "sendmsg ERROR : %s\n",
		strerror(errno));
      }
    }
    SFForwardingTarget6 *tgt6 = sfConfig.forwardingTargets6;
    for( ; tgt6 != NULL; tgt6 = tgt6->nxt) {
      struct msghdr msg = { .msg_name = &tgt6->addr,
			    .msg_namelen = sizeof(tgt6->addr),
			    .msg_iov = iov,
			    .msg_iovlen = iovcnt };
      if(sendmsg(tgt6->sock, &msg, 0) == -1) {
	fprintf(ERROUT, "sendmsg ERROR : %s\n",
		strerror(errno));
      }
    }
  }
}

/*__________________-----------------------------__________________
   _________________    openInputUDPSocket       __________________
   -----------------_____________________________------------------
*/

static int openInputUDPSocket(uint16_t port)
{
  int soc;
  struct sockaddr_in myaddr_in;

  /* Create socket */
  memset((char *)&myaddr_in, 0, sizeof(struct sockaddr_in));
  myaddr_in.sin_family = AF_INET;
  /* myaddr_in6.sin6_addr.s_addr = INADDR_ANY; */
  myaddr_in.sin_port = htons(port);

  if ((soc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    fprintf(ERROUT, "v4 socket() creation failed, %s\n", strerror(errno));
    return -1;
  }

  /* make socket non-blocking */
  int save_fd = fcntl(soc, F_GETFL);
  save_fd |= O_NONBLOCK;
  fcntl(soc, F_SETFL, save_fd);

  /* Bind the socket */
  if(bind(soc, (struct sockaddr *)&myaddr_in, sizeof(struct sockaddr_in)) == -1) {
    fprintf(ERROUT, "v4 bind() failed, port = %d : %s\n", port, strerror(errno));
    return -1;
  }
  return soc;
}

/*__________________-----------------------------__________________
   _________________    openInputUDP6Socket      __________________
   -----------------_____________________________------------------
*/

static int openInputUDP6Socket(uint16_t port)
{
  int soc;
  struct sockaddr_in6 myaddr_in6;

  /* Create socket */
  memset((char *)&myaddr_in6, 0, sizeof(struct sockaddr_in6));
  myaddr_in6.sin6_family = AF_INET6;
  /* myaddr_in6.sin6_addr = INADDR_ANY; */
  myaddr_in6.sin6_port = htons(port);

  if ((soc = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    fprintf(ERROUT, "v6 socket() creation failed, %s\n", strerror(errno));
    exit(-6);
  }

  /* make socket non-blocking */
  int save_fd = fcntl(soc, F_GETFL);
  save_fd |= O_NONBLOCK;
  fcntl(soc, F_SETFL, save_fd);

  /* Bind the socket */
  if(bind(soc, (struct sockaddr *)&myaddr_in6, sizeof(struct sockaddr_in6)) == -1) {
    fprintf(ERROUT, "v6 bind() failed, port = %d : %s\n", port, strerror(errno));
    return -1;
  }
  return soc;
}

/*_________________---------------------------__________________
  _________________   ipv4MappedAddress       __________________
  -----------------___________________________------------------
*/

static int ipv4MappedAddress(SFLIPv6 *ipv6addr, SFLIPv4 *ip4addr) {
    static uint8_t mapped_prefix[] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
    static uint8_t compat_prefix[] = { 0,0,0,0,0,0,0,0,0,0,0,0 };
    if(!memcmp(ipv6addr->addr, mapped_prefix, 12) ||
       !memcmp(ipv6addr->addr, compat_prefix, 12)) {
        memcpy(ip4addr, ipv6addr->addr + 12, 4);
        return YES;
    }
    return NO;
}

/*_________________---------------------------__________________
  _________________       readPacket          __________________
  -----------------___________________________------------------
*/

static void readPacket(int soc)
{
  struct sockaddr_in6 peer;
  int cc;
  socklen_t alen;
  char buf[SA_MAX_SFLOW_PKT_SIZ];
  alen = sizeof(peer);
  memset(&peer, 0, sizeof(peer));
  cc = recvfrom(soc, buf, SA_MAX_SFLOW_PKT_SIZ, 0, (struct sockaddr *)&peer, &alen);
  if(cc <= 0) {
    fprintf(ERROUT, "recvfrom() failed, %s\n", strerror(errno));
    return;
  }
  SFSample sample;
  memset(&sample, 0, sizeof(sample));
  sample.rawSample = (uint8_t *)buf;
  sample.rawSampleLen = cc;
  if(alen == sizeof(struct sockaddr_in)) {
    struct sockaddr_in *peer4 = (struct sockaddr_in *)&peer;
    sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;
    memcpy(&sample.sourceIP.address.ip_v4, &peer4->sin_addr, 4);
  }
  else {
    SFLIPv4 v4src;
    sample.sourceIP.type = SFLADDRESSTYPE_IP_V6;
    memcpy(sample.sourceIP.address.ip_v6.addr, &peer.sin6_addr, 16);
    if(ipv4MappedAddress(&sample.sourceIP.address.ip_v6, &v4src)) {
      sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;
      sample.sourceIP.address.ip_v4 = v4src;
    }
  }
  receiveSFlowDatagram(&sample);
}

/*_________________---------------------------__________________
  _________________     decodeLinkLayer       __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found. Decode the 802.1d if it's there.
*/

static int pcapOffsetToSFlow(uint8_t *start, int len)
{
  uint8_t *end = start + len;
  uint8_t *ptr = start;
  uint16_t type_len;

  switch(sfConfig.readPcapHdr.linktype) {
  case DLT_LINUX_SLL:
    {
      uint16_t packet_type = (ptr[0] << 8) + ptr[1];
      uint16_t arphrd_type = (ptr[2] << 8) + ptr[3];
      uint16_t lladdr_len = (ptr[4] << 8) + ptr[5];
      /* but lladdr field is always 8 bytes regardless */
      ptr += 6 + 8;
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
    }
    break;

  case DLT_EN10MB:
  default:
    /* assume Ethernet header */
    if(len < NFT_ETHHDR_SIZ) return -1; /* not enough for an Ethernet header */
    ptr += 6; /* dst */
    ptr += 6; /* src */
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;
    break;
  }
 
  while(type_len == 0x8100
	|| type_len == 0x88A8
	|| type_len == 0x9100
	|| type_len == 0x9200
	|| type_len == 0x9300) {
    /* VLAN  - next two bytes */
    /*  _____________________________________ */
    /* |   pri  | c |         vlan-id        | */
    /*  ------------------------------------- */
    ptr += 2;
    /* now get the type_len again (next two bytes) */
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;
    if(ptr >= end) return -1;
  }

  /* now we're just looking for IP */
  if(end - ptr < NFT_MIN_SIZ) return -1; /* not enough for an IPv4 header */

  /* peek for IPX */
  if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
    int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
    int ipxLen = (ptr[2] << 8) + ptr[3];
    if(ipxChecksum &&
       ipxLen >= IPX_HDR_LEN &&
       ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
      /* we don't do anything with IPX here */
      return -1;
  }

  if(type_len <= NFT_MAX_8023_LEN) {
    /* assume 802.3+802.2 header */
    /* check for SNAP */
    if(ptr[0] == 0xAA &&
       ptr[1] == 0xAA &&
       ptr[2] == 0x03) {
      ptr += 3;
      if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	return -1; /* no further decode for vendor-specific protocol */
      }
      ptr += 3;
      /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
    }
    else {
      if (ptr[0] == 0x06 &&
	  ptr[1] == 0x06 &&
	  (ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the type_len to be IP so we can inline the IP decode below */
	type_len = 0x0800;
      }
      else return -1;
    }
  }
  if(ptr >= end) return -1;

  /* assume type_len is an ethernet-type now */

  if(type_len == 0x0800) {
    /* IPV4 */
    if((end - ptr) < sizeof(struct myiphdr)) return -1;
    /* look at first byte of header.... */
    /*  ___________________________ */
    /* |   version   |    hdrlen   | */
    /*  --------------------------- */
    if((*ptr >> 4) != 4) return -1; /* not version 4 */
    if((*ptr & 15) < 5) return -1; /* not IP (hdr len must be 5 quads or more) */
    ptr += (*ptr & 15) << 2; /* skip over header */
  }

  if(type_len == 0x86DD) {
    /* IPV6 */
    /* look at first byte of header.... */
    if((*ptr >> 4) != 6) return -1; /* not version 6 */
    /* just assume no header options */
    ptr += 40;
  }

  /* still have to skip over UDP header */
  ptr += 8;
  if(ptr >= end) return -1;
  return (ptr - start);
}

/*_________________---------------------------__________________
  _________________     readPcapPacket        __________________
  -----------------___________________________------------------
*/

static int readPcapPacket(FILE *file)
{
  uint8_t buf[SA_MAX_PCAP_PKT];
  struct pcap_pkthdr hdr;
  SFSample sample;
  int skipBytes = 0;

  if(fread(&hdr, sizeof(hdr), 1, file) != 1) {
    if(feof(file)) return 0;
    fprintf(ERROUT, "unable to read pcap packet header from %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
    exit(-32);
  }

  if(sfConfig.pcapSwap) {
    hdr.ts_sec = bswap_32(hdr.ts_sec);
    hdr.ts_usec = bswap_32(hdr.ts_usec);
    hdr.caplen = bswap_32(hdr.caplen);
    hdr.len = bswap_32(hdr.len);
  }

  /* Protect against possible buffer overrun from corrupted pcap file.
     Thanks to Naoki Ogawa for spotting this. */
  if(hdr.caplen > SA_MAX_PCAP_PKT) {
    fprintf(ERROUT, "pcap %s : capture-len (%u) too long for read buffer\n", sfConfig.readPcapFileName, hdr.caplen);
    return 0;
  }

  if(fread(buf, hdr.caplen, 1, file) != 1) {
    fprintf(ERROUT, "unable to read pcap packet from %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
    exit(-34);
  }

  if(sfConfig.pcapSamplingN) {
    sfConfig.output_sample_pool++;
    if(--sfConfig.output_sample_skip <= 0) {
      sfConfig.output_sample_skip = sfl_random((2 * sfConfig.pcapSamplingN)-1);
      SFDBuf *pktsmp = SFDSampleNew(sfConfig.sFlowDatagram);
      sfd_xdr_start_tlv(pktsmp, SFLFLOW_SAMPLE_EXPANDED);
      sfd_xdr_enc_int32(pktsmp, ++sfConfig.output_sample_seqNo);
      sfd_xdr_enc_int32(pktsmp, 0); // ds_class = <interface>
      sfd_xdr_enc_int32(pktsmp, 0); // ds_index = <backplane>
      sfd_xdr_enc_int32(pktsmp, sfConfig.pcapSamplingN);
      sfd_xdr_enc_int32(pktsmp, sfConfig.output_sample_pool);
      sfd_xdr_enc_int32(pktsmp, 0); // drops count
      sfd_xdr_enc_int32(pktsmp, 0); // input format
      sfd_xdr_enc_int32(pktsmp, 0); // input port <unknown>
      sfd_xdr_enc_int32(pktsmp, 0); // output format
      sfd_xdr_enc_int32(pktsmp, 0); // output port <unknown>
      sfd_xdr_enc_int32(pktsmp, 1); // number of elements
      sfd_xdr_start_tlv(pktsmp, SFLFLOW_HEADER);
      sfd_xdr_enc_int32(pktsmp, SFLHEADER_ETHERNET_ISO8023); // header protocol - TODO: learn from pcap
      sfd_xdr_enc_int32(pktsmp, hdr.len + 4); // frame_length
      sfd_xdr_enc_int32(pktsmp, 4); // stripped (FCS)
      uint32_t caplen = hdr.caplen;
      if(caplen > SFL_DEFAULT_HEADER_SIZE)
	caplen = SFL_DEFAULT_HEADER_SIZE;
      sfd_xdr_enc_int32(pktsmp, caplen); // header len
      sfd_xdr_enc_bytes(pktsmp, buf, caplen); // header
      sfd_xdr_end_tlv(pktsmp); // header element
      sfd_xdr_end_tlv(pktsmp); // flow sample
      SFDAddSample(sfConfig.sFlowDatagram, pktsmp);
    }

    if(sfConfig.playback < 100) {
      uint64_t pcap_uS = (hdr.ts_sec * 1000000) + hdr.ts_usec;
      if(sfConfig.pcap_uS) {
	// apply playback-speed time compression factor
	uint64_t wait_uS = (pcap_uS - sfConfig.pcap_uS) / sfConfig.playback;
	if((now_mS(NULL) - SFDLastSend_mS(sfConfig.sFlowDatagram)) > 500
	   || wait_uS > 500000)
	  SFDSend(sfConfig.sFlowDatagram); // flush before sleep
	usleep(wait_uS);
      }
      sfConfig.pcap_uS = pcap_uS;
    }
  }
  else {
    // reading full sFlow datagrams from pcap file
    if(hdr.caplen < hdr.len) {
      fprintf(ERROUT, "incomplete datagram (pcap snaplen too short)\n");
    }
    else {
      /* need to skip over the encapsulation in the captured packet.
	 -- should really do this by checking for 802.2, IP options etc.  but
	 for now we just assume ethernet + IP + UDP */
      skipBytes = pcapOffsetToSFlow(buf, hdr.caplen);
      memset(&sample, 0, sizeof(sample));
      sample.rawSample = buf + skipBytes;
      sample.rawSampleLen = hdr.caplen - skipBytes;
      sample.pcapTimestamp = hdr.ts_sec;
      receiveSFlowDatagram(&sample);
    }
  }
  return 1;
}


/*_________________---------------------------__________________
  _________________     parseVlanFilter       __________________
  -----------------___________________________------------------
*/

static void peekForNumber(char *p) {
  if(*p < '0' || *p > '9') {
    fprintf(ERROUT, "error parsing vlan filter ranges (next char = <%c>)\n", *p);
    exit(-19);
  }
}

static void testVlan(uint32_t num) {
  if(num > FILTER_MAX_VLAN) {
    fprintf(ERROUT, "error parsing vlan filter (vlan = <%d> out of range)\n", num);
    exit(-20);
  }
}

static void parseVlanFilter(uint8_t *array, uint8_t flag, char *start)
{
  char *p = start;
  char *sep = " ,";
  do {
    uint32_t first, last;
    p += strspn(p, sep); /* skip separators */
    peekForNumber(p);
    first = strtol(p, &p, 0); /* read an integer */
    testVlan(first);
    array[first] = flag;
    if(*p == '-') {
      /* a range. skip the '-' (so it doesn't get interpreted as unary minus) */
      p++;
      /* and read the second integer */
      peekForNumber(p);
      last = strtol(p, &p, 0);
      testVlan(last);
      if(last > first) {
	uint32_t i;
	/* iterate over the range */
	for(i = first; i <= last; i++) array[i] = flag;
      }
    }
  } while(*p != '\0');
}

/*_________________---------------------------__________________
  _________________    parseFieldList         __________________
  -----------------___________________________------------------
*/

static int parseFields(char *start, char **array) {
  char *p = start;
  char *sep = " ,";
  int tokens = 0;
  do {
    p += strspn(p, sep); /* skip separators */
    int len = strcspn(p, sep);
    if(len) {
      if(array) {
	char *str = (char *)my_calloc(len+1);
	memcpy(str, p, len);
	array[tokens] = str;
      }
      tokens++;
    }
    p += len;
  } while(*p != '\0');
  return tokens;
}

static void parseFieldList(SFFieldList *fieldList, char *start)
{
  fieldList->n = parseFields(start, NULL);
  if(fieldList->n) {
    fieldList->fields = (char **)my_calloc(fieldList->n * sizeof(char *));
    fieldList->values = (SFStr *)my_calloc(fieldList->n * sizeof(SFStr));
    fieldList->fieldScope = (char *)my_calloc(fieldList->n * sizeof(char));
    parseFields(start, fieldList->fields);
    /* load hash table with field->slot */
    hcreate(fieldList->n);
    for(int ii = 0; ii < fieldList->n; ii++) {
      SFStr_init(&fieldList->values[ii]);
      int *pSlot = (int *)my_calloc(sizeof(int));
      *pSlot = ii;
      ENTRY e;
      e.key = fieldList->fields[ii];
      e.data = pSlot;
      hsearch(e, ENTER);
    }
  }
}

/*________________---------------------------__________________
  ________________       lookupAddress       __________________
  ----------------___________________________------------------
*/

static int parseOrResolveAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family, int numeric)
{
  struct addrinfo *info = NULL;
  struct addrinfo hints = { 0 };
  hints.ai_socktype = SOCK_DGRAM; /* constrain this so we don't get lots of answers */
  hints.ai_family = family; /* AF_INET, AF_INET6 or 0 */
  if(numeric) {
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  }
  int err = getaddrinfo(name, NULL, &hints, &info);
  if(err) {
    fprintf(ERROUT, "getaddrinfo(%s) failed: %s (expecting %s)\n",
	    name,
	    gai_strerror(err),
	    numeric ? "numeric address" : "hostname or numeric address");
    /* try again if err == EAI_AGAIN? */
    return NO;
  }

  if(info == NULL)
    return NO;

  /* info now allocated on heap - see freeaddrinfo() below */
  if(!info->ai_addr) {
    err = YES;
  }
  else {
    /* answer is now in info - a linked list of answers with sockaddr values.
       extract the address we want from the first one. */
    switch(info->ai_family) {
    case AF_INET:
      {
	struct sockaddr_in *ipsoc = (struct sockaddr_in *)info->ai_addr;
	addr->type = SFLADDRESSTYPE_IP_V4;
	addr->address.ip_v4.addr = ipsoc->sin_addr.s_addr;
	if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
      }
      break;
    case AF_INET6:
      {
	struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
	addr->type = SFLADDRESSTYPE_IP_V6;
	memcpy(&addr->address.ip_v6, &ip6soc->sin6_addr, 16);
	if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
      }
      break;
    default:
      fprintf(ERROUT, "getaddrinfo(%s): unexpected address family: %d\n", name, info->ai_family);
      err = YES;
      break;
    }
  }
  /* free the dynamically allocated data before returning */
  freeaddrinfo(info);
  /* indicate success */
  return (err == NO);
}

/*_________________---------------------------__________________
  _________________   addForwardingTarget     __________________
  -----------------___________________________------------------
  return boolean for success or failure
*/

static int addForwardingTarget(char *hostandport)
{
  /* expect <host>/<port> */
#define MAX_HOSTANDPORT_LEN 100
  char hoststr[MAX_HOSTANDPORT_LEN+1];
  char *p;
  uint32_t port;
  struct sockaddr_in6 sa;
  SFLAddress tgtIP;
  SFForwardingTarget *tgt;
  SFForwardingTarget6 *tgt6;
  int numeric = (sfConfig.allowDNS) ? NO : YES;

  if(hostandport == NULL) {
    fprintf(ERROUT, "expected <host>/<port>\n");
    return NO;
  }
  if(strlen(hostandport) > MAX_HOSTANDPORT_LEN) return NO;
  /* take a copy */
  strcpy(hoststr, hostandport);
  /* find the '/' */
  for(p = hoststr; *p != '\0'; p++) if(*p == '/') break;
  if(*p == '\0') {
    /* not found */
    fprintf(ERROUT, "host/port - no '/' found\n");
    return NO;
  }
  (*p) = '\0'; /* blat in a zero */
  p++;

  /* now p points to port string, and hoststr is just the hostname or IP */
  sscanf(p, "%u", &port);
  if(port <= 0 || port >= 65535) {
    fprintf(ERROUT, "invalid forwarding target port: %u\n", port);
    return NO;
  }

  if(parseOrResolveAddress(hoststr, (struct sockaddr *)&sa, &tgtIP, AF_UNSPEC, numeric) == NO) {
    return NO;
  }
  switch(tgtIP.type) {
  case SFLADDRESSTYPE_IP_V4:
    tgt = (SFForwardingTarget *)my_calloc(sizeof(SFForwardingTarget));
    tgt->addr = *(struct sockaddr_in *)&sa;
    tgt->addr.sin_port = htons(port);
    /* and open the socket */
    if((tgt->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
      fprintf(ERROUT, "socket open (for %s) failed: %s\n", hostandport, strerror(errno));
      return NO;
    }
    /* got this far, so must be OK */
    tgt->nxt = sfConfig.forwardingTargets;
    sfConfig.forwardingTargets = tgt;
    break;

  case SFLADDRESSTYPE_IP_V6:
    tgt6 = (SFForwardingTarget6 *)my_calloc(sizeof(SFForwardingTarget6));
    tgt6->addr = sa;
    tgt6->addr.sin6_port = htons(port);
    /* and open the socket */
    if((tgt6->sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
      fprintf(ERROUT, "socket open (for %s) failed: %s\n", hostandport, strerror(errno));
      return NO;
    }
    /* got this far, so must be OK */
    tgt6->nxt = sfConfig.forwardingTargets6;
    sfConfig.forwardingTargets6 = tgt6;
    break;

  default:
    fprintf(ERROUT, "unknown address type %s\n", hoststr);
    return NO;
  }

  return YES;
}

/*_________________---------------------------__________________
  _________________   setNetFlowCollector     __________________
  -----------------___________________________------------------
  return boolean for success or failure
*/

static int setNetFlowCollector(char *host)
{
  int numeric = (sfConfig.allowDNS) ? NO : YES;
  if(parseOrResolveAddress(host,
			   (struct sockaddr *)&sfConfig.netFlowOutputSA,
			   &sfConfig.netFlowOutputIP,
			   AF_UNSPEC,
			   numeric) == NO) {
    fprintf(ERROUT, "netflow collector address lookup failed\n");
    return NO;
  }
  return YES;
}

/*_________________---------------------------__________________
  _________________      instructions         __________________
  -----------------___________________________------------------
*/

static void instructions(char *command)
{
  fprintf(ERROUT,"Copyright (c) InMon Corporation 2000-2019 ALL RIGHTS RESERVED\n");
  fprintf(ERROUT,"This software provided with NO WARRANTY WHATSOEVER\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"Usage: %s [-p port]\n", command);
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"%s version: %s\n", command, VERSION);
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"usage:\n");
  fprintf(ERROUT, "   -h | -?            -  this help message\n");
  fprintf(ERROUT, "\n");
  fprintf(ERROUT,"general:\n");
  fprintf(ERROUT, "   -k                 -  keep going on non-signal errors rather than aborting\n");
  fprintf(ERROUT, "   -D                 -  allow hosts to be referenced by DNS name\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"forwarding:\n");
  fprintf(ERROUT, "   -f host/port       -  forward sflow to IP (or hostname if -D added)\n");
  fprintf(ERROUT, "                      -   ...repeat for multiple collectors\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"text output:\n");
  fprintf(ERROUT, "   -l                 -  output in line-by-line CSV format\n");
  fprintf(ERROUT, "   -L <fields>        -  output selected fields in line-by-line CSV format\n");
  fprintf(ERROUT, "                      -    e.g. -L srcIP,dstIP\n");
  fprintf(ERROUT, "   -g                 -  output in 'grep-friendly' format\n");
  fprintf(ERROUT, "   -j                 -  output in JSON format (compact)\n");
  fprintf(ERROUT, "   -J                 -  output in JSON format (pretty-print)\n");
  fprintf(ERROUT, "   -H                 -  output HTTP common log file format\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"tcpdump output:\n");
  fprintf(ERROUT, "   -t                 -  output packet samples in binary tcpdump(1) format\n");
  fprintf(ERROUT, "   -T                 -  output discard samples in binary tcpdump(1) format\n");
  fprintf(ERROUT,"tcpdump input:\n");
  fprintf(ERROUT, "   -r file            -  read binary tcpdump(1) format\n");
  fprintf(ERROUT, "   -R N               -  encode 1:N sFlow from raw tcpdump(1) file\n");
  fprintf(ERROUT, "   -P playback        -  0.1=slow, 1=normal, 100=max\n");
  fprintf(ERROUT, "   -x                 -  remove all IPV4 content\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"NetFlow output:\n");
  fprintf(ERROUT, "   -c host            -  netflow collector IP (or hostname if -D added)\n");
  fprintf(ERROUT, "   -d port            -  netflow collector UDP port\n");
  fprintf(ERROUT, "   -e                 -  netflow collector peer_as (default = origin_as)\n");
  fprintf(ERROUT, "   -s                 -  disable scaling of netflow output by sampling rate\n");
#ifdef SPOOFSOURCE
  fprintf(ERROUT, "   -S                 -  spoof source of netflow packets to input agent IP\n");
#endif
  fprintf(ERROUT, "   -N version         -  netflow version, 5 or 9 (default 5)\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"Filters:\n");
  fprintf(ERROUT, "   -V <vlans>         -  include vlans (e.g. -V 0-20,4091)\n");
  fprintf(ERROUT, "   -v <vlans>         -  exclude vlans\n");
  fprintf(ERROUT, "   -4                 -  listen on IPv4 socket only\n");
  fprintf(ERROUT, "   -6                 -  listen on IPv6 socket only\n");
  fprintf(ERROUT, "   -A                 -  listen on both IPv4 and IPv6 sockets\n");
  fprintf(ERROUT, "\n");
  fprintf(ERROUT, "=============== Advanced Tools ===========================================\n");
  fprintf(ERROUT, "| sFlow-RT (real time)  - https://sflow-rt.com                           |\n");
  fprintf(ERROUT, "| sFlowTrend (FREE)     - https://inmon.com/products/sFlowTrend.php      |\n");
  fprintf(ERROUT, "| Traffic Sentinel      - https://inmon.com/products/trafficsentinel.php |\n");
  fprintf(ERROUT, "==========================================================================\n");
}

/*_________________---------------------------__________________
  _________________   process_command_line    __________________
  -----------------___________________________------------------
*/

static void process_command_line(int argc, char *argv[])
{
  /* set defaults */
  sfConfig.sFlowInputPort = 6343;
  sfConfig.netFlowVersion = 5;
  sfConfig.listen4 = NO;
  sfConfig.listen6 = YES;
  sfConfig.keepGoing = NO;

  /* change "+v" to "-V"
     and "+4" to "-A"
     for backwards compatibility */
  for(int ii = 1; ii < argc; ii++) {
    if(argv[ii][0] == '+') {
      if(argv[ii][1] == 'v') {
	argv[ii][0] = '-';
	argv[ii][1] = 'V';
      }
      if(argv[ii][1] == '4') {
	argv[ii][0] = '-';
	argv[ii][1] = 'A';
      }
    }
  }
  
  for (;;) {
    int in=0, option_index=0;
    static struct option long_options[] =
      {
       // ==== no argument ====
       { "line", no_argument, NULL, 'l' },
       { "json", no_argument, NULL, 'j' },
       { "json-indented", no_argument, NULL, 'J' },
       { "grep", no_argument, NULL, 'g' },
       { "write-pcap", no_argument, NULL, 't' },
       { "write-pcap-discards", no_argument, NULL, 'T' },
       { "common-logfile", no_argument, NULL, 'H' },
       { "redact-payload", no_argument, NULL, 'x' },
       { "netflow-peer-as", no_argument, NULL, 'e' },
       { "no-scaling", no_argument, NULL, 's' },
       { "netflow-spoof-source", no_argument, NULL, 'S' },
       { "allow-dns", no_argument, NULL, 'D' },
       { "listen-v4-only", no_argument, NULL, '4' },
       { "listen-v6-only", no_argument, NULL, '6' },
       { "listen-v4-v6", no_argument, NULL, 'A' },
       { "keep-going-on-error", no_argument, NULL, 'k' },
       { "help", no_argument, NULL, 'h' },
       { "usage", no_argument, NULL, '?' },
       { "version", no_argument, NULL, 'z' },
       // ==== argument required ====
       { "fields", required_argument, NULL, 'L' },
       { "port", required_argument, NULL, 'p' },
       { "read-pcap", required_argument, NULL, 'r' },
       { "read-pcap-sampling", required_argument, NULL, 'R' },
       { "read-pcap-playback", required_argument, NULL, 'P' },
       { "netflow-collector", required_argument, NULL, 'c' },
       { "netflow-udp-dport", required_argument, NULL, 'd' },
       { "netflow-version", required_argument, NULL, 'N' },
       { "forwarding-target", required_argument, NULL, 'f' },
       { "include-vlans", required_argument, NULL, 'v' },
       { "exclude-vlans", required_argument, NULL, 'V' },
       { 0,0,0,0 }
      };

    in = getopt_long(argc,
		     argv,
		     "ljJgtTHxesSD46aAkh?zL:p:r:R:P:c:d:N:f:v:V:",
		     long_options,
		     &option_index);

    if(in == -1)
      break;

    switch(in) {
    case 'a': sfConfig.anonymize = YES; break;
    case 'p': sfConfig.sFlowInputPort = atoi(optarg); break;
    case 't': sfConfig.outputFormat = SFLFMT_PCAP; break;
    case 'T': sfConfig.outputFormat = SFLFMT_PCAP_DISCARD; break;
    case 'l': sfConfig.outputFormat = SFLFMT_LINE; break;
    case 'H': sfConfig.outputFormat = SFLFMT_CLF; break;
    case 'g': sfConfig.outputFormat = SFLFMT_SCRIPT; break;
    case 'j': sfConfig.outputFormat = SFLFMT_JSON; break;
    case 'J':
      sfConfig.outputFormat = SFLFMT_JSON;
      sfConfig.jsonIndent = YES;
      break;
    case 'L':
      sfConfig.outputFormat = SFLFMT_LINE_CUSTOM;
      parseFieldList(&sfConfig.outputFieldList, optarg);
      break;
    case 'r':
      sfConfig.readPcapFileName = strdup(optarg);
      break;
    case 'R':
      sfConfig.pcapSamplingN = atoi(optarg);
      sfConfig.outputFormat = SFLFMT_SFLOW;
      break;
    case 'P':
      sfConfig.playback = atof(optarg);
      if(sfConfig.playback <= 000001)
	sfConfig.playback = 0.00001;
      break;
    case 'x': sfConfig.removeContent = YES; break;
    case 'c':
      if(setNetFlowCollector(optarg) == NO) exit(-8);
      sfConfig.outputFormat = SFLFMT_NETFLOW;
      break;
    case 'd':
      sfConfig.netFlowOutputPort = atoi(optarg);
      sfConfig.outputFormat = SFLFMT_NETFLOW;
      break;
    case 'e': sfConfig.netFlowPeerAS = YES; break;
    case 's': sfConfig.disableNetFlowScale = YES; break;
#ifdef SPOOFSOURCE
    case 'S': sfConfig.spoofSource = YES; break;
#endif
    case 'N':
      {
        sfConfig.netFlowVersion = atoi(optarg);
        switch(sfConfig.netFlowVersion) {
        case 5:
	  sendNetFlowDatagram = sendNetFlowV5Datagram;
	  sendNetFlowDatagram_v6 = NULL;
	  break;
        case 9:
	  sendNetFlowDatagram = sendNetFlowV9Datagram;
	  sendNetFlowDatagram_v6 = sendNetFlowV9V6Datagram;
	  break;
        default:
	  fprintf(ERROUT, "invalid netflow version specified (use 5 or 9)\n");
	  exit(-8);
        }
      }
      break;
    case 'f':
      if(addForwardingTarget(optarg) == NO) exit(-35);
      sfConfig.outputFormat = SFLFMT_FWD;
      break;
    case 'V':
      sfConfig.gotVlanFilter = YES;
      parseVlanFilter(sfConfig.vlanFilter, YES, optarg);
      break;
    case 'v':
      if(!sfConfig.gotVlanFilter) {
	/* when we start with an exclude list, that means the default should be YES */
	for(int vv = 0; vv < FILTER_MAX_VLAN; vv++)
	  sfConfig.vlanFilter[vv] = YES;
	sfConfig.gotVlanFilter = YES;
      }
      parseVlanFilter(sfConfig.vlanFilter, NO, optarg);
      break;
    case '4':
      sfConfig.listenControlled = YES;
      sfConfig.listen4 = YES;
      sfConfig.listen6 = NO;
      break;
    case '6':
      sfConfig.listenControlled = YES;
      sfConfig.listen4 = NO;
      sfConfig.listen6 = YES;
      break;
    case 'A':
      sfConfig.listenControlled = YES;
      sfConfig.listen4 = YES;
      sfConfig.listen6 = YES;
      break;
    case 'k':
      sfConfig.keepGoing = YES;
      break;
    case 'D':
      sfConfig.allowDNS = YES;
      break;
    case 'z':
      fprintf(ERROUT,"%s\n", VERSION);
      exit(0);
      break;
    case 'h':
    case '?':
    default:
      instructions(*argv);
      exit(0);
    }
  }
}

/*_________________---------------------------__________________
  _________________         main              __________________
  -----------------___________________________------------------
*/

int main(int argc, char *argv[])
{
  int32_t soc4=-1,soc6=-1;

  /* read the command line */
  process_command_line(argc, argv);

  /* reading from file or socket? */
  if(sfConfig.readPcapFileName) {
    if(strcmp(sfConfig.readPcapFileName, "-") == 0) sfConfig.readPcapFile = stdin;
    else sfConfig.readPcapFile = fopen(sfConfig.readPcapFileName, "rb");
    if(sfConfig.readPcapFile == NULL) {
      fprintf(ERROUT, "cannot open %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
      exit(-1);
    }
    readPcapHeader();
    if(sfConfig.pcapSamplingN) {
      /* The pcap file is raw and we want to generate sFlow packet samples from it */
      /* sending with agentAddress=0.0.0.0 should help to avoid problems if this */
      /* were to clash with 'real' data */
      SFLAddress dummyAgentAddr = { .type=SFLADDRESSTYPE_IP_V4 };
      sfConfig.sFlowDatagram = SFDNew(SFL_MAX_DATAGRAM_SIZE,
				      &dummyAgentAddr,
				      0x5F10, /* agentSubId */
				      NULL, /* cb_magic */
				      my_cb_alloc,
				      my_cb_free,
				      now_mS,
				      sendSFlowDatagram,
				      NULL, /* no locks */
				      NULL /* no err msg */);
    }
  }
  else {
    /* open the input socket -- for now it's either a v4 or v6 socket, but in future
       we may allow both to be opened so that platforms that refuse to allow v4 packets
       to be received on a v6 socket can still get both. I think for that to really work,
       however,  we will probably need to allow the bind() to be on a particular v4 or v6
       address.  Otherwise it seems likely that we will get a clash(?) */
    if(sfConfig.listen6) {
      soc6 = openInputUDP6Socket(sfConfig.sFlowInputPort);
    }
    if(sfConfig.listen4 || (soc6 == -1 && !sfConfig.listenControlled)) {
      soc4 = openInputUDPSocket(sfConfig.sFlowInputPort);
    }
    if(soc4 == -1 && soc6 == -1) {
      fprintf(ERROUT, "unable to open UDP read socket\n");
      exit(-7);
    }
  }

  /* possible open an output socket for netflow */
  if(sfConfig.netFlowOutputPort != 0
     && sfConfig.netFlowOutputIP.type != SFLADDRESSTYPE_UNDEFINED)
    openNetFlowSocket();

  /* if tcpdump format, write the header */
  if(sfConfig.outputFormat == SFLFMT_PCAP
     || sfConfig.outputFormat == SFLFMT_PCAP_DISCARD)
    writePcapHeader();
  if(sfConfig.readPcapFile) {
    /* just use a blocking read */
#ifdef SFL_PCAP_LOOP
    for(;;) {
      uint32_t pcount;
      while(readPcapPacket(sfConfig.readPcapFile))
	pcount++;
      fprintf(ERROUT, "%"PRIu64":%u\n", now_mS(NULL), pcount);
      fseek(sfConfig.readPcapFile, sizeof(struct pcap_file_header), SEEK_SET);
    }
#else
    while(readPcapPacket(sfConfig.readPcapFile));
#endif
  }
  else {
    fd_set readfds;
    /* set the select mask */
    FD_ZERO(&readfds);
    /* loop reading packets */
    for(;;) {
      int nfds;
      struct timeval timeout;
      timeout.tv_sec = 0;
      timeout.tv_usec = 100000;

      if(soc4 != -1) FD_SET(soc4, &readfds);
      if(soc6 != -1) FD_SET(soc6, &readfds);

      nfds = select((soc4 > soc6 ? soc4 : soc6) + 1,
		    &readfds,
		    (fd_set *)NULL,
		    (fd_set *)NULL,
		    &timeout);
      /* we may return prematurely if a signal was caught, in which case
       * nfds will be -1 and errno will be set to EINTR.  If we get any other
       * error, abort (unless keepGoing is set).
       */
      if(nfds < 0 && errno != EINTR) {
	fprintf(ERROUT, "select() returned %d\n", nfds);
        if(sfConfig.keepGoing) {
	  /* we are going to try and keep going, but if we are going to do
	     that we have to make sure we don't end up in a busy-loop or
	     fill the disk with logging somewhere. The safest way is probably
	     just to sleep here for a second before we go back and try again. */
	  timeout.tv_sec = 1;
	  timeout.tv_usec = 0;
	  (void)select(1, NULL, NULL, NULL, &timeout);
	}
	else {
          exit(-9);
	}
      }
      if(nfds > 0) {
	if(soc4 != -1 && FD_ISSET(soc4, &readfds)) readPacket(soc4);
	if(soc6 != -1 && FD_ISSET(soc6, &readfds)) readPacket(soc6);
      }
    }
  }
  return 0;
}


#if defined(__cplusplus)
}  /* extern "C" */
#endif
