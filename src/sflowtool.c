/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef WIN32
#include "config_windows.h"
#else
#include "config.h"
#endif

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

#ifdef WIN32
#else
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
#endif

#include "sflow.h" /* sFlow v5 */
#include "sflow_v2v4.h" /* sFlow v2/4 */

/* If the platform is Linux, enable the source-spoofing feature too. */
#ifdef linux
#define SPOOFSOURCE 1
#endif

/*
#ifdef DARWIN
#include <architecture/byte_order.h>
#define bswap_16(x) NXSwapShort(x)
#define bswap_32(x) NXSwapInt(x)
#else
#include <byteswap.h>
#endif
*/

/* just do it in a portable way... */
static uint32_t MyByteSwap32(uint32_t n) {
  return (((n & 0x000000FF)<<24) +
	  ((n & 0x0000FF00)<<8) +
	  ((n & 0x00FF0000)>>8) +
	  ((n & 0xFF000000)>>24));
}
static uint16_t MyByteSwap16(uint16_t n) {
  return ((n >> 8) | (n << 8));
}

#ifndef PRIu64
# ifdef WIN32
#  define PRIu64 "I64u"
# else
#  define PRIu64 "llu"
# endif
#endif

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
  uint8_t label1;
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

typedef enum { SFLFMT_FULL=0, SFLFMT_PCAP, SFLFMT_LINE, SFLFMT_NETFLOW, SFLFMT_FWD, SFLFMT_CLF, SFLFMT_SCRIPT } EnumSFLFormat;

#define SA_MAX_PCAP_PKT 65536
#define SA_MAX_SFLOW_PKT_SIZ 65536

typedef struct _SFConfig {
  /* sflow(R) options */
  uint16_t sFlowInputPort;
  /* netflow(TM) options */
  uint16_t netFlowOutputPort;
  struct in_addr netFlowOutputIP;
  int netFlowOutputSocket;
  uint16_t netFlowPeerAS;
  int disableNetFlowScale;
  /* tcpdump options */
  char *readPcapFileName;
  FILE *readPcapFile;
  struct pcap_file_header readPcapHdr;
  char *writePcapFile;
  EnumSFLFormat outputFormat;
  int pcapSwap;

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
} SFConfig;

/* make the options structure global to the program */
static SFConfig sfConfig;

/* define a separate global we can use to construct the common-log-file format */
typedef struct _SFCommonLogFormat {
#define SFLFMT_CLF_MAX_LINE 2000
  int valid;
  char client[64];
  char http_log[SFLFMT_CLF_MAX_LINE];
} SFCommonLogFormat;

static SFCommonLogFormat sfCLF;
static const char *SFHTTP_method_names[] = { "-", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT" };

typedef struct _SFSample {
  SFLAddress sourceIP;
  SFLAddress agent_addr;
  uint32_t agentSubId;

  /* the raw pdu */
  uint8_t *rawSample;
  uint32_t rawSampleLen;
  uint8_t *endp;
  time_t pcapTimestamp;
  time_t readTimestamp;

  /* decode cursor */
  uint32_t *datap;

  uint32_t datagramVersion;
  uint32_t sampleType;
  uint32_t elementType;
  uint32_t ds_class;
  uint32_t ds_index;

  /* generic interface counter sample */
  SFLIf_counters ifCounters;

  /* sample stream info */
  uint32_t sysUpTime;
  uint32_t sequenceNo;
  uint32_t sampledPacketSize;
  uint32_t samplesGenerated;
  uint32_t meanSkipCount;
  uint32_t samplePool;
  uint32_t dropEvents;

  /* the sampled header */
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

  /* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
  uint32_t src_user_charset;
  uint32_t src_user_len;
  char src_user[SA_MAX_EXTENDED_USER_LEN+1];
  uint32_t dst_user_charset;
  uint32_t dst_user_len;
  char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

  /* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
  uint32_t url_direction;
  uint32_t url_len;
  char url[SA_MAX_EXTENDED_URL_LEN+1];
  uint32_t host_len;
  char host[SA_MAX_EXTENDED_HOST_LEN+1];

  /* mpls */
  SFLAddress mpls_nextHop;

  /* nat */
  SFLAddress nat_src;
  SFLAddress nat_dst;

  /* counter blocks */
  uint32_t statsSamplingInterval;
  uint32_t counterBlockVersion;

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

static void readFlowSample_header(SFSample *sample);
static void readFlowSample(SFSample *sample, int expanded);
static char *printTag(uint32_t tag, char *buf);
static char *printAddress(SFLAddress *address, char *buf);

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

/*_________________---------------------------__________________
  _________________        sf_log             __________________
  -----------------___________________________------------------
*/

void sf_log(SFSample *sample, char *fmt, ...)
{
  /* don't print anything if we are exporting tcpdump format or tabular format instead */

  if(sfConfig.outputFormat == SFLFMT_SCRIPT) {
    /* scripts like to have all the context on every line */
    char agentIP[51], tag1[51], tag2[51], nowstr[200];
    time_t now = sample->pcapTimestamp ?: sample->readTimestamp;
    strftime(nowstr, 200, "%d/%b/%Y:%H:%M:%S", localtime(&now));
    printf("%s %s %u %u %u:%u %s %s ",
	   nowstr,
	   printAddress(&sample->agent_addr, agentIP),
	   sample->agentSubId,
	   sample->sequenceNo,
	   sample->ds_class,
	   sample->ds_index,
	   printTag(sample->sampleType, tag1),
	   printTag(sample->elementType, tag2));
  }
  if(sfConfig.outputFormat == SFLFMT_FULL
     || sfConfig.outputFormat == SFLFMT_SCRIPT) {
    va_list args;
    va_start(args, fmt);
    if(vprintf(fmt, args) < 0) {
      exit(-40);
    }
  }
}

/*_________________---------------------------__________________
  _________________        printHex           __________________
  -----------------___________________________------------------
*/

static uint8_t bin2hex(int nib) { return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib); }

int printHex(const uint8_t *a, int len, char *buf, int bufLen, int marker, int bytesPerOutputLine)
{
  int b = 0, i = 0;
  for(; i < len; i++) {
    uint8_t byte;
    if(b > (bufLen - 10)) break;
    if(marker > 0 && i == marker) {
      buf[b++] = '<';
      buf[b++] = '*';
      buf[b++] = '>';
      buf[b++] = '-';
    }
    byte = a[i];
    buf[b++] = bin2hex(byte >> 4);
    buf[b++] = bin2hex(byte & 0x0f);
    if(i > 0 && (i % bytesPerOutputLine) == 0) buf[b++] = '\n';
    else {
      /* separate the bytes with a dash */
      if (i < (len - 1)) buf[b++] = '-';
    }
  }
  buf[b] = '\0';
  return b;
}

/*_________________---------------------------__________________
  _________________      printUUID            __________________
  -----------------___________________________------------------
*/

  int printUUID(const uint8_t *a, char *buf, int bufLen)
  {
    int i, b = 0;
    b += printHex(a, 4, buf, bufLen, 0, 100);
    buf[b++] = '-';
    b += printHex(a + 4, 2, buf + b, bufLen - b, 0, 100);
    buf[b++] = '-';
    b += printHex(a + 6, 2, buf + b, bufLen - b, 0, 100);
    buf[b++] = '-';
    b += printHex(a + 8, 2, buf + b, bufLen - b, 0, 100);
    buf[b++] = '-';
    b += printHex(a + 10, 6, buf + b, bufLen - b, 0, 100);

    /* should really be lowercase hex - fix that here */
    for(i = 0; i < b; i++) buf[i] = tolower(buf[i]);

    /* add NUL termination */
    buf[b] = '\0';

    return b;
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
  while ((c = *r++)) {
    if(isalnum(c)) *w++ = c;
    else if(isspace(c)) *w++ = '+';
    else {
      *w++ = '%';
      *w++ = bin2hex(c >> 4);
      *w++ = bin2hex(c & 0x0f);
    }
  }
  *w++ = '\0';
  return out;
}


/*_________________---------------------------__________________
  _________________      IP_to_a              __________________
  -----------------___________________________------------------
*/

char *IP_to_a(uint32_t ipaddr, char *buf)
{
  uint8_t *ip = (uint8_t *)&ipaddr;
  /* should really be: snprintf(buf, buflen,...) but snprintf() is not always available */
  sprintf(buf, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return buf;
}

static char *printAddress(SFLAddress *address, char *buf) {
  switch(address->type) {
  case SFLADDRESSTYPE_IP_V4:
    IP_to_a(address->address.ip_v4.addr, buf);
    break;
  case SFLADDRESSTYPE_IP_V6:
    {
      uint8_t *b = address->address.ip_v6.addr;
      /* should really be: snprintf(buf, buflen,...) but snprintf() is not always available */
      sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	      b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
    }
    break;
  default:
    sprintf(buf, "-");
  }
  return buf;
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
	 || sfConfig.vlanFilter[sample->in_vlan]
	 || sfConfig.vlanFilter[sample->out_vlan]);
}

/*_________________---------------------------__________________
  _________________    writeFlowLine          __________________
  -----------------___________________________------------------
*/

static void writeFlowLine(SFSample *sample)
{
  char agentIP[51], srcIP[51], dstIP[51];
  /* source */
  if(printf("FLOW,%s,%d,%d,",
	    printAddress(&sample->agent_addr, agentIP),
	    sample->inputPort,
	    sample->outputPort) < 0) {
    exit(-41);
  }
  /* layer 2 */
  if(printf("%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,0x%04x,%d,%d",
	    sample->eth_src[0],
	    sample->eth_src[1],
	    sample->eth_src[2],
	    sample->eth_src[3],
	    sample->eth_src[4],
	    sample->eth_src[5],
	    sample->eth_dst[0],
	    sample->eth_dst[1],
	    sample->eth_dst[2],
	    sample->eth_dst[3],
	    sample->eth_dst[4],
	    sample->eth_dst[5],
	    sample->eth_type,
	    sample->in_vlan,
	    sample->out_vlan) < 0) {
    exit(-42);
  }
  /* layer 3/4 */
  if(printf(",%s,%s,%d,0x%02x,%d,%d,%d,0x%02x",
	    printAddress(&sample->ipsrc, srcIP),
	    printAddress(&sample->ipdst, dstIP),
	    sample->dcd_ipProtocol,
	    sample->dcd_ipTos,
	    sample->dcd_ipTTL,
	    sample->dcd_sport,
	    sample->dcd_dport,
	    sample->dcd_tcpFlags) < 0) {
    exit(-43);
  }
  /* bytes */
  if(printf(",%d,%d,%d\n",
	    sample->sampledPacketSize,
	    sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4,
	    sample->meanSkipCount) < 0) {
    exit(-44);
  }
}

/*_________________---------------------------__________________
  _________________    writeCountersLine      __________________
  -----------------___________________________------------------
*/

static void writeCountersLine(SFSample *sample)
{
  /* source */
  char agentIP[51];
  if(printf("CNTR,%s,", printAddress(&sample->agent_addr, agentIP)) < 0) {
    exit(-45);
  }
  if(printf("%u,%u,%"PRIu64",%u,%u,%"PRIu64",%u,%u,%u,%u,%u,%u,%"PRIu64",%u,%u,%u,%u,%u,%u\n",
	    sample->ifCounters.ifIndex,
	    sample->ifCounters.ifType,
	    sample->ifCounters.ifSpeed,
	    sample->ifCounters.ifDirection,
	    sample->ifCounters.ifStatus,
	    sample->ifCounters.ifInOctets,
	    sample->ifCounters.ifInUcastPkts,
	    sample->ifCounters.ifInMulticastPkts,
	    sample->ifCounters.ifInBroadcastPkts,
	    sample->ifCounters.ifInDiscards,
	    sample->ifCounters.ifInErrors,
	    sample->ifCounters.ifInUnknownProtos,
	    sample->ifCounters.ifOutOctets,
	    sample->ifCounters.ifOutUcastPkts,
	    sample->ifCounters.ifOutMulticastPkts,
	    sample->ifCounters.ifOutBroadcastPkts,
	    sample->ifCounters.ifOutDiscards,
	    sample->ifCounters.ifOutErrors,
	    sample->ifCounters.ifPromiscuousMode) < 0) {
    exit(-46);
  }
}

/*_________________---------------------------__________________
  _________________    receiveError           __________________
  -----------------___________________________------------------
*/

static void receiveError(SFSample *sample, char *errm, int hexdump)
{
  char ipbuf[51];
  char scratch[6000];
  char *msg = "";
  char *hex = "";
  uint32_t markOffset = (uint8_t *)sample->datap - sample->rawSample;
  if(errm) msg = errm;
  if(hexdump) {
    printHex(sample->rawSample, sample->rawSampleLen, scratch, 6000, markOffset, 16);
    hex = scratch;
  }
  fprintf(ERROUT, "%s (source IP = %s) %s\n",
	  msg,
	  printAddress(&sample->sourceIP, ipbuf),
	  hex);

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
  uint8_t *start = sample->header;
  uint8_t *end = start + sample->headerLen;
  uint8_t *ptr = start;
  uint16_t type_len;

  /* assume not found */
  sample->gotIPV4 = NO;
  sample->gotIPV6 = NO;

  if((end - ptr) < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

  sf_log(sample,"dstMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  memcpy(sample->eth_dst, ptr, 6);
  ptr += 6;
  sf_log(sample,"srcMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  memcpy(sample->eth_src, ptr, 6);
  ptr += 6;
  type_len = (ptr[0] << 8) + ptr[1];
  ptr += 2;

  if(type_len == 0x8100) {
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
    sf_log(sample,"decodedVLAN %u\n", vlan);
    sf_log(sample,"decodedPriority %u\n", priority);
    sample->in_vlan = vlan;
    /* now get the type_len again (next two bytes) */
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;
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
	sf_log(sample,"VSNAP_OUI %02X-%02X-%02X\n", ptr[0], ptr[1], ptr[2]);
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
  sample->eth_type = type_len;

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
    sample->gotIPV4 = YES;
    sample->offsetToIPV4 = (ptr - start);
  }

  if(type_len == 0x86DD) {
    /* IPV6 */
    /* look at first byte of header.... */
    if((*ptr >> 4) != 6) return; /* not version 6 */
    /* survived all the tests - store the offset to the start of the ip6 header */
    sample->gotIPV6 = YES;
    sample->offsetToIPV6 = (ptr - start);
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
  uint8_t *start = sample->header;
  uint8_t *end = start + sample->headerLen;
  uint8_t *ptr = start;

  /* assume not found */
  sample->gotIPV4 = NO;
  sample->gotIPV6 = NO;

  if(sample->headerLen < WIFI_MIN_HDR_SIZ) return; /* not enough for an 80211 MAC header */

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
	sf_log(sample,"srcMAC %02x%02x%02x%02x%02x%02x\n", srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5]);
	memcpy(sample->eth_src, srcMAC, 6);
      }
      if(dstMAC) {
	sf_log(sample,"dstMAC %02x%02x%02x%02x%02x%02x\n", dstMAC[0], dstMAC[1], dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5]);
	memcpy(sample->eth_dst, srcMAC, 6);
      }
      if(txMAC) sf_log(sample,"txMAC %02x%02x%02x%02x%02x%02x\n", txMAC[0], txMAC[1], txMAC[2], txMAC[3], txMAC[4], txMAC[5]);
      if(rxMAC) sf_log(sample,"rxMAC %02x%02x%02x%02x%02x%02x\n", rxMAC[0], rxMAC[1], rxMAC[2], rxMAC[3], rxMAC[4], rxMAC[5]);
    }
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPLayer4        __________________
  -----------------___________________________------------------
*/

static void decodeIPLayer4(SFSample *sample, uint8_t *ptr) {
  uint8_t *end = sample->header + sample->headerLen;
  if(ptr > (end - 8)) {
    /* not enough header bytes left */
    return;
  }
  switch(sample->dcd_ipProtocol) {
  case 1: /* ICMP */
    {
      struct myicmphdr icmp;
      memcpy(&icmp, ptr, sizeof(icmp));
      sf_log(sample,"ICMPType %u\n", icmp.type);
      sf_log(sample,"ICMPCode %u\n", icmp.code);
      sample->dcd_sport = icmp.type;
      sample->dcd_dport = icmp.code;
      sample->offsetToPayload = ptr + sizeof(icmp) - sample->header;
    }
    break;
  case 6: /* TCP */
    {
      struct mytcphdr tcp;
      int headerBytes;
      memcpy(&tcp, ptr, sizeof(tcp));
      sample->dcd_sport = ntohs(tcp.th_sport);
      sample->dcd_dport = ntohs(tcp.th_dport);
      sample->dcd_tcpFlags = tcp.th_flags;
      sf_log(sample,"TCPSrcPort %u\n", sample->dcd_sport);
      sf_log(sample,"TCPDstPort %u\n",sample->dcd_dport);
      sf_log(sample,"TCPFlags %u\n", sample->dcd_tcpFlags);
      headerBytes = (tcp.th_off_and_unused >> 4) * 4;
      ptr += headerBytes;
      sample->offsetToPayload = ptr - sample->header;
    }
    break;
  case 17: /* UDP */
    {
      struct myudphdr udp;
      memcpy(&udp, ptr, sizeof(udp));
      sample->dcd_sport = ntohs(udp.uh_sport);
      sample->dcd_dport = ntohs(udp.uh_dport);
      sample->udp_pduLen = ntohs(udp.uh_ulen);
      sf_log(sample,"UDPSrcPort %u\n", sample->dcd_sport);
      sf_log(sample,"UDPDstPort %u\n", sample->dcd_dport);
      sf_log(sample,"UDPBytes %u\n", sample->udp_pduLen);
      sample->offsetToPayload = ptr + sizeof(udp) - sample->header;
    }
    break;
  default: /* some other protcol */
    sample->offsetToPayload = ptr - sample->header;
    break;
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV4            __________________
  -----------------___________________________------------------
*/

static void decodeIPV4(SFSample *sample)
{
  if(sample->gotIPV4) {
    char buf[51];
    uint8_t *end = sample->header + sample->headerLen;
    uint8_t *start = sample->header + sample->offsetToIPV4;
    uint8_t *ptr = start;
    if((end - ptr) < sizeof(struct myiphdr)) return;

    /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
       platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
    struct myiphdr ip;
    memcpy(&ip, ptr, sizeof(ip));
    /* Value copy all ip elements into sample */
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
    sample->ipsrc.address.ip_v4.addr = ip.saddr;
    sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
    sample->ipdst.address.ip_v4.addr = ip.daddr;
    sample->dcd_ipProtocol = ip.protocol;
    sample->dcd_ipTos = ip.tos;
    sample->dcd_ipTTL = ip.ttl;
    sf_log(sample,"ip.tot_len %d\n", ntohs(ip.tot_len));
    /* Log out the decoded IP fields */
    sf_log(sample,"srcIP %s\n", printAddress(&sample->ipsrc, buf));
    sf_log(sample,"dstIP %s\n", printAddress(&sample->ipdst, buf));
    sf_log(sample,"IPProtocol %u\n", sample->dcd_ipProtocol);
    sf_log(sample,"IPTOS %u\n", sample->dcd_ipTos);
    sf_log(sample,"IPTTL %u\n", sample->dcd_ipTTL);
    sf_log(sample,"IPID %u\n", ip.id);
    /* check for fragments */
    sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
    if(sample->ip_fragmentOffset > 0) {
      sf_log(sample,"IPFragmentOffset %u\n", sample->ip_fragmentOffset);
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
  uint32_t label;
  uint32_t nextHeader;

  uint8_t *end = sample->header + sample->headerLen;
  uint8_t *start = sample->header + sample->offsetToIPV6;
  uint8_t *ptr = start;
  if((end - ptr) < sizeof(struct myip6hdr)) return;

  if(sample->gotIPV6) {

    /* check the version */
    {
      int ipVersion = (*ptr >> 4);
      if(ipVersion != 6) {
	sf_log(sample,"header decode error: unexpected IP version: %d\n", ipVersion);
	return;
      }
    }

    /* get the tos (priority) */
    sample->dcd_ipTos = *ptr++ & 15;
    sf_log(sample,"IPTOS %u\n", sample->dcd_ipTos);
    /* 24-bit label */
    label = *ptr++;
    label <<= 8;
    label += *ptr++;
    label <<= 8;
    label += *ptr++;
    sf_log(sample,"IP6_label 0x%lx\n", label);
    /* payload */
    payloadLen = (ptr[0] << 8) + ptr[1];
    ptr += 2;
    /* if payload is zero, that implies a jumbo payload */
    if(payloadLen == 0) sf_log(sample,"IPV6_payloadLen <jumbo>\n");
    else sf_log(sample,"IPV6_payloadLen %u\n", payloadLen);

    /* next header */
    nextHeader = *ptr++;

    /* TTL */
    sample->dcd_ipTTL = *ptr++;
    sf_log(sample,"IPTTL %u\n", sample->dcd_ipTTL);

    {/* src and dst address */
      char buf[101];
      sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sample->ipsrc.address, ptr, 16);
      ptr +=16;
      sf_log(sample,"srcIP6 %s\n", printAddress(&sample->ipsrc, buf));
      sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sample->ipdst.address, ptr, 16);
      ptr +=16;
      sf_log(sample,"dstIP6 %s\n", printAddress(&sample->ipdst, buf));
    }

    /* skip over some common header extensions...
       http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html */
    while(nextHeader == 0 ||  /* hop */
	  nextHeader == 43 || /* routing */
	  nextHeader == 44 || /* fragment */
	  /* nextHeader == 50 => encryption - don't bother coz we'll not be able to read any further */
	  nextHeader == 51 || /* auth */
	  nextHeader == 60) { /* destination options */
      uint32_t optionLen, skip;
      sf_log(sample,"IP6HeaderExtension: %d\n", nextHeader);
      nextHeader = ptr[0];
      optionLen = 8 * (ptr[1] + 1);  /* second byte gives option len in 8-byte chunks, not counting first 8 */
      skip = optionLen - 2;
      ptr += skip;
      if(ptr > end) return; /* ran off the end of the header */
    }

    /* now that we have eliminated the extension headers, nextHeader should have what we want to
       remember as the ip protocol... */
    sample->dcd_ipProtocol = nextHeader;
    sf_log(sample,"IPProtocol %u\n", sample->dcd_ipProtocol);
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
    if(hdr.magic == MyByteSwap32(TCPDUMP_MAGIC)) {
      sfConfig.pcapSwap = YES;
      hdr.version_major = MyByteSwap16(hdr.version_major);
      hdr.version_minor = MyByteSwap16(hdr.version_minor);
      hdr.thiszone = MyByteSwap32(hdr.thiszone);
      hdr.sigfigs = MyByteSwap32(hdr.sigfigs);
      hdr.snaplen = MyByteSwap32(hdr.snaplen);
      hdr.linktype = MyByteSwap32(hdr.linktype);
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
  hdr.ts_sec = (uint32_t)time(NULL);
  hdr.ts_usec = 0;
  hdr.len = sample->sampledPacketSize;
  hdr.caplen = sample->headerLen;
  if(sfConfig.removeContent && sample->offsetToPayload) {
    /* shorten the captured header to ensure no payload bytes are included */
    hdr.caplen = sample->offsetToPayload;
  }

  /* prepare the whole thing in a buffer first, in case we are piping the output
     to another process and the reader expects it all to appear at once... */
  memcpy(buf, &hdr, sizeof(hdr));
  bytes = sizeof(hdr);
  memcpy(buf+bytes, sample->header, hdr.caplen);
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
  sfConfig.sendPkt.ip.daddr = sfConfig.netFlowOutputIP.s_addr;
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

static void sendNetFlowDatagram_spoof(SFSample *sample, NFFlowPkt5 *pkt)
{
  uint16_t packetLen = sizeof(*pkt) + sizeof(struct myiphdr) + sizeof(struct myudphdr);
  /* copy the data into the send packet */
  memcpy(sfConfig.sendPkt.data, (char *)pkt, sizeof(*pkt));
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
  struct sockaddr_in addr;
  
#ifdef SPOOFSOURCE
  if(sfConfig.spoofSource) {
    openNetFlowSocket_spoof();
    return;
  }
#endif

  memset((char *)&addr,0,sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = ntohs(sfConfig.netFlowOutputPort);
  addr.sin_addr.s_addr = sfConfig.netFlowOutputIP.s_addr;
  /* open an ordinary UDP socket */
  if((sfConfig.netFlowOutputSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    fprintf(ERROUT, "netflow output socket open failed\n");
    exit(-4);
  }
  /* connect to it so we can just use send() or write() to send on it */
  if(connect(sfConfig.netFlowOutputSocket, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    fprintf(ERROUT, "connect() to netflow output socket failed\n");
    exit(-5);
  }
}

/*_________________---------------------------__________________
  _________________   sendNetFlowDatagram     __________________
  -----------------___________________________------------------
*/

static int NFFlowSequenceNo = 0;

static void sendNetFlowDatagram(SFSample *sample)
{
  NFFlowPkt5 pkt;
  uint32_t now = (uint32_t)time(NULL);
  uint32_t bytes;
  /* ignore fragments */
  if(sample->ip_fragmentOffset > 0) return;
  /* count the bytes from the start of IP header, with the exception that
     for udp packets we use the udp_pduLen. This is because the udp_pduLen
     can be up tp 65535 bytes, which causes fragmentation at the IP layer.
     Since the sampled fragments are discarded, we have to use this field
     to get the total bytes estimates right. */
  if(sample->udp_pduLen > 0) bytes = sample->udp_pduLen;
  else bytes = sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4;

  memset(&pkt, 0, sizeof(pkt));
  pkt.hdr.version = htons(5);
  pkt.hdr.count = htons(1);
  pkt.hdr.sysUpTime = htonl(now % (3600 * 24)) * 1000;  /* pretend we started at midnight (milliseconds) */
  pkt.hdr.unixSeconds = htonl(now);
  pkt.hdr.unixNanoSeconds = 0; /* no need to be more accurate than 1 second */
  pkt.hdr.flowSequence = htonl(NFFlowSequenceNo++);

  pkt.flow.srcIP = sample->ipsrc.address.ip_v4.addr;
  pkt.flow.dstIP = sample->ipdst.address.ip_v4.addr;
  pkt.flow.nextHop = sample->nextHop.address.ip_v4.addr;
  pkt.flow.if_in = htons((uint16_t)sample->inputPort);
  pkt.flow.if_out= htons((uint16_t)sample->outputPort);

  if(!sfConfig.disableNetFlowScale) {
    pkt.flow.frames = htonl(sample->meanSkipCount);
    pkt.flow.bytes = htonl(sample->meanSkipCount * bytes);
  }
  else {
    /* set the sampling_interval header field too (used to be a 16-bit reserved field) */
    uint16_t samp_ival = (uint16_t)sample->meanSkipCount;
    pkt.hdr.sampling_interval = htons(samp_ival & 0x4000);
    pkt.flow.frames = htonl(1);
    pkt.flow.bytes = htonl(bytes);
  }

  pkt.flow.firstTime = pkt.hdr.sysUpTime;  /* set the start and end time to be now (in milliseconds since last boot) */
  pkt.flow.lastTime =  pkt.hdr.sysUpTime;
  pkt.flow.srcPort = htons((uint16_t)sample->dcd_sport);
  pkt.flow.dstPort = htons((uint16_t)sample->dcd_dport);
  pkt.flow.tcpFlags = sample->dcd_tcpFlags;
  pkt.flow.ipProto = sample->dcd_ipProtocol;
  pkt.flow.ipTos = sample->dcd_ipTos;

  if(sfConfig.netFlowPeerAS) {
    pkt.flow.srcAS = htons((uint16_t)sample->src_peer_as);
    pkt.flow.dstAS = htons((uint16_t)sample->dst_peer_as);
  }
  else {
    pkt.flow.srcAS = htons((uint16_t)sample->src_as);
    pkt.flow.dstAS = htons((uint16_t)sample->dst_as);
  }

  pkt.flow.srcMask = (uint8_t)sample->srcMask;
  pkt.flow.dstMask = (uint8_t)sample->dstMask;

#ifdef SPOOFSOURCE
  if(sfConfig.spoofSource) {
    sendNetFlowDatagram_spoof(sample, &pkt);
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
  sf_log(sample,"%s %u\n", fieldName, val);
  return val;
}

static uint64_t sf_log_next64(SFSample *sample, char *fieldName) {
  uint64_t val64 = getData64(sample);
  sf_log(sample,"%s %"PRIu64"\n", fieldName, val64);
  return val64;
}

void sf_log_percentage(SFSample *sample, char *fieldName)
{
  uint32_t hundredths = getData32(sample);
  if(hundredths == (uint32_t)-1) sf_log(sample,"%s unknown\n", fieldName);
  else {
    float percent = (float)hundredths / (float)100.0;
    sf_log(sample,"%s %.2f\n", fieldName, percent);
  }
}

static float sf_log_nextFloat(SFSample *sample, char *fieldName) {
  float val = getFloat(sample);
  sf_log(sample,"%s %.3f\n", fieldName, val);
  return val;
}

void sf_log_nextMAC(SFSample *sample, char *fieldName)
{
  uint8_t *mac = (uint8_t *)sample->datap;
  skipBytes(sample, 6);
  sf_log(sample,"%s %02x%02x%02x%02x%02x%02x\n", fieldName, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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

static char *printTag(uint32_t tag, char *buf) {
  /* should really be: snprintf(buf, buflen,...) but snprintf() is not always available */
  sprintf(buf, "%u:%u", (tag >> 12), (tag & 0x00000FFF));
  return buf;
}

static void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description) {
  char buf[51];
  sf_log(sample,"skipping unknown %s: %s len=%d\n", description, printTag(tag, buf), len);
  skipBytes(sample, len);
}

/*_________________---------------------------__________________
  _________________    readExtendedSwitch     __________________
  -----------------___________________________------------------
*/

static void readExtendedSwitch(SFSample *sample)
{
  sf_log(sample,"extendedType SWITCH\n");
  sample->in_vlan = getData32(sample);
  sample->in_priority = getData32(sample);
  sample->out_vlan = getData32(sample);
  sample->out_priority = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;

  sf_log(sample,"in_vlan %u\n", sample->in_vlan);
  sf_log(sample,"in_priority %u\n", sample->in_priority);
  sf_log(sample,"out_vlan %u\n", sample->out_vlan);
  sf_log(sample,"out_priority %u\n", sample->out_priority);
}

/*_________________---------------------------__________________
  _________________    readExtendedRouter     __________________
  -----------------___________________________------------------
*/

static void readExtendedRouter(SFSample *sample)
{
  char buf[51];
  sf_log(sample,"extendedType ROUTER\n");
  getAddress(sample, &sample->nextHop);
  sample->srcMask = getData32(sample);
  sample->dstMask = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;

  sf_log(sample,"nextHop %s\n", printAddress(&sample->nextHop, buf));
  sf_log(sample,"srcSubnetMask %u\n", sample->srcMask);
  sf_log(sample,"dstSubnetMask %u\n", sample->dstMask);
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway_v2   __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway_v2(SFSample *sample)
{
  sf_log(sample,"extendedType GATEWAY\n");

  sample->my_as = getData32(sample);
  sample->src_as = getData32(sample);
  sample->src_peer_as = getData32(sample);

  /* clear dst_peer_as and dst_as to make sure we are not
     remembering values from a previous sample - (thanks Marc Lavine) */
  sample->dst_peer_as = 0;
  sample->dst_as = 0;

  sample->dst_as_path_len = getData32(sample);
  /* just point at the dst_as_path array */
  if(sample->dst_as_path_len > 0) {
    sample->dst_as_path = sample->datap;
    /* and skip over it in the input */
    skipBytes(sample, sample->dst_as_path_len * 4);
    /* fill in the dst and dst_peer fields too */
    sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
    sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
  }

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;

  sf_log(sample,"my_as %u\n", sample->my_as);
  sf_log(sample,"src_as %u\n", sample->src_as);
  sf_log(sample,"src_peer_as %u\n", sample->src_peer_as);
  sf_log(sample,"dst_as %u\n", sample->dst_as);
  sf_log(sample,"dst_peer_as %u\n", sample->dst_peer_as);
  sf_log(sample,"dst_as_path_len %u\n", sample->dst_as_path_len);
  if(sample->dst_as_path_len > 0) {
    uint32_t i = 0;
    for(; i < sample->dst_as_path_len; i++) {
      if(i == 0) sf_log(sample,"dst_as_path ");
      else sf_log(sample,"-");
      sf_log(sample,"%u", ntohl(sample->dst_as_path[i]));
    }
    sf_log(sample,"\n");
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
  char buf[51];

  sf_log(sample,"extendedType GATEWAY\n");

  if(sample->datagramVersion >= 5) {
    getAddress(sample, &sample->bgp_nextHop);
    sf_log(sample,"bgp_nexthop %s\n", printAddress(&sample->bgp_nextHop, buf));
  }

  sample->my_as = getData32(sample);
  sample->src_as = getData32(sample);
  sample->src_peer_as = getData32(sample);
  sf_log(sample,"my_as %u\n", sample->my_as);
  sf_log(sample,"src_as %u\n", sample->src_as);
  sf_log(sample,"src_peer_as %u\n", sample->src_peer_as);
  segments = getData32(sample);

  /* clear dst_peer_as and dst_as to make sure we are not
     remembering values from a previous sample - (thanks Marc Lavine) */
  sample->dst_peer_as = 0;
  sample->dst_as = 0;

  if(segments > 0) {
    sf_log(sample,"dst_as_path ");
    for(seg = 0; seg < segments; seg++) {
      uint32_t seg_type;
      uint32_t seg_len;
      uint32_t i;
      seg_type = getData32(sample);
      seg_len = getData32(sample);
      for(i = 0; i < seg_len; i++) {
	uint32_t asNumber;
	asNumber = getData32(sample);
	/* mark the first one as the dst_peer_as */
	if(i == 0 && seg == 0) sample->dst_peer_as = asNumber;
	else sf_log(sample,"-");
	/* make sure the AS sets are in parentheses */
	if(i == 0 && seg_type == SFLEXTENDED_AS_SET) sf_log(sample,"(");
	sf_log(sample,"%u", asNumber);
	/* mark the last one as the dst_as */
	if(seg == (segments - 1) && i == (seg_len - 1)) sample->dst_as = asNumber;
      }
      if(seg_type == SFLEXTENDED_AS_SET) sf_log(sample,")");
    }
    sf_log(sample,"\n");
  }
  sf_log(sample,"dst_as %u\n", sample->dst_as);
  sf_log(sample,"dst_peer_as %u\n", sample->dst_peer_as);

  sample->communities_len = getData32(sample);
  /* just point at the communities array */
  if(sample->communities_len > 0) sample->communities = sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, sample->communities_len * 4);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
  if(sample->communities_len > 0) {
    uint32_t j = 0;
    for(; j < sample->communities_len; j++) {
      if(j == 0) sf_log(sample,"BGP_communities ");
      else sf_log(sample,"-");
      sf_log(sample,"%u", ntohl(sample->communities[j]));
    }
    sf_log(sample,"\n");
  }

  sample->localpref = getData32(sample);
  sf_log(sample,"BGP_localpref %u\n", sample->localpref);

}

/*_________________---------------------------__________________
  _________________    readExtendedUser       __________________
  -----------------___________________________------------------
*/

static void readExtendedUser(SFSample *sample)
{
  sf_log(sample,"extendedType USER\n");

  if(sample->datagramVersion >= 5) {
    sample->src_user_charset = getData32(sample);
    sf_log(sample,"src_user_charset %d\n", sample->src_user_charset);
  }

  sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN);

  if(sample->datagramVersion >= 5) {
    sample->dst_user_charset = getData32(sample);
    sf_log(sample,"dst_user_charset %d\n", sample->dst_user_charset);
  }

  sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;

  sf_log(sample,"src_user %s\n", sample->src_user);
  sf_log(sample,"dst_user %s\n", sample->dst_user);
}

/*_________________---------------------------__________________
  _________________    readExtendedUrl        __________________
  -----------------___________________________------------------
*/

static void readExtendedUrl(SFSample *sample)
{
  sf_log(sample,"extendedType URL\n");

  sample->url_direction = getData32(sample);
  sf_log(sample,"url_direction %u\n", sample->url_direction);
  sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN);
  sf_log(sample,"url %s\n", sample->url);
  if(sample->datagramVersion >= 5) {
    sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN);
    sf_log(sample,"host %s\n", sample->host);
  }
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
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
    uint32_t j = 0;
    for(; j < lstk.depth; j++) {
      if(j == 0) sf_log(sample,"%s ", fieldName);
      else sf_log(sample,"-");
      lab = ntohl(lstk.stack[j]);
      sf_log(sample,"%u.%u.%u.%u",
	     (lab >> 12),     /* label */
	     (lab >> 9) & 7,  /* experimental */
	     (lab >> 8) & 1,  /* bottom of stack */
	     (lab &  255));   /* TTL */
    }
    sf_log(sample,"\n");
  }
}

/*_________________---------------------------__________________
  _________________    readExtendedMpls       __________________
  -----------------___________________________------------------
*/

static void readExtendedMpls(SFSample *sample)
{
  char buf[51];
  sf_log(sample,"extendedType MPLS\n");
  getAddress(sample, &sample->mpls_nextHop);
  sf_log(sample,"mpls_nexthop %s\n", printAddress(&sample->mpls_nextHop, buf));

  mplsLabelStack(sample, "mpls_input_stack");
  mplsLabelStack(sample, "mpls_output_stack");
  
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
  _________________    readExtendedNat        __________________
  -----------------___________________________------------------
*/

static void readExtendedNat(SFSample *sample)
{
  char buf[51];
  sf_log(sample,"extendedType NAT\n");
  getAddress(sample, &sample->nat_src);
  sf_log(sample,"nat_src %s\n", printAddress(&sample->nat_src, buf));
  getAddress(sample, &sample->nat_dst);
  sf_log(sample,"nat_dst %s\n", printAddress(&sample->nat_dst, buf));
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}

/*_________________---------------------------__________________
  _________________    readExtendedNatPort    __________________
  -----------------___________________________------------------
*/

static void readExtendedNatPort(SFSample *sample)
{
  sf_log(sample,"extendedType NAT PORT\n");
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
    sf_log(sample,"mpls_tunnel_lsp_name %s\n", tunnel_name);
  tunnel_id = getData32(sample);
  sf_log(sample,"mpls_tunnel_id %u\n", tunnel_id);
  tunnel_cos = getData32(sample);
  sf_log(sample,"mpls_tunnel_cos %u\n", tunnel_cos);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
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
    sf_log(sample,"mpls_vc_name %s\n", vc_name);
  vll_vc_id = getData32(sample);
  sf_log(sample,"mpls_vll_vc_id %u\n", vll_vc_id);
  vc_cos = getData32(sample);
  sf_log(sample,"mpls_vc_cos %u\n", vc_cos);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
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
    sf_log(sample,"mpls_ftn_descr %s\n", ftn_descr);
  ftn_mask = getData32(sample);
  sf_log(sample,"mpls_ftn_mask %u\n", ftn_mask);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
  _________________  readExtendedMplsLDP_FEC  __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsLDP_FEC(SFSample *sample)
{
  uint32_t fec_addr_prefix_len = getData32(sample);
  sf_log(sample,"mpls_fec_addr_prefix_len %u\n", fec_addr_prefix_len);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
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
    uint32_t j = 0;
    for(; j < lstk.depth; j++) {
      if(j == 0) sf_log(sample,"vlan_tunnel ");
      else sf_log(sample,"-");
      lab = ntohl(lstk.stack[j]);
      sf_log(sample,"0x%04x.%u.%u.%u",
	     (lab >> 16),       /* TPI */
	     (lab >> 13) & 7,   /* priority */
	     (lab >> 12) & 1,   /* CFI */
	     (lab & 4095));     /* VLAN */
    }
    sf_log(sample,"\n");
  }
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
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
  char ssid[SFL_MAX_SSID_LEN+1];
  if(getString(sample, ssid, SFL_MAX_SSID_LEN) > 0) {
    sf_log(sample,"rx_SSID %s\n", ssid);
  }

  bssid = (uint8_t *)sample->datap;
  sf_log(sample,"rx_BSSID ");
  for(i = 0; i < 6; i++) sf_log(sample,"%02x", bssid[i]);
  sf_log(sample,"\n");
  skipBytes(sample, 6);

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
  char ssid[SFL_MAX_SSID_LEN+1];
  if(getString(sample, ssid, SFL_MAX_SSID_LEN) > 0) {
    sf_log(sample,"tx_SSID %s\n", ssid);
  }

  bssid = (uint8_t *)sample->datap;
  sf_log(sample,"tx_BSSID ");
  for(i = 0; i < 6; i++) sf_log(sample,"%02x", bssid[i]);
  sf_log(sample,"\n");
  skipBytes(sample, 6);

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
  sf_log(sample,"aggregation_num_pdus %u\n", num_pdus);
  for(i = 0; i < num_pdus; i++) {
    sf_log(sample,"aggregation_pdu %u\n", i);
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
  sf_log(sample,"flowSampleType HEADER\n");
  sample->headerProtocol = getData32(sample);
  sf_log(sample,"headerProtocol %u\n", sample->headerProtocol);
  sample->sampledPacketSize = getData32(sample);
  sf_log(sample,"sampledPacketSize %u\n", sample->sampledPacketSize);
  if(sample->datagramVersion > 4) {
    /* stripped count introduced in sFlow version 5 */
    sample->stripped = getData32(sample);
    sf_log(sample,"strippedBytes %u\n", sample->stripped);
  }
  sample->headerLen = getData32(sample);
  sf_log(sample,"headerLen %u\n", sample->headerLen);
  
  sample->header = (uint8_t *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->headerLen);
  {
    char scratch[2000];
    printHex(sample->header, sample->headerLen, scratch, 2000, 0, 2000);
    sf_log(sample,"headerBytes %s\n", scratch);
  }
  
  switch(sample->headerProtocol) {
    /* the header protocol tells us where to jump into the decode */
  case SFLHEADER_ETHERNET_ISO8023:
    decodeLinkLayer(sample);
    break;
  case SFLHEADER_IPv4: 
    sample->gotIPV4 = YES;
    sample->offsetToIPV4 = 0;
    break;
  case SFLHEADER_IPv6: 
    sample->gotIPV6 = YES;
    sample->offsetToIPV6 = 0;
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
    sf_log(sample,"NO_DECODE headerProtocol=%d\n", sample->headerProtocol);
    break;
  default:
    fprintf(ERROUT, "undefined headerProtocol = %d\n", sample->headerProtocol);
    exit(-12);
  }
  
  if(sample->gotIPV4) {
    /* report the size of the original IPPdu (including the IP header) */
    sf_log(sample,"IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4);
    decodeIPV4(sample);
  }
  else if(sample->gotIPV6) {
    /* report the size of the original IPPdu (including the IP header) */
    sf_log(sample,"IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV6);
    decodeIPV6(sample);
  }

}

/*_________________---------------------------__________________
  _________________  readFlowSample_ethernet  __________________
  -----------------___________________________------------------
*/

static void readFlowSample_ethernet(SFSample *sample, char *prefix)
{
  uint8_t *p;
  sf_log(sample,"flowSampleType %sETHERNET\n", prefix);
  sample->eth_len = getData32(sample);
  memcpy(sample->eth_src, sample->datap, 6);
  skipBytes(sample, 6);
  memcpy(sample->eth_dst, sample->datap, 6);
  skipBytes(sample, 6);
  sample->eth_type = getData32(sample);
  sf_log(sample,"%sethernet_type %u\n", prefix, sample->eth_type);
  sf_log(sample,"%sethernet_len %u\n", prefix, sample->eth_len);
  p = sample->eth_src;
  sf_log(sample,"%sethernet_src %02x%02x%02x%02x%02x%02x\n", prefix, p[0], p[1], p[2], p[3], p[4], p[5]);
  p = sample->eth_dst;
  sf_log(sample,"%sethernet_dst %02x%02x%02x%02x%02x%02x\n", prefix, p[0], p[1], p[2], p[3], p[4], p[5]);
}


/*_________________---------------------------__________________
  _________________    readFlowSample_IPv4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv4(SFSample *sample, char *prefix)
{
  sf_log(sample,"flowSampleType %sIPV4\n", prefix);
  sample->headerLen = sizeof(SFLSampled_ipv4);
  sample->header = (uint8_t *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->headerLen);
  {
    char buf[51];
    SFLSampled_ipv4 nfKey;
    memcpy(&nfKey, sample->header, sizeof(nfKey));
    sample->sampledPacketSize = ntohl(nfKey.length);
    sf_log(sample,"%ssampledPacketSize %u\n", prefix, sample->sampledPacketSize); 
    sf_log(sample,"%sIPSize %u\n", prefix,  sample->sampledPacketSize);
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
    sample->ipsrc.address.ip_v4 = nfKey.src_ip;
    sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
    sample->ipdst.address.ip_v4 = nfKey.dst_ip;
    sample->dcd_ipProtocol = ntohl(nfKey.protocol);
    sample->dcd_ipTos = ntohl(nfKey.tos);
    sf_log(sample,"%ssrcIP %s\n", prefix, printAddress(&sample->ipsrc, buf));
    sf_log(sample,"%sdstIP %s\n", prefix, printAddress(&sample->ipdst, buf));
    sf_log(sample,"%sIPProtocol %u\n", prefix, sample->dcd_ipProtocol);
    sf_log(sample,"%sIPTOS %u\n", prefix, sample->dcd_ipTos);
    sample->dcd_sport = ntohl(nfKey.src_port);
    sample->dcd_dport = ntohl(nfKey.dst_port);
    switch(sample->dcd_ipProtocol) {
    case 1: /* ICMP */
      sf_log(sample,"%sICMPType %u\n", prefix, sample->dcd_dport);
      /* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
      break;
    case 6: /* TCP */
      sf_log(sample,"%sTCPSrcPort %u\n", prefix, sample->dcd_sport);
      sf_log(sample,"%sTCPDstPort %u\n", prefix, sample->dcd_dport);
      sample->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
      sf_log(sample,"%sTCPFlags %u\n", prefix, sample->dcd_tcpFlags);
      break;
    case 17: /* UDP */
      sf_log(sample,"%sUDPSrcPort %u\n", prefix, sample->dcd_sport);
      sf_log(sample,"%sUDPDstPort %u\n", prefix, sample->dcd_dport);
      break;
    default: /* some other protcol */
      break;
    }
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample_IPv6    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv6(SFSample *sample, char *prefix)
{
  sf_log(sample,"flowSampleType %sIPV6\n", prefix);
  sample->header = (uint8_t *)sample->datap; /* just point at the header */
  sample->headerLen = sizeof(SFLSampled_ipv6);
  skipBytes(sample, sample->headerLen);
  {
    char buf[51];
    SFLSampled_ipv6 nfKey6;
    memcpy(&nfKey6, sample->header, sizeof(nfKey6));
    sample->sampledPacketSize = ntohl(nfKey6.length);
    sf_log(sample,"%ssampledPacketSize %u\n", prefix, sample->sampledPacketSize); 
    sf_log(sample,"%sIPSize %u\n", prefix, sample->sampledPacketSize); 
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipsrc.address.ip_v6, &nfKey6.src_ip, 16);
    sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipdst.address.ip_v6, &nfKey6.dst_ip, 16);
    sample->dcd_ipProtocol = ntohl(nfKey6.protocol);
    sf_log(sample,"%ssrcIP6 %s\n", prefix, printAddress(&sample->ipsrc, buf));
    sf_log(sample,"%sdstIP6 %s\n", prefix, printAddress(&sample->ipdst, buf));
    sf_log(sample,"%sIPProtocol %u\n", prefix, sample->dcd_ipProtocol);
    sf_log(sample,"%spriority %u\n", prefix, ntohl(nfKey6.priority));
    sample->dcd_sport = ntohl(nfKey6.src_port);
    sample->dcd_dport = ntohl(nfKey6.dst_port);
    switch(sample->dcd_ipProtocol) {
    case 1: /* ICMP */
      sf_log(sample,"%sICMPType %u\n", prefix, sample->dcd_dport);
      /* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
      break;
    case 6: /* TCP */
      sf_log(sample,"%sTCPSrcPort %u\n", prefix, sample->dcd_sport);
      sf_log(sample,"%sTCPDstPort %u\n", prefix, sample->dcd_dport);
      sample->dcd_tcpFlags = ntohl(nfKey6.tcp_flags);
      sf_log(sample,"%sTCPFlags %u\n", prefix, sample->dcd_tcpFlags);
      break;
    case 17: /* UDP */
      sf_log(sample,"%sUDPSrcPort %u\n", prefix, sample->dcd_sport);
      sf_log(sample,"%sUDPDstPort %u\n", prefix, sample->dcd_dport);
      break;
    default: /* some other protcol */
      break;
    }
  }
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
  sf_log(sample,"flowSampleType memcache\n");
  sf_log_next32(sample, "memcache_op_protocol");
  sf_log_next32(sample, "memcache_op_cmd");
  if(getString(sample, key, SFL_MAX_MEMCACHE_KEY) > 0) {
    sf_log(sample,"memcache_op_key %s\n", URLEncode(key, enc_key, ENC_KEY_BYTES));
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

  sf_log(sample,"flowSampleType http\n");
  method = sf_log_next32(sample, "http_method");
  protocol = sf_log_next32(sample, "http_protocol");
  if(getString(sample, uri, SFL_MAX_HTTP_URI) > 0) {
    sf_log(sample,"http_uri %s\n", uri);
  }
  if(getString(sample, host, SFL_MAX_HTTP_HOST) > 0) {
    sf_log(sample,"http_host %s\n", host);
  }
  if(getString(sample, referrer, SFL_MAX_HTTP_REFERRER) > 0) {
    sf_log(sample,"http_referrer %s\n", referrer);
  }
  if(getString(sample, useragent, SFL_MAX_HTTP_USERAGENT) > 0) {
    sf_log(sample,"http_useragent %s\n", useragent);
  }
  if(tag == SFLFLOW_HTTP2) {
    if(getString(sample, xff, SFL_MAX_HTTP_XFF) > 0) {
      sf_log(sample,"http_xff %s\n", xff);
    }
  }
  if(getString(sample, authuser, SFL_MAX_HTTP_AUTHUSER) > 0) {
    sf_log(sample,"http_authuser %s\n", authuser);
  }
  if(getString(sample, mimetype, SFL_MAX_HTTP_MIMETYPE) > 0) {
    sf_log(sample,"http_mimetype %s\n", mimetype);
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
    /* should really be: snprintf(sfCLF.http_log, SFLFMT_CLF_MAX_LINE,...) but snprintf() is not always available */
    sprintf(sfCLF.http_log, "- %s [%s] \"%s %s HTTP/%u.%u\" %u %"PRIu64" \"%s\" \"%s\"",
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

  sf_log(sample,"flowSampleType applicationOperation\n");

  if(getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
    sf_log(sample,"application %s\n", application);
  }
  if(getString(sample, operation, SFLAPP_MAX_OPERATION_LEN) > 0) {
    sf_log(sample,"operation %s\n", operation);
  }
  if(getString(sample, attributes, SFLAPP_MAX_ATTRIBUTES_LEN) > 0) {
    sf_log(sample,"attributes %s\n", attributes);
  }
  if(getString(sample, status, SFLAPP_MAX_STATUS_LEN) > 0) {
    sf_log(sample,"status_descr %s\n", status);
  }
  sf_log_next64(sample, "request_bytes");
  sf_log_next64(sample, "response_bytes");
  sf_log_next32(sample, "duration_uS");
  status32 = getData32(sample);
  if(status32 >= SFLAPP_NUM_STATUS_CODES)
    sf_log(sample,"status <out-of-range=%u>\n", status32);
  else
    sf_log(sample,"status %s\n", SFL_APP_STATUS_names[status32]);
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
    sf_log(sample,"server_context_application %s\n", application);
  }
  if(getString(sample, operation, SFLAPP_MAX_OPERATION_LEN) > 0) {
    sf_log(sample,"server_context_operation %s\n", operation);
  }
  if(getString(sample, attributes, SFLAPP_MAX_ATTRIBUTES_LEN) > 0) {
    sf_log(sample,"server_context_attributes %s\n", attributes);
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
    sf_log(sample,"actor_initiator %s\n", actor);
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
    sf_log(sample,"actor_target %s\n", actor);
  }
}

/*_________________----------------------------__________________
  _________________   readExtendedSocket4      __________________
  -----------------____________________________------------------
*/

static void readExtendedSocket4(SFSample *sample)
{
  char buf[51];
  sf_log(sample,"extendedType socket4\n");
  sf_log_next32(sample, "socket4_ip_protocol");
  sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
  sample->ipsrc.address.ip_v4.addr = getData32_nobswap(sample);
  sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
  sample->ipdst.address.ip_v4.addr = getData32_nobswap(sample);
  sf_log(sample,"socket4_local_ip %s\n", printAddress(&sample->ipsrc, buf));
  sf_log(sample,"socket4_remote_ip %s\n", printAddress(&sample->ipdst, buf));
  sf_log_next32(sample, "socket4_local_port");
  sf_log_next32(sample, "socket4_remote_port");
  
  if(sfConfig.outputFormat == SFLFMT_CLF) {
    memcpy(sfCLF.client, buf, 50);
    sfCLF.client[50] = '\0';
  }

}

/*_________________----------------------------__________________
  _________________ readExtendedProxySocket4   __________________
  -----------------____________________________------------------
*/

static void readExtendedProxySocket4(SFSample *sample)
{
  char buf[51];
  SFLAddress ipsrc,ipdst;
  sf_log(sample,"extendedType proxy_socket4\n");
  sf_log_next32(sample, "proxy_socket4_ip_protocol");
  ipsrc.type = SFLADDRESSTYPE_IP_V4;
  ipsrc.address.ip_v4.addr = getData32_nobswap(sample);
  ipdst.type = SFLADDRESSTYPE_IP_V4;
  ipdst.address.ip_v4.addr = getData32_nobswap(sample);
  sf_log(sample,"proxy_socket4_local_ip %s\n", printAddress(&ipsrc, buf));
  sf_log(sample,"proxy_socket4_remote_ip %s\n", printAddress(&ipdst, buf));
  sf_log_next32(sample, "proxy_socket4_local_port");
  sf_log_next32(sample, "proxy_socket4_remote_port");
}

/*_________________----------------------------__________________
  _________________  readExtendedSocket6       __________________
  -----------------____________________________------------------
*/

static void readExtendedSocket6(SFSample *sample)
{
  char buf[51];
  sf_log(sample,"extendedType socket6\n");
  sf_log_next32(sample, "socket6_ip_protocol");
  sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&sample->ipsrc.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&sample->ipdst.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  sf_log(sample,"socket6_local_ip %s\n", printAddress(&sample->ipsrc, buf));
  sf_log(sample,"socket6_remote_ip %s\n", printAddress(&sample->ipdst, buf));
  sf_log_next32(sample, "socket6_local_port");
  sf_log_next32(sample, "socket6_remote_port");

  if(sfConfig.outputFormat == SFLFMT_CLF) {
    memcpy(sfCLF.client, buf, 51);
    sfCLF.client[50] = '\0';
  }
}

/*_________________----------------------------__________________
  _________________ readExtendedProxySocket6   __________________
  -----------------____________________________------------------
*/

static void readExtendedProxySocket6(SFSample *sample)
{
  char buf[51];
  SFLAddress ipsrc, ipdst;
  sf_log(sample,"extendedType proxy_socket6\n");
  sf_log_next32(sample, "proxy_socket6_ip_protocol");
  ipsrc.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&ipsrc.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  ipdst.type = SFLADDRESSTYPE_IP_V6;
  memcpy(&ipdst.address.ip_v6, sample->datap, 16);
  skipBytes(sample, 16);
  sf_log(sample,"proxy_socket6_local_ip %s\n", printAddress(&ipsrc, buf));
  sf_log(sample,"proxy_socket6_remote_ip %s\n", printAddress(&ipdst, buf));
  sf_log_next32(sample, "proxy_socket6_local_port");
  sf_log_next32(sample, "proxy_socket6_remote_port");
}

/*_________________----------------------------__________________
  _________________    readExtendedDecap       __________________
  -----------------____________________________------------------
*/

static void readExtendedDecap(SFSample *sample, char *prefix)
{
  uint32_t offset = getData32(sample);
  sf_log(sample,"extendedType %sdecap\n", prefix);
  sf_log(sample,"%sdecap_inner_header_offset %u\n", prefix, offset);
}

/*_________________----------------------------__________________
  _________________    readExtendedVNI         __________________
  -----------------____________________________------------------
*/

static void readExtendedVNI(SFSample *sample, char *prefix)
{
  uint32_t vni = getData32(sample);
  sf_log(sample,"extendedType %sVNI\n", prefix);
  sf_log(sample,"%sVNI %u\n", prefix, vni);
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
  sf_log(sample, "tcpinfo_direction %s\n", direction);
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

/*_________________---------------------------__________________
  _________________    readFlowSample_v2v4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_v2v4(SFSample *sample)
{
  sf_log(sample,"sampleType FLOWSAMPLE\n");

  sample->samplesGenerated = getData32(sample);
  sf_log(sample,"sampleSequenceNo %u\n", sample->samplesGenerated);
  {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
    sf_log(sample,"sourceId %u:%u\n", sample->ds_class, sample->ds_index);
  }
  
  sample->meanSkipCount = getData32(sample);
  sample->samplePool = getData32(sample);
  sample->dropEvents = getData32(sample);
  sample->inputPort = getData32(sample);
  sample->outputPort = getData32(sample);
  sf_log(sample,"meanSkipCount %u\n", sample->meanSkipCount);
  sf_log(sample,"samplePool %u\n", sample->samplePool);
  sf_log(sample,"dropEvents %u\n", sample->dropEvents);
  sf_log(sample,"inputPort %u\n", sample->inputPort);
  if(sample->outputPort & 0x80000000) {
    uint32_t numOutputs = sample->outputPort & 0x7fffffff;
    if(numOutputs > 0) sf_log(sample,"outputPort multiple %d\n", numOutputs);
    else sf_log(sample,"outputPort multiple >1\n");
  }
  else sf_log(sample,"outputPort %u\n", sample->outputPort);
  
  sample->packet_data_tag = getData32(sample);
  
  switch(sample->packet_data_tag) {
    
  case INMPACKETTYPE_HEADER: readFlowSample_header(sample); break;
  case INMPACKETTYPE_IPV4:
    sample->gotIPV4Struct = YES;
    readFlowSample_IPv4(sample, "");
    break;
  case INMPACKETTYPE_IPV6:
    sample->gotIPV6Struct = YES;
    readFlowSample_IPv6(sample, "");
    break;
  default: receiveError(sample, "unexpected packet_data_tag", YES); break;
  }

  sample->extended_data_tag = 0;
  {
    uint32_t x;
    sample->num_extended = getData32(sample);
    for(x = 0; x < sample->num_extended; x++) {
      uint32_t extended_tag;
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
    }
  }

  if(sampleFilterOK(sample)) {
    switch(sfConfig.outputFormat) {
    case SFLFMT_NETFLOW:
      /* if we are exporting netflow and we have an IPv4 layer, compose the datagram now */
      if(sfConfig.netFlowOutputSocket && (sample->gotIPV4 || sample->gotIPV4Struct)) sendNetFlowDatagram(sample);
      break;
    case SFLFMT_PCAP:
      /* if we are writing tcpdump format, write the next packet record now */
      writePcapPacket(sample);
      break;
    case SFLFMT_LINE:
      /* or line-by-line output... */
      writeFlowLine(sample);
      break;
    case SFLFMT_CLF:
    case SFLFMT_FULL:
    case SFLFMT_SCRIPT:
    default:
      /* if it was full-detail output then it was done as we went along */
      break;
    }
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample         __________________
  -----------------___________________________------------------
*/

static void readFlowSample(SFSample *sample, int expanded)
{
  uint32_t num_elements, sampleLength;
  uint8_t *sampleStart;

  sf_log(sample,"sampleType FLOWSAMPLE\n");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  sample->samplesGenerated = getData32(sample);
  sf_log(sample,"sampleSequenceNo %u\n", sample->samplesGenerated);
  if(expanded) {
    sample->ds_class = getData32(sample);
    sample->ds_index = getData32(sample);
  }
  else {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  sf_log(sample,"sourceId %u:%u\n", sample->ds_class, sample->ds_index);

  sample->meanSkipCount = getData32(sample);
  sample->samplePool = getData32(sample);
  sample->dropEvents = getData32(sample);
  sf_log(sample,"meanSkipCount %u\n", sample->meanSkipCount);
  sf_log(sample,"samplePool %u\n", sample->samplePool);
  sf_log(sample,"dropEvents %u\n", sample->dropEvents);
  if(expanded) {
    sample->inputPortFormat = getData32(sample);
    sample->inputPort = getData32(sample);
    sample->outputPortFormat = getData32(sample);
    sample->outputPort = getData32(sample);
  }
  else {
    uint32_t inp, outp;
    inp = getData32(sample);
    outp = getData32(sample);
    sample->inputPortFormat = inp >> 30;
    sample->outputPortFormat = outp >> 30;
    sample->inputPort = inp & 0x3fffffff;
    sample->outputPort = outp & 0x3fffffff;
  }

  switch(sample->inputPortFormat) {
  case 3: sf_log(sample,"inputPort format==3 %u\n", sample->inputPort); break;
  case 2: sf_log(sample,"inputPort multiple %u\n", sample->inputPort); break;
  case 1: sf_log(sample,"inputPort dropCode %u\n", sample->inputPort); break;
  case 0: sf_log(sample,"inputPort %u\n", sample->inputPort); break;
  }

  switch(sample->outputPortFormat) {
  case 3: sf_log(sample,"outputPort format==3 %u\n", sample->outputPort); break;
  case 2: sf_log(sample,"outputPort multiple %u\n", sample->outputPort); break;
  case 1: sf_log(sample,"outputPort dropCode %u\n", sample->outputPort); break;
  case 0: sf_log(sample,"outputPort %u\n", sample->outputPort); break;
  }

  /* clear the CLF record */
  sfCLF.valid = NO;
  sfCLF.client[0] = '\0';

  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      uint32_t tag, length;
      uint8_t *start;
      char buf[51];
      tag = sample->elementType = getData32(sample);
      sf_log(sample,"flowBlock_tag %s\n", printTag(tag, buf));
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
      default: skipTLVRecord(sample, tag, length, "flow_sample_element"); break;
      }
      lengthCheck(sample, "flow_sample_element", start, length);
    }
  }
  lengthCheck(sample, "flow_sample", sampleStart, sampleLength);
  
  if(sampleFilterOK(sample)) {
    switch(sfConfig.outputFormat) {
    case SFLFMT_NETFLOW:
      /* if we are exporting netflow and we have an IPv4 layer, compose the datagram now */
      if(sfConfig.netFlowOutputSocket && sample->gotIPV4) sendNetFlowDatagram(sample);
      break;
    case SFLFMT_PCAP:
      /* if we are writing tcpdump format, write the next packet record now */
      writePcapPacket(sample);
      break;
    case SFLFMT_LINE:
      /* or line-by-line output... */
      writeFlowLine(sample);
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
    default:
      /* if it was full-detail output then it was done as we went along */
      break;
    }
  }
}

/*_________________---------------------------__________________
  _________________  readCounters_generic     __________________
  -----------------___________________________------------------
*/

static void readCounters_generic(SFSample *sample)
{
  /* the first part of the generic counters block is really just more info about the interface. */
  sample->ifCounters.ifIndex = sf_log_next32(sample, "ifIndex");
  sample->ifCounters.ifType = sf_log_next32(sample, "networkType");
  sample->ifCounters.ifSpeed = sf_log_next64(sample, "ifSpeed");
  sample->ifCounters.ifDirection = sf_log_next32(sample, "ifDirection");
  sample->ifCounters.ifStatus = sf_log_next32(sample, "ifStatus");
  /* the generic counters always come first */
  sample->ifCounters.ifInOctets = sf_log_next64(sample, "ifInOctets");
  sample->ifCounters.ifInUcastPkts = sf_log_next32(sample, "ifInUcastPkts");
  sample->ifCounters.ifInMulticastPkts = sf_log_next32(sample, "ifInMulticastPkts");
  sample->ifCounters.ifInBroadcastPkts = sf_log_next32(sample, "ifInBroadcastPkts");
  sample->ifCounters.ifInDiscards = sf_log_next32(sample, "ifInDiscards");
  sample->ifCounters.ifInErrors = sf_log_next32(sample, "ifInErrors");
  sample->ifCounters.ifInUnknownProtos = sf_log_next32(sample, "ifInUnknownProtos");
  sample->ifCounters.ifOutOctets = sf_log_next64(sample, "ifOutOctets");
  sample->ifCounters.ifOutUcastPkts = sf_log_next32(sample, "ifOutUcastPkts");
  sample->ifCounters.ifOutMulticastPkts = sf_log_next32(sample, "ifOutMulticastPkts");
  sample->ifCounters.ifOutBroadcastPkts = sf_log_next32(sample, "ifOutBroadcastPkts");
  sample->ifCounters.ifOutDiscards = sf_log_next32(sample, "ifOutDiscards");
  sample->ifCounters.ifOutErrors = sf_log_next32(sample, "ifOutErrors");
  sample->ifCounters.ifPromiscuousMode = sf_log_next32(sample, "ifPromiscuousMode");
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
  sample->in_vlan = getData32(sample);
  sf_log(sample,"in_vlan %u\n", sample->in_vlan);
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
  _________________  readCounters_portName    __________________
  -----------------___________________________------------------
*/

static void readCounters_portName(SFSample *sample)
{
  char ifname[SFL_MAX_PORTNAME_LEN+1];
  if(getString(sample, ifname, SFL_MAX_PORTNAME_LEN) > 0) {
    sf_log(sample,"ifName %s\n", ifname);
  }
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
  char uuidStr[100];
  if(getString(sample, hostname, SFL_MAX_HOSTNAME_LEN) > 0) {
    sf_log(sample,"hostname %s\n", hostname);
  }
  uuid = (uint8_t *)sample->datap;
  printUUID(uuid, uuidStr, 100);
  sf_log(sample,"UUID %s\n", uuidStr);
  skipBytes(sample, 16);
  sf_log_next32(sample, "machine_type");
  sf_log_next32(sample, "os_name");
  if(getString(sample, os_release, SFL_MAX_OSRELEASE_LEN) > 0) {
    sf_log(sample,"os_release %s\n", os_release);
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
  for(i = 0; i < num_adaptors; i++) {
    ifindex = getData32(sample);
    sf_log(sample,"adaptor_%u_ifIndex %u\n", i, ifindex);
    num_macs = getData32(sample);
    sf_log(sample,"adaptor_%u_MACs %u\n", i, num_macs);
    for(j = 0; j < num_macs; j++) {
      mac = (uint8_t *)sample->datap;
      sf_log(sample,"adaptor_%u_MAC_%u %02x%02x%02x%02x%02x%02x\n",
	     i, j,
	     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
      skipBytes(sample, 8);
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
    sf_log(sample,"jvm_name %s\n", vm_name);
  }
  if(getString(sample, vendor, SFLJVM_MAX_VENDOR_LEN) > 0) {
    sf_log(sample,"jvm_vendor %s\n", vendor);
  }
  if(getString(sample, version, SFLJVM_MAX_VERSION_LEN) > 0) {
    sf_log(sample,"jvm_version %s\n", version);
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
    sf_log(sample,"application %s\n", application);
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
  sf_log(sample,"actorAdminPortState %u\n", portState.v.actorAdmin);
  sf_log(sample,"actorOperPortState %u\n", portState.v.actorOper);
  sf_log(sample,"partnerAdminPortState %u\n", portState.v.partnerAdmin);
  sf_log(sample,"partnerOperPortState %u\n", portState.v.partnerOper);
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

static void readCounters_SFP(SFSample *sample)
{
  uint32_t num_lanes,ll;
  sf_log_next32(sample, "sfp_module_id");
  sf_log_next32(sample, "sfp_module_total_lanes");
  sf_log_next32(sample, "sfp_module_supply_voltage");
  sf_log_next32(sample, "sfp_module_temperature");
  num_lanes = getData32(sample);
  sf_log(sample, "sfp_module_active_lanes %u\n", num_lanes);
  for(ll=0; ll < num_lanes; ll++) {
    sf_log(sample, "sfp_lane_index.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_tx_bias_current_uA.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_tx_power_uW.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_tx_power_min_uW.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_tx_power_max_uW.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_tx_wavelength_nM.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_rx_power_uW.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_rx_power_min_uW.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_rx_power_max_uW.%u %u\n", ll, getData32(sample));
    sf_log(sample, "sfp_lane_rx_wavelength_nM.%u %u\n", ll, getData32(sample));
  }
}

/*_________________---------------------------__________________
  _________________  readCountersSample_v2v4  __________________
  -----------------___________________________------------------
*/

static void readCountersSample_v2v4(SFSample *sample)
{
  sf_log(sample,"sampleType COUNTERSSAMPLE\n");
  sample->samplesGenerated = getData32(sample);
  sf_log(sample,"sampleSequenceNo %u\n", sample->samplesGenerated);
  {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  sf_log(sample,"sourceId %u:%u\n", sample->ds_class, sample->ds_index);


  sample->statsSamplingInterval = getData32(sample);
  sf_log(sample,"statsSamplingInterval %u\n", sample->statsSamplingInterval);
  /* now find out what sort of counter blocks we have here... */
  sample->counterBlockVersion = getData32(sample);
  sf_log(sample,"counterBlockVersion %u\n", sample->counterBlockVersion);
  
  /* first see if we should read the generic stats */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC:
  case INMCOUNTERSVERSION_ETHERNET:
  case INMCOUNTERSVERSION_TOKENRING:
  case INMCOUNTERSVERSION_FDDI:
  case INMCOUNTERSVERSION_VG:
  case INMCOUNTERSVERSION_WAN: readCounters_generic(sample); break;
  case INMCOUNTERSVERSION_VLAN: break;
  default: receiveError(sample, "unknown stats version", YES); break;
  }
  
  /* now see if there are any specific counter blocks to add */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC: /* nothing more */ break;
  case INMCOUNTERSVERSION_ETHERNET: readCounters_ethernet(sample); break;
  case INMCOUNTERSVERSION_TOKENRING:readCounters_tokenring(sample); break;
  case INMCOUNTERSVERSION_FDDI: break;
  case INMCOUNTERSVERSION_VG: readCounters_vg(sample); break;
  case INMCOUNTERSVERSION_WAN: break;
  case INMCOUNTERSVERSION_VLAN: readCounters_vlan(sample); break;
  default: receiveError(sample, "unknown INMCOUNTERSVERSION", YES); break;
  }
  /* line-by-line output... */
  if(sfConfig.outputFormat == SFLFMT_LINE) writeCountersLine(sample);
}

/*_________________---------------------------__________________
  _________________   readCountersSample      __________________
  -----------------___________________________------------------
*/

static void readCountersSample(SFSample *sample, int expanded)
{
  uint32_t sampleLength;
  uint32_t num_elements;
  uint8_t *sampleStart;
  sf_log(sample,"sampleType COUNTERSSAMPLE\n");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  sample->samplesGenerated = getData32(sample);
  
  sf_log(sample,"sampleSequenceNo %u\n", sample->samplesGenerated);
  if(expanded) {
    sample->ds_class = getData32(sample);
    sample->ds_index = getData32(sample);
  }
  else {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  sf_log(sample,"sourceId %u:%u\n", sample->ds_class, sample->ds_index);
  
  num_elements = getData32(sample);
  {
    uint32_t el;
    for(el = 0; el < num_elements; el++) {
      uint32_t tag, length;
      uint8_t *start;
      char buf[51];
      tag = sample->elementType = getData32(sample);
      sf_log(sample,"counterBlock_tag %s\n", printTag(tag, buf));
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
      default: skipTLVRecord(sample, tag, length, "counters_sample_element"); break;
      }
      lengthCheck(sample, "counters_sample_element", start, length);
    }
  }
  lengthCheck(sample, "counters_sample", sampleStart, sampleLength);
  /* line-by-line output... */
  if(sfConfig.outputFormat == SFLFMT_LINE) writeCountersLine(sample);
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
  sf_log(sample,"sampleType RTMETRIC\n");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  if(getString(sample, dsName, SFL_MAX_RTMETRIC_KEY_LEN) > 0) {
    sf_log(sample, "rtmetric_datasource_name %s\n", dsName);
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
	sf_log(sample, "rtmetric %s = (string) \"%s\"\n", mname, mvalstr);
	break;
      case 1:
	mvali32 = getData32(sample);
	sf_log(sample, "rtmetric %s = (counter32) %u\n", mname, mvali32);
	break;
      case 2:
	mvali64 = getData64(sample);
	sf_log(sample, "rtmetric %s = (counter64) %"PRIu64"\n", mname, mvali64);
	break;
      case 3:
	mvali32 = getData32(sample);
	sf_log(sample, "rtmetric %s = (gauge32) %u\n", mname, mvali32);
	break;
      case 4:
	mvali64 = getData64(sample);
	sf_log(sample, "rtmetric %s = (gauge64) %"PRIu64"\n", mname, mvali64);
	break;
      case 5:
	mvalfloat = getFloat(sample);
	sf_log(sample, "rtmetric %s = (gaugefloat) %.3f\n", mname, mvalfloat);
	break;
      case 6:
	mvaldouble = getDouble(sample);
	sf_log(sample, "rtmetric %s = (gaugefloat) %.3f\n", mname, mvaldouble);
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
  sf_log(sample,"sampleType RTFLOW\n");
  sampleLength = getData32(sample);
  sampleStart = (uint8_t *)sample->datap;
  if(getString(sample, dsName, SFL_MAX_RTMETRIC_KEY_LEN) > 0) {
    sf_log(sample, "rtflow_datasource_name %s\n", dsName);
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
      char fvaladdrstr[64];
      u_char fvalmac[6];
      char fvalmacstr[32];
      getString(sample, fname, SFL_MAX_RTMETRIC_KEY_LEN);
      ftype = getData32(sample);
      switch(ftype) {
      case 0:
	getString(sample, fvalstr, SFL_MAX_RTMETRIC_VAL_LEN);
	sf_log(sample, "rtflow %s = (string) \"%s\"\n", fname, fvalstr);
	break;
      case 1:
	memcpy(fvalmac, sample->datap, 6);
	skipBytes(sample, 6);
	printHex(fvalmac, 6, fvalmacstr, 32, 0, 100);
	sf_log(sample, "rtflow %s = (mac) %s\n", fname, fvalmacstr);
	break;
      case 2:
	fvaladdr.type = SFLADDRESSTYPE_IP_V4;
	fvaladdr.address.ip_v4.addr = getData32_nobswap(sample);
	sf_log(sample, "rtflow %s = (ip) %s\n",
	       fname,
	       printAddress(&fvaladdr,fvaladdrstr));
	break;
      case 3:
	fvaladdr.type = SFLADDRESSTYPE_IP_V6;
	memcpy(fvaladdr.address.ip_v6.addr, sample->datap, 16);
	skipBytes(sample, 16);
	sf_log(sample, "rtflow %s = (ip6) %s\n",
	       fname,
	       printAddress(&fvaladdr,fvaladdrstr));
	break;
      case 4:
	fvali32 = getData32(sample);
	sf_log(sample, "rtflow %s = (int32) %u\n", fname, fvali32);
	break;
      case 5:
	fvali64 = getData64(sample);
	sf_log(sample, "rtflow %s = (int64) %"PRIu64"\n", fname, fvali64);
	break;
      case 6:
	fvalfloat = getFloat(sample);
	sf_log(sample, "rtflow %s = (gaugefloat) %.3f\n", fname, fvalfloat);
	break;
      case 7:
	fvaldouble = getDouble(sample);
	sf_log(sample, "rtflow %s = (gaugefloat) %.3f\n", fname, fvaldouble);
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
  char buf[51];
  
  /* log some datagram info */
  sf_log(sample,"datagramSourceIP %s\n", printAddress(&sample->sourceIP, buf));
  sf_log(sample,"datagramSize %u\n", sample->rawSampleLen);
  sf_log(sample,"unixSecondsUTC %u\n", sample->readTimestamp);
  if(sample->pcapTimestamp) sf_log(sample,"pcapTimestamp %s\n", ctime(&sample->pcapTimestamp)); /* thanks to Richard Clayton for this bugfix */

  /* check the version */
  sample->datagramVersion = getData32(sample);
  sf_log(sample,"datagramVersion %d\n", sample->datagramVersion);
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
    sf_log(sample,"agentSubId %u\n", sample->agentSubId);
  }

  sample->sequenceNo = getData32(sample);  /* this is the packet sequence number */
  sample->sysUpTime = getData32(sample);
  samplesInPacket = getData32(sample);
  sf_log(sample,"agent %s\n", printAddress(&sample->agent_addr, buf));
  sf_log(sample,"packetSequenceNo %u\n", sample->sequenceNo);
  sf_log(sample,"sysUpTime %u\n", sample->sysUpTime);
  sf_log(sample,"samplesInPacket %u\n", samplesInPacket);

  /* now iterate and pull out the flows and counters samples */
  {
    uint32_t samp = 0;
    for(; samp < samplesInPacket; samp++) {
      if((uint8_t *)sample->datap >= sample->endp) {
	fprintf(ERROUT, "unexpected end of datagram after sample %d of %d\n", samp, samplesInPacket);
	SFABORT(sample, SF_ABORT_EOS);
      }
      /* just read the tag, then call the approriate decode fn */
      sample->elementType = 0;
      sample->sampleType = getData32(sample);
      sf_log(sample,"startSample ----------------------\n");
      sf_log(sample,"sampleType_tag %s\n", printTag(sample->sampleType, buf));
      if(sample->datagramVersion >= 5) {
	switch(sample->sampleType) {
	case SFLFLOW_SAMPLE: readFlowSample(sample, NO); break;
	case SFLCOUNTERS_SAMPLE: readCountersSample(sample, NO); break;
	case SFLFLOW_SAMPLE_EXPANDED: readFlowSample(sample, YES); break;
	case SFLCOUNTERS_SAMPLE_EXPANDED: readCountersSample(sample, YES); break;
	case SFLRTMETRIC: readRTMetric(sample); break;
	case SFLRTFLOW: readRTFlow(sample); break;
	default: skipTLVRecord(sample, sample->sampleType, getData32(sample), "sample"); break;
	}
      }
      else {
	switch(sample->sampleType) {
	case FLOWSAMPLE: readFlowSample_v2v4(sample); break;
	case COUNTERSSAMPLE: readCountersSample_v2v4(sample); break;
	default: receiveError(sample, "unexpected sample type", YES); break;
	}
      }
      sf_log(sample,"endSample   ----------------------\n");
    }
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
    sf_log(sample,"startDatagram =================================\n");
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
    sf_log(sample, "endDatagram   =================================\n");
    fflush(stdout);
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

#ifndef WIN32
  /* make socket non-blocking */
  int save_fd = fcntl(soc, F_GETFL);
  save_fd |= O_NONBLOCK;
  fcntl(soc, F_SETFL, save_fd);
#endif /* WIN32 */

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

#ifndef WIN32
  /* make socket non-blocking */
  int save_fd = fcntl(soc, F_GETFL);
  save_fd |= O_NONBLOCK;
  fcntl(soc, F_SETFL, save_fd);
#endif /* WIN32 */

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
  _________________     readPcapPacket        __________________
  -----------------___________________________------------------
*/




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
	|| type_len == 0x9100) {
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
    hdr.ts_sec = MyByteSwap32(hdr.ts_sec);
    hdr.ts_usec = MyByteSwap32(hdr.ts_usec);
    hdr.caplen = MyByteSwap32(hdr.caplen);
    hdr.len = MyByteSwap32(hdr.len);
  }
  
  if(fread(buf, hdr.caplen, 1, file) != 1) {
    fprintf(ERROUT, "unable to read pcap packet from %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
    exit(-34);
  }


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

/*________________---------------------------__________________
  ________________       lookupAddress       __________________
  ----------------___________________________------------------
*/

static int parseOrResolveAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family, int numeric)
{
  struct addrinfo *info = NULL;
  struct addrinfo hints = { 0 };
  hints.ai_socktype = SOCK_DGRAM; // constrain this so we don't get lots of answers
  hints.ai_family = family; // PF_INET, PF_INET6 or 0
  if(numeric) {
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  }
  int err = getaddrinfo(name, NULL, &hints, &info);
  if(err) {
    fprintf(ERROUT, "getaddrinfo() failed: %s", gai_strerror(err));
    /* try again if err == EAI_AGAIN? */
    return NO;
  }
  
  if(info == NULL) return NO;
  
  if(info->ai_addr) {
    // answer is now in info - a linked list of answers with sockaddr values.
    // extract the address we want from the first one. $$$ should perhaps
    // traverse the list and look for an IPv4 address since that is more
    // likely to work?
    switch(info->ai_family) {
    case PF_INET:
      {
	struct sockaddr_in *ipsoc = (struct sockaddr_in *)info->ai_addr;
	addr->type = SFLADDRESSTYPE_IP_V4;
	addr->address.ip_v4.addr = ipsoc->sin_addr.s_addr;
	if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
      }
      break;
    case PF_INET6:
      {
	struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
	addr->type = SFLADDRESSTYPE_IP_V6;
	memcpy(&addr->address.ip_v6, &ip6soc->sin6_addr, 16);
	if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
      }
      break;
    default:
      fprintf(ERROUT, "get addrinfo: unexpected address family: %d", info->ai_family);
      return NO;
      break;
    }
  }
  // free the dynamically allocated data before returning
  freeaddrinfo(info);
  return YES;
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

  if(parseOrResolveAddress(hoststr, (struct sockaddr *)&sa, &tgtIP, 0, 1) == NO) {
    return NO;
  }
  switch(tgtIP.type) {
  case SFLADDRESSTYPE_IP_V4:
    tgt = (SFForwardingTarget *)my_calloc(sizeof(SFForwardingTarget));
    tgt->addr = *(struct sockaddr_in *)&sa;
    tgt->addr.sin_port = htons(port);
    /* and open the socket */
    if((tgt->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
      fprintf(ERROUT, "socket open (for %s) failed: %s", hostandport, strerror(errno));
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
      fprintf(ERROUT, "socket open (for %s) failed: %s", hostandport, strerror(errno));
      return NO;
    }
    /* got this far, so must be OK */
    tgt6->nxt = sfConfig.forwardingTargets6;
    sfConfig.forwardingTargets6 = tgt6;
    break;

  default:
    fprintf(ERROUT, "unknown address type %s", hoststr);
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
  fprintf(ERROUT,"Copyright (c) InMon Corporation 2000-2011 ALL RIGHTS RESERVED\n");
  fprintf(ERROUT,"This software provided with NO WARRANTY WHATSOEVER\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"Usage: %s [-p port]\n", command);
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"%s version: %s\n", command, VERSION);
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"usage:\n");
  fprintf(ERROUT, "   -h | -?            -  this help message\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"forwarding:\n");
  fprintf(ERROUT, "   -f host/port       -  (forward sflow to another collector\n");
  fprintf(ERROUT, "                      -   ...repeat for multiple collectors)\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"txt output:\n");
  fprintf(ERROUT, "   -l                 -  (output in line-by-line CSV format)\n");
  fprintf(ERROUT, "   -g                 -  (output in 'grep-friendly' format)\n");
  fprintf(ERROUT, "   -H                 -  (output HTTP common log file format)\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"tcpdump output:\n");
  fprintf(ERROUT, "   -t                 -  (output in binary tcpdump(1) format)\n");
  fprintf(ERROUT, "   -r file            -  (read binary tcpdump(1) format)\n");
  fprintf(ERROUT, "   -x                 -  (remove all IPV4 content)\n");
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"NetFlow output:\n");
  fprintf(ERROUT, "   -c hostname_or_IP  -  (netflow collector host)\n");
  fprintf(ERROUT, "   -d port            -  (netflow collector UDP port)\n");
  fprintf(ERROUT, "   -e                 -  (netflow collector peer_as (default = origin_as))\n");
  fprintf(ERROUT, "   -s                 -  (disable scaling of netflow output by sampling rate)\n");
#ifdef SPOOFSOURCE
  fprintf(ERROUT, "   -S                 -  spoof source of netflow packets to input agent IP\n");
#endif
  fprintf(ERROUT,"\n");
  fprintf(ERROUT,"Filters:\n");
  fprintf(ERROUT, "   +v <vlans>         -  include vlans (e.g. +v 0-20,4091)\n");
  fprintf(ERROUT, "   -v <vlans>         -  exclude vlans\n");
  fprintf(ERROUT, "   -4                 -  listen on IPv4 socket only\n");
  fprintf(ERROUT, "   -6                 -  listen on IPv6 socket only\n");
  fprintf(ERROUT, "   +4                 -  listen on both IPv4 and IPv6 sockets\n");
  fprintf(ERROUT, "\n");
  fprintf(ERROUT,"General options:\n");
  fprintf(ERROUT, "   -k                 -  keep going on non-signal errors rather than aborting\n");
  fprintf(ERROUT, "\n");
  fprintf(ERROUT, "=============== Advanced Tools ==============================================\n");
  fprintf(ERROUT, "| sFlow-RT (real time)  - http://sflow-rt.com                               |\n");
  fprintf(ERROUT, "| sFlowTrend (FREE)     - http://www.inmon.com/products/sFlowTrend.php      |\n");
  fprintf(ERROUT, "| Traffic Sentinel      - http://www.inmon.com/support/sentinel_release.php |\n");
  fprintf(ERROUT, "=============================================================================\n");
}

/*_________________---------------------------__________________
  _________________   process_command_line    __________________
  -----------------___________________________------------------
*/

static void process_command_line(int argc, char *argv[])
{
  int arg = 1, in = 0;
  int i;
  int plus,minus;
  size_t len_str;

  /* set defaults */
  sfConfig.sFlowInputPort = 6343;
#ifdef WIN32
  sfConfig.listen4 = YES;
  sfConfig.listen6 = NO;
#else
  sfConfig.listen4 = NO;
  sfConfig.listen6 = YES;
#endif
  sfConfig.keepGoing = NO;

  /* walk though the args */
  while (arg < argc) {
    plus = (argv[arg][0] == '+');
    minus = (argv[arg][0] == '-');
    if(plus == NO && minus == NO) { instructions(*argv); exit(1); }
    in = argv[arg++][1];
    /* check first that options with/without arguments are correct */
    switch(in) {
    case 't':
    case 'l':
    case 'g':
    case 'H':
    case 'x':
    case 'e':
    case 's':
#ifdef SPOOFSOURCE
    case 'S':
#endif
    case '4':
    case '6':
    case 'k':
    case '?':
    case 'h': break;
    case 'p':
    case 'r':
    case 'z':
    case 'c':
    case 'd':
    case 'f':
    case 'v': if(arg < argc) break;
    default: instructions(*argv); exit(1);
    }

    switch(in) {
    case 'p': sfConfig.sFlowInputPort = atoi(argv[arg++]); break;
    case 't': sfConfig.outputFormat = SFLFMT_PCAP; break;
    case 'l': sfConfig.outputFormat = SFLFMT_LINE; break;
    case 'H': sfConfig.outputFormat = SFLFMT_CLF; break;
    case 'g': sfConfig.outputFormat = SFLFMT_SCRIPT; break;
    case 'r':
        len_str = strlen(argv[arg]); /* argv[arg] already null-terminated */
        sfConfig.readPcapFileName = my_calloc(len_str+1);
	memcpy(sfConfig.readPcapFileName, argv[arg++], len_str);
        break;
    case 'x': sfConfig.removeContent = YES; break;
    case 'c':
      {
	struct hostent *ent = gethostbyname(argv[arg++]);
	if(ent == NULL) {
	  fprintf(ERROUT, "netflow collector hostname lookup failed\n");
	  exit(-8);
        }
    	sfConfig.netFlowOutputIP.s_addr = ((struct in_addr *)(ent->h_addr_list[0]))->s_addr;
	sfConfig.outputFormat = SFLFMT_NETFLOW;
      }
      break;
    case 'd':
      sfConfig.netFlowOutputPort = atoi(argv[arg++]);
      sfConfig.outputFormat = SFLFMT_NETFLOW;
      break;
    case 'e': sfConfig.netFlowPeerAS = YES; break;
    case 's': sfConfig.disableNetFlowScale = YES; break;
#ifdef SPOOFSOURCE      
    case 'S': sfConfig.spoofSource = YES; break;
#endif
    case 'f':
      if(addForwardingTarget(argv[arg++]) == NO) exit(-35);
      sfConfig.outputFormat = SFLFMT_FWD;
      break;
    case 'v':
      if(plus) {
	/* +v => include vlans */
	sfConfig.gotVlanFilter = YES;
	parseVlanFilter(sfConfig.vlanFilter, YES, argv[arg++]);
      }
      else {
	/* -v => exclude vlans */
	if(! sfConfig.gotVlanFilter) {
	  /* when we start with an exclude list, that means the default should be YES */
	  for(i = 0; i < FILTER_MAX_VLAN; i++) sfConfig.vlanFilter[i] = YES;
	  sfConfig.gotVlanFilter = YES;
	}
	parseVlanFilter(sfConfig.vlanFilter, NO, argv[arg++]);
      }
      break;
    case '4':
      sfConfig.listenControlled = YES;
      sfConfig.listen4 = YES;
      sfConfig.listen6 = plus;
      break;
    case '6':
      sfConfig.listenControlled = YES;
      sfConfig.listen4 = NO;
      sfConfig.listen6 = YES;
      break;
    case 'k': sfConfig.keepGoing = YES; break;
    /* remaining are -h or -? */
    default: instructions(*argv); exit(0);
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

#ifdef WIN32
  WSADATA wsadata;
  WSAStartup(0xffff, &wsadata);
  /* TODO: supposed to call WSACleanup() on termination */
#endif

  /* read the command line */
  process_command_line(argc, argv);

#ifdef WIN32
  /* on windows we need to tell stdout if we want it to be binary */
  if(sfConfig.outputFormat == SFLFMT_PCAP) setmode(1, O_BINARY);
#endif

  /* reading from file or socket? */
  if(sfConfig.readPcapFileName) {
    if(strcmp(sfConfig.readPcapFileName, "-") == 0) sfConfig.readPcapFile = stdin;
    else sfConfig.readPcapFile = fopen(sfConfig.readPcapFileName, "rb");
    if(sfConfig.readPcapFile == NULL) {
      fprintf(ERROUT, "cannot open %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
      exit(-1);
    }
    readPcapHeader();
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
  if(sfConfig.netFlowOutputPort != 0 && sfConfig.netFlowOutputIP.s_addr != 0) openNetFlowSocket();
  /* if tcpdump format, write the header */
  if(sfConfig.outputFormat == SFLFMT_PCAP) writePcapHeader();
  if(sfConfig.readPcapFile) {
    /* just use a blocking read */
    while(readPcapPacket(sfConfig.readPcapFile));
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
