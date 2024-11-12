/* Copyright (c) 2002-2023 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_UNTAP_H
#define SFLOW_UNTAP_H 1


#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include "util.h"

  #define SFU_MAX_LINE 512
  
  typedef struct _SFUPort {
    SFLAddress addr;
    uint32_t port;
  } SFUPort;

  typedef struct _SFUntap {
    struct _SFUntap *nxt;
    SFUPort tap;
    SFUPort rx;
    SFUPort tx;
    uint32_t rx_seqNo;
    uint32_t tx_seqNo;
  } SFUntap;

  static UTHash *SFUntapLoad(char *path) {
    UTHash *taps = UTHASH_NEW(SFUntap, tap, UTHASH_DFLT);
    FILE *ff = fopen(path, "r");
    if(ff == NULL) {
      fprintf(ERROUT, "SFUntapLoad: cannot open %s : %s\n", path, strerror(errno));
    }
    else {
      char line[SFU_MAX_LINE];
      int truncated=0;
      while(my_readline(ff, line, SFU_MAX_LINE, &truncated) != EOF) {
	if(truncated) {
	  fprintf(ERROUT, "SFUntapLoad: line too long : %s\n", line);
	  continue;
	}
	printf("next line = %s\n", line);
	SFUntap untap = {};
	char *p = line;
	char *sep = " \t,=>";
	char quot = '"';
	char token[SFU_MAX_LINE];
	bool complete=NO;

#define GET_NEXT_TOK parseNextTok(&p, sep, NO, quot, YES, token, SFU_MAX_LINE)

	// expecting: tap-ip,tap-port,rx-ip,rx-port[,tx-ip,tx-port]
	// so that sFlow from datasource == "tap" is remapped to look
	// like it was sampled at ingress == "rx" (and optionally at egress == "tx")

	// tap rx
	if(GET_NEXT_TOK)
	  parseOrResolveAddress(token, NULL, &untap.tap.addr, 0, YES);
	if(GET_NEXT_TOK)
	  untap.tap.port = strtol(token, NULL, 0);
	if(GET_NEXT_TOK)
	  // tapped-link rx port
	  parseOrResolveAddress(token, NULL, &untap.rx.addr, 0, YES);
	if(GET_NEXT_TOK) {
	  untap.rx.port = strtol(token, NULL, 0);
	  complete = YES; // can stop here
	}
	// tapped-link tx port (optional)
	if(GET_NEXT_TOK)
	  parseOrResolveAddress(token, NULL, &untap.tx.addr, 0, YES);
	if(GET_NEXT_TOK)
	  untap.tx.port = strtol(token, NULL, 0);

	if(complete) {
	  SFUntap *tap = calloc(1, sizeof(*tap));
	  *tap = untap;
	  UTHashAdd(taps, tap);
	}
	else {
	  fprintf(ERROUT, "SFUntapLoad: line incomplete : %s\n", line);
	  continue;
	}
      }
      fclose(ff);
    }
    return taps;
  }
    

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_UNTAP_H */
