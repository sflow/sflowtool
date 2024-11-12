/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */
#ifndef SFLOW_UTIL_H
#define SFLOW_UTIL_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <netdb.h>
#include <ctype.h>
#include "sflow.h"

#define ERROUT stderr
#ifdef DEBUG
#define ERROR stdout
#endif

  typedef uint32_t bool;
#define YES 1
#define NO 0
  
  void *my_calloc(size_t bytes);
  void my_free(void *ptr);
  int parseOrResolveAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family, int numeric);
  int my_readline(FILE *ff, char *buf, uint32_t len, int *p_truncated);
  char *parseNextTok(char **str, char *sep, int delim, char quot, int trim, char *buf, int buflen);
  
  
#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_UTIL_H */
