/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "util.h"
  
/*________________---------------------------__________________
  ________________       lookupAddress       __________________
  ----------------___________________________------------------
*/

int parseOrResolveAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family, int numeric)
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

  int my_readline(FILE *ff, char *buf, uint32_t len, int *p_truncated) {
    // read up to len-1 chars from line, but consume the whole line.
    // return number of characters read (0 for empty line), or EOF if file
    // was already at EOF. Always null-terminate the buffer. Indicate
    // number of truncated characters with the pointer provided.
    int ch;
    uint32_t count=0;
    bool atEOF=YES;
    bool bufOK=(buf != NULL
		&& len > 1);
    if(p_truncated)
      *p_truncated = 0;
    while((ch = getc(ff)) != EOF) {
      atEOF = NO;
      // EOL on CR, LF or CRLF
      if(ch == 10 || ch == 13) {
	if(ch == 13) {
	  // peek for CRLF
	  if((ch = getc(ff)) != 10)
	    ungetc(ch, ff);
	}
	break;
      }
      if(bufOK
	 && count < (len-1))
	buf[count++] = ch;
      else if(p_truncated)
	(*p_truncated)++;
    }
    if(bufOK)
      buf[count] = '\0';
    return atEOF ? EOF : count;
  }

  /*________________---------------------------__________________
    ________________    trimWhitespace         __________________
    ----------------___________________________------------------
  */
  
  char *trimWhitespace(char *str, uint32_t len)
  {
    // NULL -> NULL
    if(str == NULL)
      return NULL;
    
    // "" -> NULL
    if(len == 0
       || *str == '\0')
      return NULL;
    
    char *end = str + len - 1;

    // Trim leading space
    while(isspace(*str)) {
      // also return NULL for a string with only spaces in it
      // (don't want that condition to slip through unnoticed)
      if(++str > end)
	return NULL;
    }

    // Trim trailing space
    while(end > str
	  && isspace(*end))
      end--;

    // Write new null terminator
    *(end+1) = 0;

    return str;
  }

  /*________________---------------------------__________________
    ________________    parseNextTok           __________________
    ----------------___________________________------------------
  */

  static int isSeparator(char ch, char *separators) {
    if(separators == NULL) return NO;
    for(char *sep = separators; (*sep) != '\0'; sep++)
      if((*sep) == ch) return YES;
    return NO;
  }

  char *parseNextTok(char **str, char *sep, int delim, char quot, int trim, char *buf, int buflen)
  {
    if(str == NULL) return NULL;

    char *a = (*str);

    if(a == NULL) {
      // We hit EOS last time and indicated it by setting *str to NULL.
      // Last time we may have returned an empty string to indicate a
      // trailing delimiter (or the whole input was ""). This time
      // we terminate for sure.
      return NULL;
    }

    // initialize buffer to empty string
    buf[0] = '\0';

    if(a[0] == '\0') {
      // return the empty string and make sure we terminate next time
      *str = NULL;
      return buf;
    }

    int buflast = buflen-1;
    int len = 0;

    if(delim && isSeparator(a[0], sep)) {
      // leading delimiter, so don't advance - just allow an
      // empty-string token to be generated.  The delimiter
      // will be consumed below
    }
    else {
      if(!delim) {
	// skip separators
	while(a[0] != '\0' && isSeparator(a[0], sep)) a++;
      }
      if(a[0] == quot) {
	a++; // consume leading quote
	while(a[0] != '\0') {
	  if(a[0] == quot) {
	    a++; // consume it
	    if(a[0] != quot) break; // quotquot -> quot
	  }
	  if(len < buflast) buf[len++] = a[0];
	  a++;
	}
      }
      else {
	while(a[0] != '\0' && !isSeparator(a[0], sep)) {
	  if(len < buflast) buf[len++] = a[0];
	  a++;
	}
      }
    }
    buf[len] = '\0';

    if(!delim) {
      // skip separators again - in case there are no more tokens
      // and this takes us all the way to EOS
      while(a[0] != '\0' && isSeparator(a[0], sep)) a++;
    }

    if(a[0] == '\0') {
      // at EOS, so indicate to the caller that there are no more tokens after this one
      *str = NULL;
    }
    else {
      if(delim) {
	// since we got a token, we need
	// to consume the trailing delimiter if it is there
	if(isSeparator(a[0], sep)) a++;
	// this may mean we are at EOS now, but that implies
	// there is one more (empty-string) token,  so it's
	// correct.
      }
      *str = a;
    }

    return trim ? trimWhitespace(buf, len) : buf;
  }
  
#if defined(__cplusplus)
}  /* extern "C" */
#endif
