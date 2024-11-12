/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */
#ifndef SFLOW_UTHASH_H
#define SFLOW_UTHASH_H 1

#if defined(__cplusplus)
extern "C" {
#endif

  #include "util.h"
  

  /*_________________---------------------------__________________
    _________________     hashing               __________________
    -----------------___________________________------------------
    Don't expose this directly, so we can swap them out easily for
    alternatives if we want to.
  */

#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U
  static uint32_t hash_fnv1a(const char *s, const uint32_t len)
  {
    uint32_t hash = FNV_OFFSET_32;
    for(uint32_t i = 0; i < len; i++) {
      hash ^= (s[i]);
      hash *= FNV_PRIME_32;
    }
    return hash;
  }

  uint32_t my_strhash(const char *str) {
    return hash_fnv1a(str, strlen(str));
  }

  bool my_strequal(const char *s1, const char *s2) {
    if(s1==s2)
      return YES;
    if(s1==NULL
       || s2==NULL)
      return NO;
    return (strcmp(s1,s2) == 0);
  }

  /*________________---------------------------__________________
    ________________        UTHash             __________________
    ----------------___________________________------------------
    A simple open-hash for structures, where the key is a field
    in the structure - either fixed-length or a null-terminated string.
  */

  // UTHash
  typedef struct _UTHash {
    void **bins;
    uint32_t f_offset;
    uint32_t f_len;
    uint32_t cap;
    uint32_t entries;
    uint32_t dbins;
    uint32_t options;
  } UTHash;

#define UTHASH_DFLT 0
#define UTHASH_SKEY 1
#define UTHASH_IDTY 4
  UTHash *UTHashNew(uint32_t f_offset, uint32_t f_len, uint32_t options);
#define UTHASH_NEW(t,f,o) UTHashNew(offsetof(t, f), sizeof(((t *)0)->f), (o))
  void UTHashFree(UTHash *oh);
  void *UTHashAdd(UTHash *oh, void *obj);
  void *UTHashGet(UTHash *oh, void *obj);
  void *UTHashGetOrAdd(UTHash *oh, void *obj);
  void *UTHashDel(UTHash *oh, void *obj);
  void *UTHashDelKey(UTHash *oh, void *obj);
  void UTHashReset(UTHash *oh);
   uint32_t UTHashN(UTHash *oh);

#define UTHASH_DBIN (void *)-1

#define UTHASH_WALK(oh, obj) for(uint32_t _ii=0; _ii<oh->cap; _ii++) if(((obj)=(typeof(obj))oh->bins[_ii]) && (obj) != UTHASH_DBIN)

#define UTHASH_INIT 8 // must be power of 2

#define UTHASH_BYTES(oh) ((oh)->cap * sizeof(void *))

  UTHash *UTHashNew(uint32_t f_offset, uint32_t f_len, uint32_t options) {
    UTHash *oh = (UTHash *)my_calloc(sizeof(UTHash));
    oh->options = options;
    oh->cap = UTHASH_INIT;
    oh->bins = my_calloc(UTHASH_BYTES(oh));
    oh->f_offset = (options & (UTHASH_IDTY)) ? 0 : f_offset;
    oh->f_len = (options & (UTHASH_SKEY|UTHASH_IDTY)) ? 0 : f_len;
    return oh;
  }

  static void *hashAdd(UTHash *oh, void *obj);

  static void hashRebuild(UTHash *oh, bool bigger) {
    uint32_t old_cap = oh->cap;
    void **old_bins = oh->bins;
    if(bigger) oh->cap *= 2;
    oh->bins = my_calloc(UTHASH_BYTES(oh));
    oh->entries = 0;
    oh->dbins = 0;
    for(uint32_t ii = 0; ii < old_cap; ii++)
      if(old_bins[ii] && old_bins[ii] != UTHASH_DBIN)
	hashAdd(oh, old_bins[ii]);
    my_free(old_bins);
  }

  static uint32_t hashHash(UTHash *oh, void *obj) {
    char *f = (char *)obj + oh->f_offset;
    if(oh->f_len) return hash_fnv1a(f, oh->f_len);
    else if(oh->options & UTHASH_IDTY) return (uint32_t)((uint64_t)obj);
    return my_strhash(*(char **)f);
  }

  static bool hashEqual(UTHash *oh, void *obj1, void *obj2) {
    char *f1 = (char *)obj1 + oh->f_offset;
    char *f2 = (char *)obj2 + oh->f_offset;
    return (oh->f_len)
      ? (!memcmp(f1, f2, oh->f_len))
      : ((oh->options & UTHASH_IDTY)
	 ? (obj1 == obj2)
	 : my_strequal(*(char **)f1, *(char **)f2));
  }

  // oh->cap is always a power of 2, so we can just mask the bits
#define UTHASH_WRAP(oh, pr) ((pr) & ((oh)->cap - 1))

static uint32_t hashSearch(UTHash *oh, void *obj, void **found) {
    uint32_t probe = hashHash(oh, obj);
    int32_t dbin = -1;
    probe = UTHASH_WRAP(oh, probe);
    for( ; oh->bins[probe]; probe=UTHASH_WRAP(oh,probe+1)) {
      void *entry = oh->bins[probe];
      if(entry == UTHASH_DBIN) {
	// remember first dbin
	if(dbin == -1)  dbin = probe;
	else if(dbin == probe) break; // all the way around!
      }
      else if(hashEqual(oh, obj, entry)) {
	(*found) = entry;
	return probe;
      }
    }
    // not found - reuse the dbin if we encountered one
    (*found) = NULL;
    return (dbin == -1) ? probe : dbin;
  }

  static void *hashAdd(UTHash *oh, void *obj) {
    if(obj == NULL) return NULL;
    // make sure there is room so the search cannot fail
    if(oh->entries >= (oh->cap >> 1))
      hashRebuild(oh, YES);
    // search for obj or empty slot
    void *found = NULL;
    uint32_t idx = hashSearch(oh, obj, &found);
    // put it here
    oh->bins[idx] = obj;
    if(!found) oh->entries++;
    // return what was there before
    return found;
  }

  void *UTHashAdd(UTHash *oh, void *obj) {
    void *overwritten;
    overwritten = hashAdd(oh, obj);
    return overwritten;
  }

  void *UTHashGet(UTHash *oh, void *obj) {
    if(obj == NULL) return NULL;
    void *found = NULL;
    hashSearch(oh, obj, &found);
    return found;
  }

  void *UTHashGetOrAdd(UTHash *oh, void *obj) {
    if(obj == NULL) return NULL;
    void *found = NULL;
    hashSearch(oh, obj, &found);
    if(!found)
      hashAdd(oh, obj);
    return found;
  }

  static void *hashDelete(UTHash *oh, void *obj, bool identity) {
    if(obj == NULL) return NULL;
    void *found = NULL;
    int idx = hashSearch(oh, obj, &found);
    if (found
	&& (found == obj
	    || identity == NO)) {
      oh->bins[idx] = UTHASH_DBIN;
      oh->entries--;
      if(++oh->dbins >= (oh->cap >> 1))
	hashRebuild(oh, NO);
    }
    return found;
  }

  void *UTHashDel(UTHash *oh, void *obj) {
    // delete this particular object
    return hashDelete(oh, obj, YES);
  }

  void *UTHashDelKey(UTHash *oh, void *obj) {
    // delete whatever is stored under this key
    return hashDelete(oh, obj, NO);
  }

  void UTHashReset(UTHash *oh) {
    memset(oh->bins, 0, UTHASH_BYTES(oh));
    oh->entries = 0;
    oh->dbins = 0;
   }

  uint32_t UTHashN(UTHash *oh) {
    return oh->entries;
  }

  void UTHashFree(UTHash *oh) {
    if(oh == NULL) return;
    my_free(oh->bins);
    my_free(oh);
  }

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_UTHASH_H */
