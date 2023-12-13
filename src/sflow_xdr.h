/* Copyright (c) 2002-2022 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_XDR_H
#define SFLOW_XDR_H 1

#if defined(__cplusplus)
extern "C" {
#endif

  // sFlow datagram encoding (XDR)
  // Multi-threading considerations:
  // The SFD* functions may require synchronization if the counter-samples are
  // supplied by a different thread than the packet samples or discards, but
  // the sfd_xdr_* functions operate on a separate SFDBuf that can always
  // be private to one thread. So theoretically several threads could work
  // on encoding samples in parallel and only the operations involving SFDDgram
  // would need a semaphore.
  
  // Set an upper-limit on the size of any flow/counter/discard sample.
#define SFD_MAX_SAMPLE_SIZE 512
#define SFD_MAX_SAMPLE_QUADS (SFD_MAX_SAMPLE_SIZE >> 2)
// Set an upper limit on the number of flow/counter/discard samples in one datagram.
#define SFD_MAX_DATAGRAM_SAMPLES 16
  // Set an upper limit on the nesting of XDR structures.
#define SFD_XDR_MAX_STACKDEPTH 16

  // #define SFD_ASSERT(x) assert(x)
#define SFD_ASSERT(x)

  // Each flow/counter/discard sample will be one SFDBuf which can
  // encode multiple nested elements within it. For example, a flow-sample
  // may contain the elements packet-header, extended-switch and extended-router.
  // Simularly, a counter-sample may contain generic-counters, ethernet-counters
  // and optical-counter elements.
  
  typedef struct _SFDBuf {
    struct _SFDBuf *nxt;
    uint32_t cursor;
    uint32_t nstack;
    uint32_t stack[SFD_XDR_MAX_STACKDEPTH];
    uint32_t xdr[SFD_MAX_SAMPLE_QUADS];
  } SFDBuf;

  // XDR encoding is quad-aligned, network-byte order.

  static void sfd_xdr_init(SFDBuf *buf) {
    buf->cursor = 0;
    buf->nstack = 0;
    buf->nxt = NULL;
  }

  static uint32_t *sfd_xdr_ptr(SFDBuf *buf) {
    return (buf->xdr + buf->cursor);
  }

  static void sfd_xdr_enc_int32(SFDBuf *buf, uint32_t val32) {
    SFD_ASSERT(buf->cursor < SFD_MAX_SAMPLE_QUADS-1);
    buf->xdr[buf->cursor++] = htonl(val32);
  }

  static void sfd_xdr_enc_int64(SFDBuf *buf, uint64_t val64) {
    uint32_t hi = (val64 >> 32);
    uint32_t lo = val64;
    sfd_xdr_enc_int32(buf, hi);
    sfd_xdr_enc_int32(buf, lo);
  }

  static void sfd_xdr_enc_float(SFDBuf *buf, float valf) {
    uint32_t val;
    memcpy(&val, &valf, 4);
    sfd_xdr_enc_int32(buf, val);
  }

  static void sfd_xdr_enc_dbl(SFDBuf *buf, double vald) {
    uint64_t val64;
    memcpy(&val64, &vald, 8);
    sfd_xdr_enc_int64(buf, val64);
  }

  static void sfd_xdr_enc_bytes(SFDBuf *buf, u_char *data, uint32_t len) {
    if(len) {
      uint32_t quads = (len + 3) >> 2;
      u_char *ptr = (u_char *)sfd_xdr_ptr(buf);
      buf->cursor += quads;
      SFD_ASSERT(buf->cursor < SFD_MAX_SAMPLE_QUADS-1);
      buf->xdr[buf->cursor] = 0; // Clear the 'landing pad' (so any pad bytes are 00s).
      memcpy(ptr, data, len);
    }
  }

  static void sfd_xdr_enc_str(SFDBuf *buf, const char *str, uint32_t len) {
    sfd_xdr_enc_int32(buf, len);
    sfd_xdr_enc_bytes(buf, (u_char *)str, len);
  }

  static void sfd_xdr_enc_mac(SFDBuf *buf, u_char *mac) {
    sfd_xdr_enc_bytes(buf, mac, 6);
  }

  static void sfd_xdr_enc_ip(SFDBuf *buf, SFLAddress *ip) {
    SFD_ASSERT(buf->cursor < (SFD_MAX_SAMPLE_QUADS-2));
    sfd_xdr_enc_int32(buf, ip->type);
    if(ip->type == SFLADDRESSTYPE_IP_V6)
      sfd_xdr_enc_bytes(buf, (u_char *)&ip->address.ip_v6.addr, 16);
    else
      sfd_xdr_enc_bytes(buf, (u_char *)&ip->address.ip_v4.addr, 4);
  }

  static void sfd_xdr_start_tlv(SFDBuf *buf, uint32_t tag) {
    SFD_ASSERT(buf->cursor < (SFD_MAX_SAMPLE_QUADS-2));
    SFD_ASSERT(buf->nstack < (SFD_XDR_MAX_STACKDEPTH-1));
    buf->xdr[buf->cursor++] = htonl(tag);
    buf->stack[buf->nstack++] = buf->cursor; // remember cursor offset
    buf->xdr[buf->cursor++] = htonl(0); // place-holder for length
  }

  static void sfd_xdr_end_tlv(SFDBuf *buf) {
    SFD_ASSERT(buf->nstack > 0);
    uint32_t c_len = buf->stack[--buf->nstack];
    SFD_ASSERT(c_len < (SFD_MAX_SAMPLE_QUADS-1));
    buf->xdr[c_len] = htonl((buf->cursor - c_len - 1) << 2);
  }

  // Datagram functions.

  // The datagram object knows how to encode the header and
  // compose datagrams with minimal copying.

  typedef void (*f_send_t)(void *magic, struct iovec *iov, int iovcnt);
  typedef uint64_t (*f_now_mS_t)(void *magic);
  typedef void *(*f_alloc_t)(void *magic, size_t bytes);
  typedef void (*f_free_t)(void *magic, void *obj);
  typedef void (*f_lock_t)(void *magic, int on);
  typedef void (*f_err_t)(void *magic, char *msg);
  
  typedef struct {
    SFLAddress agentAddress;
    uint32_t agentSubId;
    uint32_t dgramSeqNo;
    uint64_t bootTime_mS;
    uint64_t lastSend_mS;
    uint32_t dgramLen;
    uint32_t maxDgramLen;
    uint32_t cursor0;
    uint32_t headerLen;
    SFDBuf hdr;
    SFDBuf *bufs;
    uint32_t nsamples;
    SFDBuf *samples[SFD_MAX_DATAGRAM_SAMPLES];
    struct iovec iov[SFD_MAX_DATAGRAM_SAMPLES + 1];
    void *magic;
    f_send_t f_send;
    f_now_mS_t f_now_mS;
    f_alloc_t f_alloc;
    f_free_t f_free;
    f_lock_t f_lock;
    f_err_t f_err;
  } SFDDgram;

  static SFDDgram *SFDNew(uint32_t maxDgramLen,
			  SFLAddress *agentAddress,
			  uint32_t agentSubId,
			  void *magic,
			  f_alloc_t allocFn,
			  f_free_t freeFn,
			  f_now_mS_t nowFn,
			  f_send_t sendFn,
			  f_lock_t lockFn,
			  f_err_t errFn) {
    SFD_ASSERT(agentAddress->type == SFLADDRESSTYPE_IP_V4
	       || agentAddress->type == SFLADDRESSTYPE_IP_V6);
    SFD_ASSERT(allocFn != NULL);
    SFDDgram *sfdg = (SFDDgram *)allocFn(magic, sizeof(SFDDgram));
    memset(sfdg, 0, sizeof(*sfdg));
    sfdg->maxDgramLen = maxDgramLen;
    sfdg->agentAddress = *agentAddress;
    sfdg->agentSubId = agentSubId;
    sfdg->magic = magic;
    sfdg->f_alloc = allocFn;
    sfdg->f_free = freeFn;
    sfdg->f_now_mS = nowFn;
    sfdg->f_send = sendFn;
    sfdg->f_lock = lockFn;
    sfdg->f_err = errFn;
    sfdg->bootTime_mS = sfdg->f_now_mS(sfdg->magic);
    // We can do the first part of the header encoding here
    // because it is always the same.
    SFDBuf *hdr = &(sfdg->hdr);
    sfd_xdr_enc_int32(hdr, SFLDATAGRAM_VERSION5);
    sfd_xdr_enc_ip(hdr, &sfdg->agentAddress);
    sfd_xdr_enc_int32(hdr, sfdg->agentSubId);
    // Remember where we should reset to.
    sfdg->cursor0 = hdr->cursor;
    // And we already know what iov[0] will be
    // after we add three more fields...
    sfdg->headerLen = ((hdr->cursor + 3) << 2);
    sfdg->dgramLen = sfdg->headerLen;
    sfdg->iov[0].iov_base = hdr->xdr;
    sfdg->iov[0].iov_len = sfdg->headerLen;
    return sfdg;
  }

  // If lock fn supplied, it will be called for thread mutual-exclusion.
#define SFD_LOCK(dg,on) if((dg)->f_lock) (dg)->f_lock((dg)->magic, (on))

  // Datagram recycles xdr buffers, but only if allocated here.
#define SFD_RECYCLE (SFDBuf *)0xD1CEC0DE

  static SFDBuf *SFDSampleNew(SFDDgram *sfdg) {
    SFD_LOCK(sfdg, 1);
    SFDBuf *buf = sfdg->bufs;
    if(buf)
      sfdg->bufs = buf->nxt;
    else
     buf = (SFDBuf *)sfdg->f_alloc(sfdg->magic, sizeof(SFDBuf));
    sfd_xdr_init(buf);
    // Sheep-brand buf as coming from here.
    buf->nxt = SFD_RECYCLE;
    SFD_LOCK(sfdg, 0);
    return buf;
  }

  static void SFDSend_nolock(SFDDgram *sfdg) {
    // Something to send?
    if(sfdg->nsamples == 0)
      return;
    // Get timestamp.
    sfdg->lastSend_mS = sfdg->f_now_mS(sfdg->magic);
    // Complete the header.
    SFDBuf *hdr = &(sfdg->hdr);
    hdr->cursor = sfdg->cursor0;
    sfd_xdr_enc_int32(hdr, ++sfdg->dgramSeqNo);
    sfd_xdr_enc_int32(hdr, (sfdg->lastSend_mS - sfdg->bootTime_mS));
    sfd_xdr_enc_int32(hdr, sfdg->nsamples);
    // Send out datagram.
    sfdg->f_send(sfdg->magic, sfdg->iov, sfdg->nsamples + 1);
    // And reset.
    // Recycle bufs if they were mine.
    // TODO: should maybe insist that they be mine?
    for(uint32_t ii=0; ii<sfdg->nsamples; ii++) {
      SFDBuf *buf = sfdg->samples[ii];
      if(buf->nxt == SFD_RECYCLE) {
	buf->nxt = sfdg->bufs;
	sfdg->bufs = buf;
      }
      else if(sfdg->f_err)
	sfdg->f_err(sfdg->magic, "sample not allocated by SFDSampleNew");
    }
    // And reset for next datagram.
    sfdg->nsamples = 0;
    sfdg->dgramLen = sfdg->headerLen;
  }

  static void SFDSend(SFDDgram *sfdg) {
    SFD_LOCK(sfdg, 1);
    SFDSend_nolock(sfdg);
    SFD_LOCK(sfdg, 0);
  }

  static uint64_t SFDLastSend_mS(SFDDgram *sfdg) {
    return sfdg->lastSend_mS;
  }
  
  static void SFDAddSample(SFDDgram *sfdg, SFDBuf *buf) {
    SFD_LOCK(sfdg, 1);
    SFD_ASSERT(buf->nstack == 0);
    SFD_ASSERT(sfdg->nsamples <= SFD_MAX_DATAGRAM_SAMPLES);
    // May need to send what we have first.
    uint32_t len = (buf->cursor << 2);
    if((sfdg->dgramLen + len) >= sfdg->maxDgramLen)
      SFDSend_nolock(sfdg);
    // Count the samples that are submitted.
    sfdg->samples[sfdg->nsamples++] = buf;
    // Add to iovec.
    sfdg->iov[sfdg->nsamples].iov_base = buf->xdr;
    sfdg->iov[sfdg->nsamples].iov_len = len;
    // Update datagram length.
    sfdg->dgramLen += len;
    SFD_LOCK(sfdg, 0);
  }

  static void SFDFree(SFDDgram *sfdg) {
    SFD_ASSERT(sfdg->f_free != NULL);
    for(uint32_t ii=0; ii<sfdg->nsamples; ii++) {
      SFDBuf *buf = sfdg->samples[ii];
      if(buf->nxt == SFD_RECYCLE)
	sfdg->f_free(sfdg->magic, buf);
    }
    sfdg->f_free(sfdg->magic, sfdg);
  }
    

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_XDR_H */
