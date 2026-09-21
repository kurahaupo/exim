/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
Copyright © The Exim Maintainers 2026
Copyright © Jeremy Harris 2026
See the file NOTICE for conditions of use and distribution.
SPDX-License-Identifier: GPL-2.0-or-later
*/

/* Sieve filter "body" input processing.
Stackable layers for quoted-printable and base64 decoding.
*/

#include "../exim.h"
#include "sieve_filter.h"

#define DECODE_LAYER_DEBUG		if (FALSE)

#define DECODE_OK	0
#define DECODE_NOCHAR	-1
#define DECODE_MORE	-2
#define DECODE_ERROR	-3

#define D_BUF_SIZE	4096 /* For testing buf boundaries, go short, eg. 14 */

/******************************************************************************/

static BOOL
cmn_hasc(const in_processing * inp)
{
return inp->in_bufp->ptr < inp->in_bufp->end;
}

/* _getbuf() hauls into the layer buffer, limited by the req len (and the
buffer size), returning the actual avail len and a start ptr.
If there was leftover data in the layer buf, that is returned instead.
The buffer ptrs are left in the "all consumed" state.
*/



/* _getbuf_nr() is like _getbuf() except that:
- uncomsumed data is first relocated to the start of the layer buffer
  (done in the _releasebuf() op)
- refill appends to unconsumed
- buffer data in not marked as consumed. */

static const uschar *
cmn_getbuf_nr(const in_processing * inp, unsigned * lenp,
  BOOL (*refill)(const in_processing *, unsigned))
{
unsigned len = *lenp, size;
in_buf * bp = inp->in_bufp;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: req len %u\n", inp->in_layer_name, len);
DECODE_LAYER_DEBUG
  debug_printf_indent(" - ptr +%d  end +%d\n",
    (int)(bp->ptr - bp->buf),
    (int)(bp->end - bp->buf));

/* If the buffer has no outstanding data, or data is at the base of the buffer,
top up with more data. If none available, indicate EOF. */

if (!cmn_hasc(inp) || bp->ptr == bp->buf)
  if (!refill(inp, len)) { *lenp = 0; return NULL; }

if ((size = bp->end - bp->ptr) > len) size = len;
*lenp = size;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: got %u %.*q\n", inp->in_layer_name,
    size, (int)size, bp->ptr);
DECODE_LAYER_DEBUG
  debug_printf_indent(" - ptr +%d  end +%d, %u buffered\n",
    (int)(bp->ptr - bp->buf), (int)(bp->end - bp->buf),
    (unsigned)(bp->end - bp->ptr));

return bp->ptr;
}


/* Consume (some of) the data indicated by getbuf_nr. Copy any remaining down
to the base of the buffer. */

void
cmn_releasebuf(const in_processing * inp, unsigned consumed)
{
in_buf * bp = inp->in_bufp;
const uschar * s = bp->ptr + consumed;
unsigned ncopy;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: notify %u\n", inp->in_layer_name, consumed);
DECODE_LAYER_DEBUG
  debug_printf_indent(" - was ptr +%d  end +%d, %u buffered: %.*q\n",
    (int)(bp->ptr - bp->buf), (int)(bp->end - bp->buf),
    (unsigned)(bp->end - bp->ptr),
    (int)(bp->end - bp->ptr), bp->ptr
    );

if (s > bp->end)
  log_write(LOG_PANIC_DIE, "%s: overlarge consumed count %u", __FUNCTION__, consumed);

/* If less than some arbitrary small amout remains uncomsumed, copy down
to the buffer base. */

if ((ncopy = bp->end - s) > 0 && ncopy < 16)
  memmove(bp->buf, s, (size_t)ncopy);
bp->ptr = bp->buf;
bp->end = bp->buf + ncopy;

DECODE_LAYER_DEBUG
  debug_printf_indent(" - now ptr +%d  end +%d, %u buffered: %.*q\n",
    (int)(bp->ptr - bp->buf), (int)(bp->end - bp->buf),
    (unsigned)(bp->end - bp->ptr),
    (int)(bp->end - bp->ptr), bp->ptr
    );
}


static int
cmn_ferror(const in_processing * inp)
{
return !inp->in_bufp->ptr || inp_ferror(inp->in_lower);
}

/******************************************************************************/
/* qp & b64 decode layers */

static in_buf decode_buf;

static void
conform_check(const in_processing * inp, const char * where)
{
if (ANY_DEBUG || f.running_in_test_harness)
  if (  Ustrcmp(rx_prc->in_layer_name, "stdin") != 0
     && Ustrcmp(rx_prc->in_layer_name, "mime") != 0)
    log_write(LOG_PANIC_DIE,
              "%s: bad substrate %s", where, inp->in_layer_name);
}

const in_processing *
cmn_push_receive_functions(const in_processing * inp,
  const in_processing * tmpl, const char * where)
{
static in_processing cmn_layer;
in_buf * bp;

conform_check(inp, where);

cmn_layer = *tmpl;
cmn_layer.in_lower = inp;
bp = cmn_layer.in_bufp;

if (!bp->buf) bp->buf = store_get(D_BUF_SIZE, GET_TAINTED);
bp->end = bp->ptr = bp->buf;

return &cmn_layer;
}

/******************************************************************************/
/* Quoted-printable */


/* Decode one QP coded unit.  Called once the flag = has been spotted.
Update the source pointer and the remaining source bytecount on a good
return.  Return either the decoded char or a status code for various types
of unhandled situations.
*/

static int
decode_qp(const uschar ** srcp, unsigned * limp)
{
const uschar * src = *srcp;
unsigned lim = *limp;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s %d: decode_qp() lim %u\n", __FUNCTION__, __LINE__,
		      lim);

if (--lim == 0)
  return DECODE_MORE;

/* Is it two hex digits following the = ? */

if (isxdigit(*src))
  if (lim > 1)
    if (isxdigit(src[1]))
      {
      /* Do hex conversion */
      uschar b = *src++;
      uschar c = (isdigit(b) ? b - '0' : toupper(b) - 'A' + 10) <<4;
      b = *src++;
      c |= isdigit(b) ? b - '0' : toupper(b) - 'A' + 10;
      *srcp = src;
      *limp = lim - 2;
      return (int)c;
      }
    else
      return DECODE_ERROR;	/* error */
  else
    return DECODE_MORE;		/* end of buffer; indeterminate */

/* Not hexdigit */
/* Whitespace may follow; just ignore it if it precedes \n */

while (*src == '\t' || *src == ' ' || *src == '\r')
  if (lim--)
    src++;
  else
    return DECODE_MORE;		/* end of buffer; indeterminate */

if (*src == '\n')	/* hit soft line break */
  {
  *srcp = ++src;
  *limp = --lim;
  return DECODE_NOCHAR;
  }

return DECODE_ERROR;		/* illegal char here */
}


static BOOL
qp_refill(const in_processing * inp, unsigned lim)
{
const uschar * src, * src_start, * src_end;
unsigned nsrc = MIN(lim, D_BUF_SIZE);
in_buf * bp = inp->in_bufp;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: lim %u\n", __FUNCTION__, lim);

bp->end = bp->ptr = bp->buf;

expand_level++;
src_start = inp_getbuf_nr(inp->in_lower, &nsrc);
src_end = src_start + nsrc;
expand_level--;
if (!src_start)
  return FALSE;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: lwr offered %u %.*q\n", __FUNCTION__,
		      nsrc, (int)nsrc, src_start);

for (src = src_start; src < src_end; )
  {
  int ch = *src++;

  if (ch != '=')
    {
    *bp->end++ = ch;			/* not a flag ch; copy verbatim */
    nsrc--;				/* consumed one inchar */
    }
  else
    switch (ch = decode_qp(&src, &nsrc))	/* try for one decoded ch */
      {
      case DECODE_ERROR:
	FDEBUG debug_printf_indent("%s: decode error\n", inp->in_layer_name);
	goto bad_decode;

      case DECODE_MORE:			/* buffer exhausted; indeterminate. */
	src = src_end;		/* Break loop without consuming any input. */
	break;

      case DECODE_NOCHAR:		/* no output result char */
	break;

      default:	*bp->end++ = ch;	/* decoded ch output */
	break;
      }
  }

/* Tell the substrate layer how much we consumed */

nsrc = (unsigned)(src_end - src_start) - nsrc;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: %u src bytes consumed, %u res bytes\n", __FUNCTION__,
		      nsrc, (unsigned)(bp->end - bp->ptr));

inp_releasebuf(inp->in_lower, nsrc);
if (nsrc > 0)
  return TRUE;

FDEBUG debug_printf_indent("%s: incomplete input\n", inp->in_layer_name);

bad_decode:
  bp->ptr = NULL;	/* flag error state */
  return FALSE;
}

static const uschar *
qp_getbuf_nr(const in_processing * inp, unsigned * lenp)
{
return cmn_getbuf_nr(inp, lenp, qp_refill);
}


static in_processing qp_template = {
  .in_layer_name =	US"qp",
  .in_bufp =		&decode_buf,
  .in_getbuf_nr =	qp_getbuf_nr,
  .in_releasebuf =	cmn_releasebuf,
  .in_ferror =		cmn_ferror,
};

const in_processing *
qp_push_receive_functions(const in_processing * inp)
{
return cmn_push_receive_functions(inp, &qp_template, __FUNCTION__);
}



/******************************************************************************/
/* Base-64 */

/* Table copied from base64.c */
static uschar dec64table[] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, /*  0-15 */
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, /* 16-31 */
  255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63, /* 32-47 */
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255, /* 48-63 */
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 64-79 */
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255, /* 80-95 */
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 96-111 */
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255  /* 112-127*/
};

/* Code massaged from b64decode().  Consider moving fn to base64.c */
/* Decode one group of input, and write to output.  Update both pointers
on success.  Return 0 for success, or an error code.
*/

static int
decode_b64(const uschar ** srcp, const uschar * src_end, uschar ** dstp)
{
const uschar * src = *srcp;
uschar * dst = *dstp;
int x, y;

while (isspace(x = *src++))			/* in 1 */
  if (src >= src_end) return DECODE_MORE;
if (x > 127 || (x = dec64table[x]) == 255)
  return DECODE_ERROR;

while (isspace(y = *src++))			/* in 2 */
  if (src >= src_end) return DECODE_MORE;
if (y > 127 || (y = dec64table[y]) == 255)
  return DECODE_ERROR;

*dst++ = (x << 2) | (y >> 4);				/* out 1 */

while (isspace(x = *src++))			/* in 3 */
  if (src >= src_end) return DECODE_MORE;
if (x == '=')         /* endmarker, but there should be another */
  {
  while (isspace(x = *src++))
    if (src >= src_end) return DECODE_MORE;
  if (x != '=') return DECODE_ERROR;

  /* The coding in b64decode() checks for only whitespace between here
  and end-of-input here.  We can check vs. end-of-block, but that is a
  weaker test. */

  while (isspace(y = *src++))
    if (src >= src_end) goto ok;
  return DECODE_ERROR;
  }
if (x > 127 || (x = dec64table[x]) == 255) return DECODE_ERROR;
*dst++ = (y << 4) | (x >> 2);				/* out 2 */

while (isspace(y = *src++))			/* in 4 */
  if (src >= src_end) return DECODE_MORE;
if (y == '=')			/* endmarker, only whitespace permitted after */
  {
  while (isspace(y = *src++))
    if (src >= src_end) goto ok;
  return DECODE_ERROR;
  }
if (y > 127 || (y = dec64table[y]) == 255) return DECODE_ERROR;
*dst++ = (x << 6) | y;					/* out 3 */

ok:
  *srcp = src;
  *dstp = dst;
  return DECODE_OK;
}


static BOOL
b64_refill(const in_processing * inp, unsigned lim)
{
const uschar * src, * src_start, * src_end;
unsigned nsrc = MIN(lim, D_BUF_SIZE);
in_buf * bp = inp->in_bufp;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: lim %u\n", __FUNCTION__, lim);

bp->end = bp->ptr = bp->buf;

expand_level++;
src_start = inp_getbuf_nr(inp->in_lower, &nsrc);
src_end = src_start + nsrc;
expand_level--;
if (!src_start)
  return FALSE;

for (src = src_start; src < src_end; )
  switch (decode_b64(&src, src_end, &bp->end))
    {
    case DECODE_ERROR:
      FDEBUG debug_printf_indent("%s: decode error\n", inp->in_layer_name);
      goto bad_decode;

    case DECODE_MORE:			/* buffer exhausted; indeterminate. */
      src = src_end;		/* Break loop without consuming any input. */
      break;
    }

/* Tell the substrate layer how much we consumed */

nsrc = src - src_start;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: %u src bytes consumed, %u res bytes\n", __FUNCTION__,
		      nsrc, (unsigned)(bp->end - bp->ptr));

inp_releasebuf(inp->in_lower, nsrc);
if (nsrc > 0)
  return TRUE;

bad_decode:
  bp->ptr = NULL;	/* flag error state */
  return FALSE;
}


static const uschar *
b64_getbuf_nr(const in_processing * inp, unsigned * lenp)
{
return cmn_getbuf_nr(inp, lenp, b64_refill);
}

static in_processing b64_template = {
  .in_layer_name =	US"b64",
  .in_bufp =		&decode_buf,
  .in_getbuf_nr =	b64_getbuf_nr,
  .in_releasebuf =	cmn_releasebuf,
  .in_ferror =		cmn_ferror
};


const in_processing *
b64_push_receive_functions(const in_processing * inp)
{
return cmn_push_receive_functions(inp, &b64_template, __FUNCTION__);
}

/******************************************************************************/
#if HAVE_ICONV
/* Charset transform */

/*XXX will we ever need to be running multiple iconv' in parallel?
As in, for the nested mime uppacking?
Maybe add the buffer access to the layer "private" context.
*/

static BOOL
iconv_refill(const in_processing * inp, unsigned lim)
{
unsigned inlen = GETC_BUFFER_UNLIMITED;
const uschar * in;
uschar * out;
size_t inbytes, outbytes, res;
iconv_t icd = inp->in_private;
in_buf * bp = inp->in_bufp;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: lim %u\n", __FUNCTION__, lim);

/* Get a ref to data from below.  If none, return EOF */

expand_level++;
in = inp_getbuf_nr(inp->in_lower, &inlen);
expand_level--;
if (!in) return FALSE;

inbytes = (size_t)inlen;
out = bp->end;
if ((outbytes = D_BUF_SIZE - (bp->end - bp->ptr)) > lim)
  outbytes = lim;

res = iconv(icd, (ICONV_ARG2_TYPE) &in, &inbytes, C(&out), &outbytes);
if (res == -1)
  {
  FDEBUG debug_printf_indent("iconv: %s\n", strerror(errno));
  goto bad;
  }

/* If no conversion result and our buf is empty, error */
if (inbytes == inlen && bp->ptr == bp->end)
  {
  FDEBUG debug_printf_indent("iconv: trailing partial input\n");
  goto bad;
  }

bp->end = out;
inlen -= inbytes;                       /* number consumed */

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: %u src bytes consumed, %u res bytes\n", __FUNCTION__,
                      inlen, (unsigned)(bp->end - bp->ptr));

expand_level++;
inp_releasebuf(inp->in_lower, inlen);
expand_level--;
if (inlen > 0)
  return TRUE;

bad:
  bp->ptr = NULL;                           /* flag as error */
  return FALSE;
}

static const uschar *
iconv_getbuf_nr(const in_processing * inp, unsigned * lenp)
{
return cmn_getbuf_nr(inp, lenp, iconv_refill);
}



static const in_processing *
iconv_pop(const in_processing * inp)
{
iconv_t icd = inp->in_private;
(void) iconv_close(icd);
return inp->in_lower;
}


static in_buf iconv_buf;

static in_processing iconv_template = {
  .in_layer_name =	US"iconv",
  .in_bufp =		&iconv_buf,
  .in_getbuf_nr =	iconv_getbuf_nr,
  .in_releasebuf =	cmn_releasebuf,
  .in_ferror =		cmn_ferror,
  .in_pop =		iconv_pop
};

const in_processing *
iconv_push_receive_functions(const in_processing * inp, const uschar * s_chset)
{
in_processing * new = NULL;
iconv_t icd;
in_buf * bp;

if ((icd = iconv_open("utf-8", C(s_chset))) != (iconv_t)-1)
  {
  new = store_get(sizeof(in_processing), GET_UNTAINTED);

  *new = iconv_template;
  new->in_private = icd;
  new->in_lower = inp;

  bp = new->in_bufp;
  if (!bp->buf) bp->buf = store_get(D_BUF_SIZE, GET_TAINTED);
  bp->end = bp->ptr = bp->buf;
  }
else
  FDEBUG debug_printf_indent("iconv_open(%q, %q) failed: %s%s\n",
        "utf-8", s_chset, strerror(errno),
        errno == EINVAL ? " (maybe unsupported conversion)" : "");

return new;
}

#endif	/*HAVE_ICONV*/
/******************************************************************************/

/* A processing layer for mime-parts.
This handles one layer of mime nesting, and is stackable.
We search for the mime boundary in the data from our substrate, and treat
that as a temporary end-of-data for our client layer. */

typedef struct {
  const pcre2_code *	re;
  pcre2_match_context * mctx;
  pcre2_match_data *	md;
  int			dfa_wspace[SIEVE_BODY_REGEX_WORK_SIZE];
  uint32_t		matchopt;

  uint32_t		boundary_distance;
  const uschar *	lwr_end;
} mime_ctx_t;


/* getbuf_nr a whole load from below, and run the regex against that. */

static BOOL
mime_refill(const in_processing * inp, unsigned lim)
{
in_buf * bp = inp->in_bufp;
const uschar * src_start, * src_end;
unsigned nsrc = MIN(lim, D_BUF_SIZE);
mime_ctx_t * mc = inp->in_private;
int rc;

DECODE_LAYER_DEBUG
  debug_printf_indent("%s: lim %u\n", __FUNCTION__, lim);

expand_level++;
src_start = inp_getbuf_nr(inp->in_lower, &nsrc);
mc->lwr_end = src_end = src_start + nsrc;
expand_level--;
if (!src_start)			/* Error or EOF */
  return FALSE;

DECODE_LAYER_DEBUG debug_printf_indent("%s: lwr offered %u %.*q\n",
				      __FUNCTION__, nsrc, (int)nsrc, src_start);

bp->buf = bp->ptr = bp->end = W(src_start);

if (mc->boundary_distance == 0)
  {
  DECODE_LAYER_DEBUG debug_printf_indent(
    "%s: previously seen boundary; return EOF\n", __FUNCTION__);
  return FALSE;
  }

if (nsrc == 0)			/* no data currently; shortcut a ret no-match */
  {				/* likely for a clear_boundary op */
  mc->matchopt &= ~PCRE2_DFA_RESTART;
  return TRUE;
  }

rc = pcre2_dfa_match(
      mc->re,			/* result of pcre2_compile() */
      src_start,		/* the subject string */
      nsrc,			/* the length of the subject string */
      0,			/* start at offset 0 in the subject */
      mc->matchopt,		/* options */
      mc->md,			/* the match data block */
      mc->mctx,			/* a match context; NULL means use defaults */
      mc->dfa_wspace,		/* working space vector */
      SIEVE_BODY_REGEX_WORK_SIZE); /* number of elements (NOT size in bytes) */

DECODE_LAYER_DEBUG
  if (rc >= 0)
    debug_printf_indent("%s %d: rc %d\n", __FUNCTION__, __LINE__, rc);
  else
    {
    pcre2_get_error_message(rc, big_buffer, big_buffer_size);
    debug_printf_indent("%s %d: rc %d %q\n", __FUNCTION__, __LINE__,
			rc, big_buffer);
    }

/* If we matched a boundary, set our buffer pointers to indicate the
preceding data and the fill is done.  For a partial match, ditto (but
remember the partial state. For no match, indicate all the data (and remember
the state).
XXX what if a partial-match turns out later to be a nomatch?  For that case
we want to not return any data that includes the boundary (ok, we don't anyway)
nor consume it (no?  why not?).  Oh, but on seeing the nomatch, *then* we want
to return it as data. So we must not consume it, at partial-match time.
So we must check the partial status when our consume is called, and only
add the boundary on a full-match to the amount we consume in our substrate.
*/

if (rc > 0)
  {
  /* Our RE had the boundary, so the match returned says where the pre-boundary
  data ends. We want to indicate the pre-boundary data to our caller. */
  const PCRE2_SIZE * ovec = pcre2_get_ovector_pointer(mc->md);
  bp->end = W(src_start) + ovec[0];
  mc->matchopt = PCRE2_PARTIAL_SOFT | PCRE2_DFA_SHORTEST | PCRE2_NOTEMPTY;
  mc->boundary_distance = ovec[0];
  DECODE_LAYER_DEBUG debug_printf_indent("set boundary_distance %u\n",
					    (unsigned)mc->boundary_distance);
  return TRUE;
  }

switch (rc)
  {
  case PCRE2_ERROR_NOMATCH:
    bp->end = W(src_end);			/* return all the data */
    mc->matchopt &= ~PCRE2_DFA_RESTART;
    return TRUE;

  case PCRE2_ERROR_PARTIAL:
    {
    /* We *hope* that "longest partial match", for the spec of the returned
    match does not include a lookahead assertion. So it should be safe to
    return that. */
    const PCRE2_SIZE * ovec = pcre2_get_ovector_pointer(mc->md);
    bp->end = W(src_start) + ovec[1];
    mc->matchopt |= PCRE2_DFA_RESTART;
    return TRUE;
    }

  default:
    /* NB: if we get PCRE2_ERROR_DFA_RECURSE here, the workspace was not big enough */
    FDEBUG
      {
      pcre2_get_error_message(rc, big_buffer, big_buffer_size);
      debug_printf_indent("match: %.200s\n", big_buffer);
      }
    bp->ptr = NULL;		/* set error condition */
    return FALSE;
  }
}

static const uschar *
mime_getbuf_nr(const in_processing * inp, unsigned * lenp)
{
return cmn_getbuf_nr(inp, lenp, mime_refill);
}

static void
mime_releasebuf_cmn(const in_processing * inp, unsigned consumed)
{
in_buf * bp = inp->in_bufp;
mime_ctx_t * mc = inp->in_private;

expand_level++;
inp_releasebuf(inp->in_lower, consumed);
expand_level--;

/* Refresh "our" buffer pointers, as we just refer to the layer below and
the release just done may have changed them. */

DECODE_LAYER_DEBUG debug_printf_indent("%s - refresh buffer pointers\n",
				      __FUNCTION__);
expand_level++;
 {
  unsigned nsrc = 0;
  mc->lwr_end = bp->ptr = bp->buf = W(inp_getbuf_nr(inp->in_lower, &nsrc));
  if (!bp->ptr)					/* ensure non-error state */
    bp->ptr = bp->end = bp->buf = (void *) 1;
 }
expand_level--;
}

static void
mime_releasebuf(const in_processing * inp, unsigned consumed)
{
in_buf * bp = inp->in_bufp;
mime_ctx_t * mc = inp->in_private;

if (bp->ptr)				/* check for error-state */
  {
  DECODE_LAYER_DEBUG
    {
    debug_printf_indent("%s: %u\n", __FUNCTION__, consumed);
    debug_printf_indent("%s - was inptr +%d  inend +%d, %u buffered: %.*q\n",
	__FUNCTION__,
	(int)(bp->ptr - bp->buf), (int)(bp->end - bp->buf),
	(unsigned)(bp->end - bp->ptr),
	(int)(bp->end - bp->ptr), bp->ptr
	);
    debug_printf_indent("boundary_distance was %u\n",
			(unsigned)mc->boundary_distance);
    }

  mime_releasebuf_cmn(inp, consumed);
  mc->boundary_distance -= consumed;
  DECODE_LAYER_DEBUG debug_printf_indent("boundary_distance now %u\n",
					  (unsigned)mc->boundary_distance);
  }
}


static in_processing mime_template = {
  .in_layer_name =	US"mime",
  .in_getbuf_nr =	mime_getbuf_nr,
  .in_releasebuf =	mime_releasebuf,
  .in_ferror =		cmn_ferror,
};

const in_processing *
mime_push_receive_functions(const in_processing * inp,
  const pcre2_code * re, pcre2_match_context * mctx, pcre2_match_data * md)
{
in_processing * new = store_get(sizeof(in_processing) + sizeof(in_buf)
				+ sizeof(mime_ctx_t), GET_UNTAINTED);
in_buf * bp = (in_buf *)(new + 1);
mime_ctx_t * mc = (mime_ctx_t *)(bp + 1);

DECODE_LAYER_DEBUG debug_printf_indent("%s\n", __FUNCTION__);

*new = mime_template;
new->in_private = mc;
new->in_bufp = bp;
new->in_lower = inp;
bp->buf = bp->ptr = bp->end = (void *) 1;			/* non-error status */
mc->re = re;
mc->mctx = mctx;
mc->md = md;
mc->matchopt = PCRE2_PARTIAL_SOFT | PCRE2_DFA_SHORTEST | PCRE2_NOTEMPTY;
mc->boundary_distance = UINT_MAX;
mc->lwr_end = NULL;

return new;
}

int
mime_clear_boundary(const in_processing * inp)
{
unsigned consumed = 0;
in_buf * bp = inp->in_bufp;
mime_ctx_t * mc = inp->in_private;
const uschar * s;
int yield;

DECODE_LAYER_DEBUG debug_printf_indent("%s: consume boundary\n", __FUNCTION__);

if (!bp->ptr || !mc->lwr_end)
  return SIEVE_MIME_BOUNDARY_ERROR;

/* A boundary has a possible leading newline, then runs to the next newline
(inclusive).  NB: lwr_end is only valid for one call here, until after the next
getbuf_nr. */

if (*(s = bp->ptr) == '\n' && s < mc->lwr_end)
  s++, consumed++;
for (; s < mc->lwr_end; s++)
  { consumed++; if (*s == '\n') break; }

if (s == mc->lwr_end)
  yield = SIEVE_MIME_BOUNDARY_EOD;
else
  {
  uschar c = '\0';
  /* Scan back from the end looking for the "--" that a last-boundary has */

  while (--s > bp->ptr +1 && ((c = *s) == '\n' || c == ' ' || c == '\t'))
    ;

  yield = c == '-' && *--s == '-'
    ?  SIEVE_MIME_BOUNDARY_LAST : SIEVE_MIME_BOUNDARY_NONLAST;
  }

DECODE_LAYER_DEBUG
  {
  debug_printf_indent("%s: consume %u\n", __FUNCTION__, consumed);

  if (mc->boundary_distance != 0)
    debug_printf_indent("boundary_distance was %u\n",
			  (unsigned)mc->boundary_distance);
  }

mime_releasebuf_cmn(inp, consumed);
mc->boundary_distance = UINT_MAX;
mc->lwr_end = NULL;				/* enforce no repeat calls */
return yield;
}


/******************************************************************************/


/* End of sieve_filter_input.c */
/* vi: aw ai sw=2
*/
