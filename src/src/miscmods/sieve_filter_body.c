/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
Copyright (c) The Exim Maintainers 2026
Copyright (c) Jeremy Harris 2026
See the file NOTICE for conditions of use and distribution.
SPDX-License-Identifier: GPL-2.0-or-later
*/

/* Sieve filter "body" test.  RFC 5173 */

#include "../exim.h"
#include "sieve_filter.h"

gstring * sieve_body_content_matchtypes = NULL;

#define CBOUND_NO	0
#define CBOUND_LEAD	1
#define CBOUND_FINAL	2

/******************************************************************************/
/* Strings for debug */
static const uschar * s_cmp_names[] = {
  [COMP_OCTET] = US"octet",
  [COMP_EN_ASCII_CASEMAP] = US"casemap",
  [COMP_ASCII_NUMERIC] = US"numeric"
};
static const uschar * s_match_names[] = {
  [MATCH_IS] = US"is",
  [MATCH_CONTAINS] = US"contains",
  [MATCH_MATCHES] = US"matches"
};
static const uschar * s_xform_names[] = {
  [XFORM_RAW] = US"raw",
  [XFORM_CONTENT] = US"content",
  [XFORM_TEXT] = US"text"
};
/******************************************************************************/

#if HAVE_ICONV && defined(WITH_CONTENT_SCAN)
static int
consume_mime_boundary(void)
{
int rc;
expand_level++;
rc = mime_clear_boundary(rx_prc);
expand_level--;
return rc;
}


static const pcre2_code *
boundary_to_re(sieve_t * filter, const uschar * s)
{
gstring * rg = string_fmt_append(NULL, "(?sn)(\\n|^)--%s(--)?[ \\t]*\\n", s);

DEBUG(sieve) debug_printf_indent("%s: re %Y\n", __FUNCTION__, rg);
return regex_compile(string_from_gstring(rg), 0,
		    USS &filter->errmsg, pcre_gen_cmp_ctx);
}

#endif

/* Convert matchtype+comparator and key to a compiled regex.
Note that key is an array of gstrings.
Return NULL for error.
*/

static const pcre2_code *
sieve_cm_to_regex(sieve_t * filter,
  enum Comparator ca, enum MatchType ma, gstring * key)
{
gstring * g;

FDEBUG
  {
  debug_printf_indent(" key globlist ");
  for (gstring * g = key; g->s; g++) debug_printf(" \"%Y\"", g);
  debug_printf("\n");
  }

switch (ca)
  {
  case COMP_ASCII_NUMERIC:
    if (ma != MATCH_IS)
      {
      filter->errmsg = US"comparator does not offer specified matchtype";
      return NULL;
      }
    if (!filter->require_iascii_numeric)
      {
      filter->errmsg = US"missing previous require \"comparator-i;ascii-numeric\";";
      return NULL;
      }
    for (gstring * subkey = key; subkey->s; subkey++)
      for (const uschar * s = subkey->s, * t = s + subkey->ptr; s < t; s++)
	if (!isdigit(*s))
	  {
	  filter->errmsg = US"key for numeric comparison contains non-digit";
	  return NULL;
	  }
    /*FALLTHOUGH*/
  default:
    g = string_catn(NULL, US"(?sn)", 5);  /* newlines not special, no capture */
    break;

  case COMP_EN_ASCII_CASEMAP:
    g = string_catn(NULL, US"(?isn)", 6); /* ... plus fold case */
    break;
  }

g = string_catn(g, US"(", 1);
for (const gstring * subkey = key; ; g = string_catn(g, US"|", 1))
  {
  switch (ma)
    {
    case MATCH_IS:
      g = string_fmt_append(g, "(^\\Q%Y\\E$)", subkey); break;

    case MATCH_CONTAINS:
      /* rfc5228 2.7.1 "The empty key ("") is contained in all values".
      Handle this by matching any single char. */

      g = gstring_length(subkey) == 0
	    ? string_catn(g, US".", 1)
	    : string_fmt_append(g, "\\Q%Y\\E", subkey);
      break;

    case MATCH_MATCHES:
      /* Exact glob, against the whole subject - so tie to start/end unless a
      '*' is first/last. The first layer of '\' was removed while parsing the
      string list that is the key for matching. */
      {
      const uschar * s = subkey->s, * t = s + subkey->ptr;

      g = string_catn(g, US"(", 1);	/* start subkey */

      if (*s == '*')				/* leading glob * */
	s++;				/* drop leading "*", do not anchor */
      else
	g = string_catn(g, US"^", 1);	/* start-anchor */

      for (; s < t; s++)
	switch (*s)
	  {
	  case '\\':				/* if we meet a \ */
	    if (!s[1])					/* no next ch */
	      {
	      filter->errmsg = US"match pattern error";
	      return NULL;
	      }
	    switch (*++s)			/* take the next ch verbatim */
	      {
	      /* these regex metachars need protection */
	      case '(': case ')': case '[': case ']':
	      case '{': case '}': case '|': case '.':
	      case '^': case '$': case '*': case '?':
		g = string_catn(g, US"\\", 1);
	      default:
		g = string_catn(g, s, 1);
		break;
	      }
	    break;

	  case '?':			/* glob any-single-ch */
	    g = string_catn(g, US".", 1);
	    break;
	  case '*':			/* glob zero-or-more any ch */
	    if (s == t-1)			/* if last in pattern */
	      goto mdone;		/* drop trailing *, and do not anchor */
	    g = string_catn(g, US".*", 2);
	    break;

	  case '(': case ')': case '[': case ']':    /* these need protection */
	  case '{': case '}': case '|': case '.':
	  case '^': case '$':
	    g = string_catn(g, US"\\", 1);
	  default:
	    g = string_catn(g, s, 1);
	    break;
	  }
      g = string_catn(g, US"$", 1);		/* end-anchor */
    mdone:
      g = string_catn(g, US")", 1);		/* end subkey */
      break;
      }
    }
  if (!(++subkey)->s)
    break;
  }
g = string_catn(g, US")", 1);

DEBUG(sieve) debug_printf_indent("regex %.*q\n", g->ptr, g->s);

return regex_compile(string_from_gstring(g), 0,
		    USS &filter->errmsg, pcre_gen_cmp_ctx);
}


/* From the current offset in stdin, as processed by the input stack,
look for the given regex.

Arguments:
  filter	the sieve filter block
  re		compiled regex to search for
  cond		pointer to result

Set the result, true if matched, via the cond arg.
Return FALSE iff error, with a message set.
*/

static BOOL
sieve_file_match(sieve_t * filter, const pcre2_code * re, BOOL * cond,
  pcre2_match_data * md)
{
int dfa_wspace[SIEVE_BODY_REGEX_WORK_SIZE];
uint32_t matchopt = PCRE2_PARTIAL_SOFT | PCRE2_DFA_SHORTEST | PCRE2_NOTEMPTY;
const uschar * subj;

expand_level++;
DEBUG(sieve) debug_printf_indent("%s\n", __FUNCTION__);
DEBUG(sieve) debug_print_processing_stack();

expand_level++;

for (unsigned dlen;
     dlen = 4096, subj = receive_getbuf_nr(&dlen);
     matchopt |= PCRE2_NOTBOL)
  {
  int rc;

  expand_level--;
  DEBUG(sieve) debug_printf_indent("%s %d: dlen %u %.*q\n",
				__FUNCTION__, __LINE__, dlen, (int)dlen, subj);

  rc = pcre2_dfa_match(
	re,			/* result of pcre2_compile() */
	subj,			/* the subject string */
	dlen,			/* the length of the subject string */
	0,			/* start at offset 0 in the subject */
	matchopt,		/* options */
	md,			/* the match data block */
	pcre_gen_mtc_ctx,	/* a match context; NULL means use defaults */
	dfa_wspace,		/* working space vector */
	nelem(dfa_wspace));	/* number of elements (NOT size in bytes) */

  /* Release the whole buffer.
  If we matched anything, return with that info. */

  expand_level++;
  receive_releasebuf(dlen);
  expand_level--;

  if (rc > 0) { *cond = TRUE; goto out; }

  DEBUG(sieve)
    {
    pcre2_get_error_message(rc, big_buffer, big_buffer_size);
    debug_printf_indent("%s %d: rc %d %q\n", __FUNCTION__, __LINE__,
			rc, big_buffer);
    }

  switch (rc)
    {
    case PCRE2_ERROR_NOMATCH:	matchopt &= ~PCRE2_DFA_RESTART; break;
    case PCRE2_ERROR_PARTIAL:	matchopt |=  PCRE2_DFA_RESTART; break;
    default:
      /* NB: if we get PCRE2_ERROR_DFA_RECURSE here,
      the workspace was not big enough */
      pcre2_get_error_message(rc, big_buffer, big_buffer_size);
      filter->errmsg = string_sprintf("match: %.200s\n", big_buffer);
      goto bad;
    }

  /* Go round again, until no more data from below */
  expand_level++;
  }

expand_level--;
if (receive_ferror())
  { filter->errmsg = US"read or decode error in data file"; goto bad; }

DEBUG(sieve) debug_printf_indent("%s: got EOF\n", __FUNCTION__);

out:
  FDEBUG if (*cond) debug_printf_indent("match\n");
  expand_level--;
  return TRUE;

bad:
  DEBUG(sieve) debug_printf_indent("%s (fail)\n", __FUNCTION__);
  expand_level--;
  return FALSE;
}


/* Match within stdin, from current pos to eof */

static BOOL
sieve_body_raw(sieve_t * filter, const pcre2_code * re, BOOL * cond)
{
pcre2_match_data * md = pcre2_match_data_create(1, pcre_gen_ctx);
return sieve_file_match(filter, re, cond, md);
}


/******************************************************************************/

/* Stack decode layers if needed for the given CT & CE headers,
Return: number of layers pushed
*/

static unsigned
push_decode_layers(const uschar * ct_hdr, const uschar * ce_hdr)
{
unsigned lcount = 0;

DEBUG(sieve) debug_printf_indent("%s: ct_hdr %q ce_hdr %q\n", __FUNCTION__,
				  ct_hdr, ce_hdr);
DEBUG(sieve) debug_print_processing_stack();

if (ce_hdr)						/* encoding */
  if (strncmpic(ce_hdr, US"quoted-printable", 16) == 0)
    {
    rx_prc = qp_push_receive_functions(rx_prc);
    lcount++;
    }
  else if (strncmpic(ce_hdr, US"base64", 6) == 0)
    {
    rx_prc = b64_push_receive_functions(rx_prc);
    lcount++;
    }
  else FDEBUG
    debug_printf_indent("content-transfer-encoding %q not handled\n", ce_hdr);

#if HAVE_ICONV && defined(WITH_CONTENT_SCAN)
/* charset */

if ((ct_hdr = Ustrchr(ct_hdr, ';')))	/* skip (eg.) text/plain */
  {
  const uschar * val = NULL;
  mime_parameter m = {.name = US"charset", .namelen = 7, .value = &val};

  ct_hdr++;						/* skip the ; */
  mime_hdr_value_decode(ct_hdr, &m, 1, US"Content-Type");
  if (val)
    {
    FDEBUG debug_printf_indent("charset: %q\n", val);
    if (  strncmpic(val, US"us-ascii", 8) != 0
       && strncmpic(val, US"utf-8", 5)    != 0
       && strncmpic(val, US"8bit", 4)     != 0
       && strncmpic(val, US"7bit", 4)     != 0
       && strncmpic(val, US"binary", 6)   != 0
       )
      {				/* We need to transform this charset */
      const in_processing * inp;
      if ((inp = iconv_push_receive_functions(rx_prc, val)))
	{ rx_prc = inp; lcount++; }
      }
    }
  }
#endif	/*HAVE_ICONV && WITH_CONTENT_SCAN*/

FDEBUG debug_print_processing_stack();
return lcount;
}


/* Match within stdin as decoded per $h_content-transfer-encoding,
from current pos to eof */

static BOOL
sieve_body_text(sieve_t * filter, const pcre2_code * re, BOOL * cond)
{
const uschar * ce_hdr, * ct_hdr = US"";
unsigned decode_count;
pcre2_match_data * md;
BOOL yield;

/* Set up input decoding for transfer-encoding, by stacking a decode layer over
the stdin input layer. */

if (!(ce_hdr = expand_string(US"$h_content-transfer-encoding")))
  {
  filter->errmsg =
    US"internal expansion failure for content-transfer_encoding\n";
  return FALSE;
  }

#if HAVE_ICONV && defined(WITH_CONTENT_SCAN)
if (!(ct_hdr = expand_string(US"$h_content-type")))
  {
  filter->errmsg = US"internal expansion failure for content-type\n";
  return FALSE;
  }
#endif

decode_count = push_decode_layers(ct_hdr, ce_hdr);

md = pcre2_match_data_create(1, pcre_gen_ctx);
yield = sieve_file_match(filter, re, cond, md);

DEBUG(sieve) debug_printf_indent("pop decode layers\n");
for ( ; decode_count > 0; decode_count--) receive_pop();
FDEBUG debug_print_processing_stack();

return yield;
}

/******************************************************************************/

static void
skip_mime_part(void)
{
expand_level++;
for (unsigned dlen; dlen = 4096, receive_getbuf_nr(&dlen); )
  receive_releasebuf(dlen);
expand_level--;

DEBUG(sieve) debug_printf_indent(receive_ferror() ? "got ferror\n":"got EOF\n");
}

static BOOL
scan_mime_part(sieve_t * filter, BOOL * cond,
  const uschar * ct_hdr, const uschar * ce_hdr,
  const pcre2_code * content_re, pcre2_match_data * content_md)
{
unsigned decode_count;

expand_level++;
FDEBUG debug_printf_indent("%s entry\n", __FUNCTION__);
expand_level++;

  decode_count = push_decode_layers(ct_hdr, ce_hdr);

  if (!sieve_file_match(filter, content_re, cond, content_md))
    return FALSE;

  DEBUG(sieve) debug_printf_indent("pop decode layers\n");
  for ( ; decode_count > 0; decode_count--) receive_pop();
  FDEBUG debug_print_processing_stack();

expand_level--;
FDEBUG debug_printf_indent("%s done\n", __FUNCTION__);
expand_level--;

return TRUE;
}



static void
check_hdr(const uschar * hdr, unsigned hlen,
  const uschar * wanted, const uschar ** valp)
{
size_t nlen = Ustrlen(wanted);
if (hlen >= nlen && Ustrncmp(hdr, wanted, nlen) == 0)
  {
  	/* skip whitespace */
  for (hdr += nlen, hlen -= nlen; hlen; hdr++, hlen--)
    if (*hdr != ' ' && *hdr != '\t') break;

  *valp = string_copyn(hdr, hlen);
  }
}

/* Consume a headers area, noting values for any Content-Type and
Content-Transfer-Encoding headers seen. Optionally also scan for content
with a geven regex; may return early on hit.

Arguments:
	filter		sieve filter context
	ctp, cep	Pointers for returned header values
	re		If non-null, scan the area for content
	cond		Pointer for scan result

Return boolean no-error.
*/

static BOOL
consume_headers(sieve_t * filter, const uschar ** ctp, const uschar ** cep,
  const pcre2_code * re, BOOL * cond)
{
unsigned dlen, llen, nlen;
const uschar * buf, * line, * s, * t = NULL, * u = NULL;
pcre2_match_data * md;
int dws[SIEVE_BODY_REGEX_WORK_SIZE], rc;
uint32_t mopt = PCRE2_PARTIAL_SOFT | PCRE2_DFA_SHORTEST | PCRE2_NOTEMPTY;

if (re)
  md = pcre2_match_data_create(1, pcre_gen_ctx);

DEBUG(sieve) debug_printf_indent("%s%s start\n", __FUNCTION__,
				  re ? " (with content scan)" : "");
expand_level++;
  dlen = 4096; s = line = buf = receive_getbuf_nr(&dlen);
expand_level--;

if (!buf)						/* EOF */
  return TRUE;

while (dlen)
  if ((t = memchr(s, '\n', (size_t)dlen)))	/* Identify a line */
    {
    if (!(llen = t - line))			/* Zero-length; we're done */
      break;

						/* Check for folded headers */
    if (dlen > llen+2 && (t[1] == ' ' || t[1] == '\t'))
      s = t + 2;
    else
      {
      DEBUG(sieve) debug_printf_indent("%s: %.*q\n",
					__FUNCTION__, (int)llen, line);
      check_hdr(line, llen, US"Content-Type:", ctp);
      check_hdr(line, llen, US"Content-Transfer-Encoding:", cep);
      u = s = line = t + 1;			/* Skip line plus '\n' */
      dlen -= llen + 1;
      }
    }
  else						/* No more full lines */
    {		      /* Release what we've scanned so far, and request more. */
    if (u)					/* Hdr-scanned >0 lines */
      {
      nlen = (unsigned)(u - buf);
      if (re)					/* Scan also for content */
	{
	if ((rc = pcre2_dfa_match(re, buf, (PCRE2_SIZE)nlen, 0,
			      mopt, md, pcre_gen_mtc_ctx, dws, nelem(dws))) > 0)
	  {
	  FDEBUG debug_printf_indent("match\n");
	  expand_level--; *cond = TRUE; return TRUE;
	  }
	DEBUG(sieve)
	  {
	  pcre2_get_error_message(rc, big_buffer, big_buffer_size);
	  debug_printf_indent("%s %d: rc %d %q\n", __FUNCTION__, __LINE__,
			      rc, big_buffer);
	  }
	switch (rc)
	  {
	  case PCRE2_ERROR_NOMATCH:	mopt &= ~PCRE2_DFA_RESTART; break;
	  case PCRE2_ERROR_PARTIAL:	mopt |=  PCRE2_DFA_RESTART; break;
	  default:
	    filter->errmsg = string_sprintf("match: %.200s\n", big_buffer);
	    return FALSE;
	  }
	 mopt |= PCRE2_NOTBOL;
	}

      expand_level++;
	receive_releasebuf(nlen);
      expand_level--;
      u = NULL;
      }
    expand_level++;
      nlen = 4096; s = line = buf = receive_getbuf_nr(&nlen);
    expand_level--;

    if (!line || nlen == dlen)			/* No more data available */
      { filter->errmsg = US"incomplete headers block"; return FALSE; }

    dlen = nlen;
    }

/* We hit the empty line signifying end of the headers block. Content-scan the
buffer to this point, then release up to here. */

if (t)
  {
  nlen = (unsigned)(t+1 - buf);
  if (re)
    {
    if ((rc = pcre2_dfa_match(re, buf, (PCRE2_SIZE) nlen, 0,
			      mopt, md, pcre_gen_mtc_ctx, dws, nelem(dws))) > 0)
      {
      FDEBUG debug_printf_indent("match\n");
      *cond = TRUE; return TRUE;
      }
    DEBUG(sieve)
      {
      pcre2_get_error_message(rc, big_buffer, big_buffer_size);
      debug_printf_indent("%s %d: rc %d %q\n", __FUNCTION__, __LINE__,
			  rc, big_buffer);
      }
    if (rc != PCRE2_ERROR_NOMATCH && rc != PCRE2_ERROR_PARTIAL)
      {
      filter->errmsg = string_sprintf("match: %.200s\n", big_buffer);
      return FALSE;
      }
    }

  expand_level++;
    receive_releasebuf(nlen);
  expand_level--;
  }

DEBUG(sieve) debug_printf_indent("%s done\n", __FUNCTION__);
return TRUE;
}

/* Arguments:
	filter		sieve filter context
	content_re	compiled regex for content match
	cond		ptr for returned content match value
	ct_hdr		content-type header value for this layer
	ce_hdr		content-transfer_encoding value for this layer
	depth		mime call depth

Return:	boolean success/failure
*/

static BOOL
content_match(sieve_t * filter, const pcre2_code * content_re, BOOL * cond,
  const uschar * ct_hdr, const uschar * ce_hdr, unsigned depth)
{
BOOL skipping;

expand_level++;
FDEBUG
  debug_printf_indent("%s: depth %u ct_hdr %q\n", __FUNCTION__, depth,  ct_hdr);

if (!*ct_hdr)
  {
  /* There is no MIME type.  Only an empty type-spec will match. */
  FDEBUG debug_printf_indent("mime section lacking CT\n");

  for (gstring * subtype = sieve_body_content_matchtypes; subtype->s; subtype++)
    if (!subtype->s[0]) { *cond = TRUE; break; }
  return TRUE;
  }

/* To be interesting, the Content-Type must match one of our list. An empty
list entry will match anything; a type-only entry will match only if the
next char is a / (so a prefix does not match); a type/subtype entry will
match only is the next char is semicolon or NUL. */

skipping = TRUE;
for (gstring * subtype = sieve_body_content_matchtypes; subtype->s; subtype++)
  {
  int slen = gstring_length(subtype);
  uschar c = ct_hdr[slen];

  if (  !subtype->s[0]
     ||    Ustrncmp(ct_hdr, subtype->s, slen) == 0
	&& (gstring_chr(subtype, '/') ? c == ';' || c == '\0' : c == '/')
     )
    { skipping = FALSE; break; }
  }

FDEBUG
  {
  const uschar * s = Ustrchrnul(ct_hdr, ';');
  debug_printf_indent("%s: mimetype %.*q %s\n", __FUNCTION__,
		(int)(s - ct_hdr), ct_hdr,
		skipping ? "not interesting" : "is of interest");
  }

/* If the ct_hdr indicates multipart
- match on the prefix text, if any.  That requires an input-processing stack with
  boundary-matching over stdin, so set that up.  Set up a regex for the content
  match, and run that. If it gets a hit, we are done. Otherwise repeat until boundary
  (? indicated as eof?). Then, until boundary-is-final: recurse with the mimepart -
  headers, interest, matching). Then match on the tailing text, if any.  Done if hit.
  Else done with no-match.

For not-multipart:
  Regex for the content match; run it until match or eof. Done, with match status.
*/
#if HAVE_ICONV && defined(WITH_CONTENT_SCAN)
if (Ustrncmp(ct_hdr, "multipart", 9) == 0)
  {
  const pcre2_code * boundary_re;
  const uschar * s, * inner_boundary = NULL;
  mime_parameter m = {.name = US"boundary", .namelen = 8, .value = &inner_boundary};
  pcre2_match_data * content_md;
  int rc;

  /* RFC 5173:
  "If the :content specification matches a multipart MIME part, only the
  prologue and epilogue sections of the part will be searched for the
  key strings, treating the entire prologue and the entire epilogue as
  separate strings; the contents of nested parts are only searched if
  their respective types match the :content specification." */

  if (!(s = Ustrchr(ct_hdr, ';')))
    {
    filter->errmsg = string_sprintf("malformed multipart header %q\n", ct_hdr);
    goto bad;
    }

  content_md = pcre2_match_data_create(1, pcre_gen_ctx);

  /* Get the boundary from the CT header */

  s++;                                                /* skip the ; */
  mime_hdr_value_decode(s, &m, 1, US"Content-Type");
  DEBUG(sieve) debug_printf_indent("%s %d: inner_boundary %q\n",
				  __FUNCTION__, __LINE__, inner_boundary);
  if (!inner_boundary)
    { filter->errmsg = US"missing boundary for multipart\n"; goto bad; }

  /* Install the RE for the boundary to the mime boundary processing layer */

  if (!(boundary_re = boundary_to_re(filter, inner_boundary)))
    goto bad;

  rx_prc = mime_push_receive_functions(rx_prc, boundary_re,
				    pcre2_match_context_create(pcre_gen_ctx),
				    pcre2_match_data_create(1, pcre_gen_ctx));
  FDEBUG debug_print_processing_stack();

/*ISSUE: an empty prefix area makes us skip the first real-mimepart */

  FDEBUG
    debug_printf_indent("%s prefix area\n", skipping ? "skip":"scan");
  if (skipping)
    skip_mime_part();
  else
    {
    if (!scan_mime_part(filter, cond, ct_hdr, ce_hdr, content_re, content_md))
      goto bad;
    if (*cond)
      goto done;
    }
  DEBUG(sieve) debug_printf_indent("done with prefix area\n");
  if (receive_ferror()) goto ferror;

  /* Now we're either at our-layer first mime boundary, or properly
  out-of-data.  Ask for more data; if none then EOF and done. Otherwise,
  look for a ct header to decide if interesting, and a ce header for
  decode needs. */

  while ((rc = consume_mime_boundary()) == SIEVE_MIME_BOUNDARY_NONLAST)
    {
    const uschar * inner_ct = NULL, * inner_ce = NULL;

    FDEBUG debug_printf_indent("real mimepart\n");
    if (!consume_headers(filter, &inner_ct, &inner_ce, NULL, NULL))
      goto bad;
    if (!inner_ct)
      goto done;

    /* The match for a "real" mimepart does it's own evaluation of
    interestingness on the content-type of that mimepart. */

    if (!content_match(filter, content_re, cond, inner_ct, inner_ce, depth+1))
      goto bad;
    if (*cond)
      goto done;
    DEBUG(sieve) debug_printf_indent("done real-mimepart\n");
    }
  if (rc < 0)
    { filter->errmsg = US"internal error (mime-boundary)"; goto bad; }

  FDEBUG
    debug_printf_indent("%s suffix area\n", skipping ? "skip":"scan");
  if (skipping)
    skip_mime_part();
  else
    if (!scan_mime_part(filter, cond, ct_hdr, ce_hdr, content_re, content_md))
      goto bad;
  DEBUG(sieve) debug_printf_indent("done with suffix area\n");
  if (receive_ferror()) goto ferror;
  }
else
#endif	/* HAVE_ICONV && WITH_CONTENT_SCAN */
    if (Ustrcmp(ct_hdr, "message/rfc822") == 0)
  {
  /* RFC 5173:
  "If the :content specification matches a message/rfc822 MIME part,
  only the header of the nested message will be searched for the key
  strings, treating the header as a single string; the contents of the
  nested message body parts are only searched if their content type
  matches the :content specification."

  We need the walk the data until end-of-headers (denoted by an empty line).
  This might need pulling in additional data. Stash any content-type and
  content-transfer-encoding headers while doing that - can we use the existing
  mech that does this?
    cf. find_header_val() & consume_mime_headers().

  Then (if not skipping) scan that headers area.
  Then step past the headers area. Then recurse with the CT, CE and body area.
  */
  const uschar * inner_ct = NULL, * inner_ce = NULL;
  BOOL bad_msg_hdrs;

  FDEBUG
    debug_printf_indent("%s 822 headers\n", skipping ? "skip" : "scan");
  expand_level++;
  bad_msg_hdrs = !consume_headers(filter, &inner_ct, &inner_ce,
				  skipping ? NULL : content_re, cond);
  expand_level--;
  if (bad_msg_hdrs)
    goto bad;
  if (*cond)
    goto done;
  DEBUG(sieve) debug_printf_indent("done 822 headers\n");

  if (!inner_ct)
    {
    FDEBUG debug_printf_indent("Defaulting CT to text/plain\n");
    inner_ct = US"text/plain";
    }
  FDEBUG debug_printf_indent("inspect 822 body\n");
  if (!content_match(filter, content_re, cond, inner_ct, inner_ce, depth+1))
    goto bad;
  if (*cond)
    goto done;
  DEBUG(sieve) debug_printf_indent("done 822 body\n");
  }
else
  {
  /* RFC 5173:
  "For other MIME types, the entire part will be searched as a single string."
  */
  FDEBUG
    debug_printf_indent("%s text-like part\n", skipping ? "skip" : "scan");
  if (skipping)
    skip_mime_part();
  else
    {
    pcre2_match_data * content_md = pcre2_match_data_create(1, pcre_gen_ctx);
    if (!scan_mime_part(filter, cond, ct_hdr, ce_hdr, content_re, content_md))
      goto bad;
    }
  DEBUG(sieve) debug_printf_indent("inspect text-like part done\n");
  if (receive_ferror()) goto ferror;
  }

done:
  expand_level--;
  return TRUE;

ferror:
  filter->errmsg = US"error in input stream";
bad:
  DEBUG(sieve) debug_printf_indent("%s: ret bad\n", __FUNCTION__);
  expand_level--;
  return FALSE;
}


/* ":content" <content-types: string-list>
eg:	body :content "multipart" :contains "MIME"
	body :content "text" :contains ["missile", "coordinates"]

RFC 5173 5.2

Match recursively against MIME parts, success matches only for
message or MIME-part matching the content-type list, and excluding
sub-parts.
MIME headers are not included in search source.

An empty match string does match (giving a "container exists" facility).
XXX check spec on that for text & raw xform matches

message/rfc822 MIME parts only get their headers searched. The body part
is handled as an inner container.

An empty-string type spec matches all MIME types.
One with a leading or trailing / or containing multiple / matches none.
One with no / matches all subtypes of the matching type.
One with one / matches the given type/subtype only.
*/

/* Arguments:
	rg	Regex string for the content match
*/

static BOOL
sieve_body_content(sieve_t * filter, const pcre2_code * content_re, BOOL * cond)
{
const uschar * ct, * ce;

if (!sieve_body_content_matchtypes)
  { filter->errmsg = US"missing content matchtypes"; return FALSE; }

FDEBUG
  {
  debug_printf_indent("%s: content-types:", __FUNCTION__);
  for (gstring * g = sieve_body_content_matchtypes; g->s; g++)
    debug_printf(" %Y", g);
  debug_printf("\n");
  }

/*XXX now, can we re-use anything from mime.c ? */
/* The spec says that we're only matching in one context at a time, and
can manage with a single pass through the input data.  No need for writing
out each MIME (sub)section as a new file an recursing into it.  However, we
do need to recurse into a stack of match contexts.
*/

if (!(ce = expand_string(US"$h_content-transfer-encoding")))
  {
  filter->errmsg = US"internal expansion failure for content-transfer-encoding\n";
  return FALSE;
  }

/* For the toplevel "MIME boundary" we use a real string for content-type
"multipart", else NULL to indicate search-to-EOF. */

if (!(ct = expand_string(US"$h_content-type")))
  {
  filter->errmsg = US"internal expansion failure for content-type\n";
  return FALSE;
  }

return content_match(filter, content_re, cond, ct, ce, 0);
}

/******************************************************************************/

/* Return FALSE iff error, otherwise condition result via cond. */

BOOL
sieve_body_test(sieve_t * filter,
  enum Comparator ca, enum MatchType ma, enum XformType xa, gstring * key,
  BOOL * cond)
{
const pcre2_code * re;
BOOL res;

DEBUG(sieve) debug_printf_indent("%s: entry\n", __FUNCTION__);
FDEBUG
  debug_printf_indent(" comparator:%s, matchtype:%s, xform:%s\n",
		s_cmp_names[ca], s_match_names[ma], s_xform_names[xa]);
/*
Raw does not do encoding-conversion on the body (unlike Content & Text,
which (if possible) convert <content-transfer-encoding> to UTF-8 before
running comparisons).
Raw takes the entire body.

XFORM_CONTENT "the MIME parts that have the
	       specified content types are matched against independently"
XFORM_TEXT "matches against the results of an
	   implementation's best effort at extracting UTF-8 encoded text from
	   a message"

We will want to use the -D file.  For now, ignore the "wireformat"
possibility. Skip the top line (it has the message-id).

Filter testing leaves the body pending on stdin, but has used
our own buffering to read headers [receive_getc()].  So we have to
carry on using that. For other uses, open the message datafile in spool
and skip the header line. Stdin is then set up for either case.
*/

if (filter_test == FTEST_NONE)
  {
  int fd;

  fclose(stdin_copy);
  if ((fd = spool_open_datafile(message_id)) < 0)
    { filter->errmsg = US"failed to open data file"; return FALSE; }

  /* Solaris and BSDs have definitions for stdin which do not allow simple
  assignment, so we are forced into using this copy-variable. */

  stdin_copy = fdopen(fd, "r");

  if (fseek(stdin_copy, spool_data_start_offset(message_id), SEEK_SET) < 0)
    { filter->errmsg = US"seek error in data file"; return FALSE; }
  }

/* Setup regex for comparator plus match type, and the given search key */

if (!(re = sieve_cm_to_regex(filter, ca, ma, key)))
  return FALSE;

*cond = FALSE;		/* default for our callees */
switch (xa)
  {
  case XFORM_RAW:
    res = sieve_body_raw(filter, re, cond);
    break;
  case XFORM_TEXT:
    res = sieve_body_text(filter, re, cond);
    break;

  case XFORM_CONTENT:
    res = sieve_body_content(filter, re, cond);
    break;

  default:
    *cond = FALSE;
    res = TRUE;
    break;
  }

if (filter_test == FTEST_NONE)
  { fclose(stdin_copy); stdin_copy = NULL; }

return res;
}

/* End of sieve_filter_body.c */
/* vi: aw ai sw=2
*/
