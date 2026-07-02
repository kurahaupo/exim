/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
Copyright (c) The Exim Maintainers 2016 - 2025
Copyright (c) Michael Haardt 2003 - 2015
See the file NOTICE for conditions of use and distribution.
SPDX-License-Identifier: GPL-2.0-or-later
*/

/* This code was originally contributed by Michael Haardt. */


/* Sieve mail filter. */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "../exim.h"
#include "sieve_filter.h"

#ifdef SUBADDRESS
enum AddressPart { ADDRPART_USER, ADDRPART_DETAIL, ADDRPART_LOCALPART, ADDRPART_DOMAIN, ADDRPART_ALL };
#else
enum AddressPart { ADDRPART_LOCALPART, ADDRPART_DOMAIN, ADDRPART_ALL };
#endif
enum RelOp { LT, LE, EQ, GE, GT, NE };

struct Notification {
  gstring method;
  gstring importance;
  gstring message;
  struct Notification *next;
};

/* This should be a complete list of supported extensions, so that an external
ManageSieve (RFC 5804) program can interrogate the current Exim binary for the
list of extensions and provide correct information to a client.

We'll emit the list in the order given here; keep it alphabetically sorted, so
that callers don't get surprised.

List *MUST* end with a NULL.  Which at least makes ifdef-vs-comma easier. */

static const uschar * exim_sieve_extension_list[] = {
#ifdef BODY
  CUS"body",
#endif
  CUS"comparator-i;ascii-numeric",
  CUS"copy",
#ifdef ENCODED_CHARACTER
  CUS"encoded-character",
#endif
#ifdef ENOTIFY
  CUS"enotify",
#endif
  CUS"envelope",
#ifdef ENVELOPE_AUTH
  CUS"envelope-auth",
#endif
  CUS"fileinto",
#ifdef SUBADDRESS
  CUS"subaddress",
#endif
#ifdef VACATION
  CUS"vacation",
#endif
  NULL
};

static int eq_asciicase(const gstring * needle, const gstring * haystack, BOOL match_prefix);
static int parse_test(struct Sieve *filter, BOOL *cond, BOOL exec);
static int parse_commands(struct Sieve *filter, BOOL exec, address_item **generated);

static gstring str_from = { .s = US"From" };
static gstring str_to = { .s = US"To" };
static gstring str_cc = { .s = US"Cc" };
static gstring str_bcc = { .s = US"Bcc" };
#ifdef BODY
static gstring str_body = { .s = US"body" };
#endif
#ifdef ENVELOPE_AUTH
static gstring str_auth = { .s = US"auth" };
#endif
static gstring str_sender = { .s = US"Sender" };
static gstring str_resent_from = { .s = US"Resent-From" };
static gstring str_resent_to = { .s = US"Resent-To" };
static gstring str_fileinto = { .s = US"fileinto" };
static gstring str_envelope = { .s = US"envelope" };
#ifdef ENCODED_CHARACTER
static gstring str_encoded_character = { .s = US"encoded-character" };
#endif
#ifdef ENVELOPE_AUTH
static gstring str_envelope_auth = { .s = US"envelope-auth" };
#endif
#ifdef ENOTIFY
static gstring str_enotify = { .s = US"enotify" };
static gstring str_online = { .s = US"online" };
static gstring str_maybe = { .s = US"maybe" };
static gstring str_auto_submitted = { .s = US"Auto-Submitted" };
#endif
#ifdef SUBADDRESS
static gstring str_subaddress = { .s = US"subaddress" };
#endif
#ifdef VACATION
static gstring str_vacation = { .s = US"vacation" };
static gstring str_subject = { .s = US"Subject" };
#endif
static gstring str_copy = { .s = US"copy" };
static gstring str_iascii_casemap = { .s = US"i;ascii-casemap" };
static gstring str_enascii_casemap = { .s = US"en;ascii-casemap" };
static gstring str_ioctet = { .s = US"i;octet" };
static gstring str_iascii_numeric = { .s = US"i;ascii-numeric" };
static gstring str_comparator_iascii_casemap = { .s = US"comparator-i;ascii-casemap" };
static gstring str_comparator_enascii_casemap = { .s = US"comparator-en;ascii-casemap" };
static gstring str_comparator_ioctet = { .s = US"comparator-i;octet" };
static gstring str_comparator_iascii_numeric = { .s = US"comparator-i;ascii-numeric" };

static gstring * const sieve_wordlist[] = {
  &str_from,
  &str_to,
  &str_cc,
  &str_bcc,
#ifdef ENVELOPE_AUTH
  &str_auth,
#endif
#ifdef BODY
  &str_body,
#endif
  &str_sender,
  &str_resent_from,
  &str_resent_to,
  &str_fileinto,
  &str_envelope,
#ifdef ENCODED_CHARACTER
  &str_encoded_character,
#endif
#ifdef ENVELOPE_AUTH
  &str_envelope_auth,
#endif
#ifdef ENOTIFY
  &str_enotify,
  &str_online,
  &str_maybe,
  &str_auto_submitted,
#endif
#ifdef SUBADDRESS
  &str_subaddress,
#endif
#ifdef VACATION
  &str_vacation,
  &str_subject,
#endif
  &str_copy,
  &str_iascii_casemap,
  &str_enascii_casemap,
  &str_ioctet,
  &str_iascii_numeric,
  &str_comparator_iascii_casemap,
  &str_comparator_enascii_casemap,
  &str_comparator_ioctet,
  &str_comparator_iascii_numeric,
};


/*************************************************
*          Encode to quoted-printable            *
*************************************************/

/*
Arguments:
  src               UTF-8 string

Returns
  dst, allocated, a US-ASCII string
*/

static gstring *
quoted_printable_encode(const gstring * src)
{
gstring * dst = NULL;
size_t line = 0;

for (const uschar * start = src->s, * end = start + src->ptr;
     start < end; ++start)
  {
  uschar ch = *start;
  if (line >= 73)	/* line length limit */
    {
    dst = string_catn(dst, US"=\n", 2);	/* line split */
    line = 0;
    }
  if (  (ch >= '!' && ch <= '<')
     || (ch >= '>' && ch <= '~')
     || (  (ch == '\t' || ch == ' ')
	&& start+2 < end && (start[1] != '\r' || start[2] != '\n')	/* CRLF */
	)
     )
    {
    dst = string_catn(dst, start, 1);		/* copy char */
    ++line;
    }
  else if (ch == '\r' && start+1 < end && start[1] == '\n')		/* CRLF */
    {
    dst = string_catn(dst, US"\n", 1);		/* NL */
    line = 0;
    ++start;	/* consume extra input char */
    }
  else
    {
    dst = string_fmt_append(dst, "=%02X", ch);
    line += 3;
    }
  }

(void) string_from_gstring(dst);
gstring_release_unused(dst);
return dst;
}


/*************************************************
*     Check mail address for correct syntax      *
*************************************************/

/*
Check mail address for being syntactically correct.

Arguments:
  filter      points to the Sieve filter including its state
  address     String containing one address

Returns
  1           Mail address is syntactically OK
 -1           syntax error
*/

static int
check_mail_address(struct Sieve * filter, const gstring * address)
{
if (address->ptr > 0)
  {
  int start, end, domain;
  uschar * error;
  const uschar * ss = parse_extract_address(address->s, &error,
					    &start, &end, &domain, FALSE);
  if (ss)
    return 1;

  filter->errmsg = string_sprintf("malformed address %q (%s)",
      address->s, error);
  }
else
  filter->errmsg = US"empty address";

FDEBUG debug_printf_indent("%s\n", filter->errmsg);
return -1;
}


/*************************************************
*          Decode URI encoded string             *
*************************************************/

/*
Arguments:
  str               URI encoded string

Returns
  str is modified in place
  TRUE              Decoding successful
  FALSE             Encoding error
*/

#ifdef ENOTIFY
static BOOL
uri_decode(gstring * str)
{
uschar * s, * t;
const uschar * e;

if (str->ptr == 0) return TRUE;
for (t = s = str->s, e = s + str->ptr; s < e; )
  if (*s == '%')
    {
    if (s+2 < e && isxdigit(s[1]) && isxdigit(s[2]))
      {
      *t++ = ((isdigit(s[1]) ? s[1]-'0' : tolower(s[1])-'a'+10)<<4)
            | (isdigit(s[2]) ? s[2]-'0' : tolower(s[2])-'a'+10);
      s += 3;
      }
    else
      {
      FDEBUG debug_printf_indent("uri decode: bad encoding\n");
      return FALSE;
      }
    }
  else
    *t++ = *s++;

*t = '\0';
str->ptr = t - str->s;
return TRUE;
}


/*************************************************
*               Parse mailto URI                 *
*************************************************/

/*
Parse mailto-URI.

       mailtoURI   = "mailto:" [ to ] [ headers ]
       to          = [ addr-spec *("%2C" addr-spec ) ]
       headers     = "?" header *( "&" header )
       header      = hname " = " hvalue
       hname       = *urlc
       hvalue      = *urlc

Arguments:
  filter      points to the Sieve filter including its state
  uri         URI, excluding scheme
  recipient   list of recipients; prepnded to
  body

Returns
  1           URI is syntactically OK
  0           Unknown URI scheme
 -1           syntax error
*/

static int
parse_mailto_uri(struct Sieve * filter, const uschar * uri,
  string_item ** recipient, gstring * header, gstring * subject,
  gstring * body)
{
const uschar * start;

if (Ustrncmp(uri, "mailto:", 7))
  {
  filter->errmsg = US "Unknown URI scheme";
  return 0;
  }

uri += 7;
if (*uri && *uri != '?')
  for (;;)
    {
    /* match to */
    for (start = uri; *uri && *uri != '?' && (*uri != '%' || uri[1] != '2' || tolower(uri[2]) != 'c'); ++uri);
    if (uri > start)
      {
      gstring * to = string_catn(NULL, start, uri - start);
      string_item * new;

      if (!uri_decode(to))
        {
        filter->errmsg = US"Invalid URI encoding";
        goto bad;
        }
      new = store_get(sizeof(string_item), GET_UNTAINTED);
      new->text = string_from_gstring(to);
      new->next = *recipient;
      *recipient = new;
      }
    else
      {
      filter->errmsg = US"Missing addr-spec in URI";
      goto bad;
      }
    if (*uri == '%') uri += 3;
    else break;
    }
if (*uri == '?')
  for (uri++; ;)
    {
    gstring * hname = string_get(0), * hvalue = NULL;

    /* match hname */
    for (start = uri; *uri && (isalnum(*uri) || strchr("$-_.+!*'(), %", *uri)); ++uri) ;
    if (uri > start)
      {
      hname = string_catn(hname, start, uri-start);

      if (!uri_decode(hname))
        {
        filter->errmsg = US"Invalid URI encoding";
        goto bad;
        }
      }
    /* match = */
    if (*uri++ != '=')
      {
      filter->errmsg = US"Missing equal after hname";
      goto bad;
      }

    /* match hvalue */
    for (start = uri; *uri && (isalnum(*uri) || strchr("$-_.+!*'(), %", *uri)); ++uri) ;
    if (uri > start)
      {
      hvalue = string_catn(NULL, start, uri-start);	/*XXX this used to say "hname =" */

      if (!uri_decode(hvalue))
        {
        filter->errmsg = US"Invalid URI encoding";
        goto bad;
        }
      }
    if (hname->ptr == 2 && strcmpic(hname->s, US"to") == 0)
      {
      string_item * new = store_get(sizeof(string_item), GET_UNTAINTED);
      new->text = string_from_gstring(hvalue);
      new->next = *recipient;
      *recipient = new;
      }
    else if (hname->ptr == 4 && strcmpic(hname->s, US"body") == 0)
      *body = *hvalue;
    else if (hname->ptr == 7 && strcmpic(hname->s, US"subject") == 0)
      *subject = *hvalue;
    else
      {
      static gstring ignore[] =
        {
        {.s = US"date", .ptr = 4, .size = 5},
        {.s = US"from", .ptr = 4, .size = 5},
        {.s = US"message-id", .ptr = 10, .size = 11},
        {.s = US"received", .ptr = 8, .size = 9},
        {.s = US"auto-submitted", .ptr = 14, .size = 15}
        };
      static const gstring * end = ignore + nelem(ignore);
      gstring * i;

      for (i = ignore; i < end && !eq_asciicase(hname, i,  FALSE); ++i);
      if (i == end)
        {
	hname = string_fmt_append(NULL, "%Y%Y: %Y\n", header, hname, hvalue);
	(void) string_from_gstring(hname);
	/*XXX we seem to do nothing with this new hname? */
        }
      }
    if (*uri == '&') ++uri;
    else break;
    }
if (*uri)
  {
  filter->errmsg = US"Syntactically invalid URI";
  goto bad;
  }
return 1;

bad:
  FDEBUG debug_printf_indent("%s\n", filter->errmsg);
  return -1;
}
#endif


/*************************************************
*          Octet-wise string comparison          *
*************************************************/

/*
Arguments:
  needle            UTF-8 string to search ...
  haystack          ... inside the haystack
  match_prefix      TRUE to compare if needle is a prefix of haystack

Returns:      0               needle not found in haystack
              1               needle found
*/

static int
eq_octet(const gstring * needle, const gstring * haystack, BOOL match_prefix)
{
size_t nl, hl;
const uschar *n, *h;

nl = needle->ptr;
n = needle->s;
hl = haystack->ptr;
h = haystack->s;
while (nl>0 && hl>0)
  {
#if !HAVE_ICONV
  if (*n & 0x80) return 0;
  if (*h & 0x80) return 0;
#endif
  if (*n != *h) return 0;
  ++n;
  ++h;
  --nl;
  --hl;
  }
return (match_prefix ? nl == 0 : nl == 0 && hl == 0);
}


/*************************************************
*    ASCII case-insensitive string comparison    *
*************************************************/

/*
Arguments:
  needle            UTF-8 string to search ...
  haystack          ... inside the haystack
  match_prefix      TRUE to compare if needle is a prefix of haystack

Returns:      0               needle not found in haystack
              1               needle found
*/

static int
eq_asciicase(const gstring *needle, const gstring *haystack, BOOL match_prefix)
{
size_t nl, hl;
const uschar *n, *h;
uschar nc, hc;

nl = needle->ptr;
n = needle->s;
hl = haystack->ptr;
h = haystack->s;
while (nl > 0 && hl > 0)
  {
  nc = *n;
  hc = *h;
#if !HAVE_ICONV
  if (nc & 0x80) return 0;
  if (hc & 0x80) return 0;
#endif
  /* tolower depends on the locale and only ASCII case must be insensitive */
  if ((nc >= 'A' && nc <= 'Z' ? nc | 0x20 : nc) != (hc >= 'A' && hc <= 'Z' ? hc | 0x20 : hc)) return 0;
  ++n;
  ++h;
  --nl;
  --hl;
  }
return (match_prefix ? nl == 0 : nl == 0 && hl == 0);
}


/*************************************************
*              Glob pattern search               *
*************************************************/

/*
Arguments:
  needle          pattern to search ...
  haystack        ... inside the haystack
  ascii_caseless  ignore ASCII case
  match_octet     match octets, not UTF-8 multi-octet characters

Returns:      0               needle not found in haystack
              1               needle found
              -1              pattern error
*/

static int
eq_glob(const gstring *needle,
  const gstring *haystack, BOOL ascii_caseless, BOOL match_octet)
{
const uschar *n, *h, *nend, *hend;
int may_advance = 0;

n = needle->s;
h = haystack->s;
nend = n+needle->ptr;
hend = h+haystack->ptr;
while (n < nend)
  if (*n == '*')
    {
    ++n;
    may_advance = 1;
    }
  else
    {
    const uschar *npart, *hpart;

    /* Try to match a non-star part of the needle at the current */
    /* position in the haystack.                                 */
    match_part:
    npart = n;
    hpart = h;
    while (npart<nend && *npart != '*') switch (*npart)
      {
      case '?':
        {
        if (hpart == hend) return 0;
        if (match_octet)
          ++hpart;
        else
          {
          /* Match one UTF8 encoded character */
          if ((*hpart&0xc0) == 0xc0)
            {
            ++hpart;
            while (hpart<hend && ((*hpart&0xc0) == 0x80)) ++hpart;
            }
          else
            ++hpart;
          }
        ++npart;
        break;
        }
      case '\\':
        {
        ++npart;
        if (npart == nend)
	  {
	  FDEBUG debug_printf_indent("glob pattern error\n");
	  return -1;
	  }
        /* FALLTHROUGH */
        }
      default:
        {
        if (hpart == hend) return 0;
        /* tolower depends on the locale, but we need ASCII */
        if
          (
#if !HAVE_ICONV
          (*hpart&0x80) || (*npart&0x80) ||
#endif
          ascii_caseless
          ? ((*npart>= 'A' && *npart<= 'Z' ? *npart|0x20 : *npart) != (*hpart>= 'A' && *hpart<= 'Z' ? *hpart|0x20 : *hpart))
          : *hpart != *npart
          )
          {
          if (may_advance)
            /* string match after a star failed, advance and try again */
            {
            ++h;
            goto match_part;
            }
          else return 0;
          }
        else
          {
          ++npart;
          ++hpart;
          };
        }
      }
    /* at this point, a part was matched successfully */
    if (may_advance && npart == nend && hpart<hend)
      /* needle ends, but haystack does not: if there was a star before, advance and try again */
      {
      ++h;
      goto match_part;
      }
    h = hpart;
    n = npart;
    may_advance = 0;
    }
return (h == hend ? 1 : may_advance);
}


/*************************************************
*    ASCII numeric comparison                    *
*************************************************/

/*
Arguments:
  a                 first numeric string
  b                 second numeric string
  relop             relational operator

Returns:      0               not (a relop b)
              1               a relop b
*/

static int
eq_asciinumeric(const gstring *a, const gstring *b, enum RelOp relop)
{
size_t al, bl;
const uschar *as, *aend, *bs, *bend;
int cmp;

as = a->s;
aend = a->s+a->ptr;
bs = b->s;
bend = b->s+b->ptr;

while (*as>= '0' && *as<= '9' && as<aend) ++as;
al = as-a->s;
while (*bs>= '0' && *bs<= '9' && bs<bend) ++bs;
bl = bs-b->s;

if (al && bl == 0) cmp = -1;
else if (al == 0 && bl == 0) cmp = 0;
else if (al == 0 && bl) cmp = 1;
else
  {
  cmp = al-bl;
  if (cmp == 0) cmp = memcmp(a->s, b->s, al);
  }
switch (relop)
  {
  case LT: return cmp < 0;
  case LE: return cmp <= 0;
  case EQ: return cmp == 0;
  case GE: return cmp >= 0;
  case GT: return cmp > 0;
  case NE: return cmp != 0;
  }
  /*NOTREACHED*/
  return -1;
}


/*************************************************
*             Compare strings                    *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  needle      UTF-8 pattern or string to search ...
  haystack    ... inside the haystack
  co          comparator to use
  mt          match type to use

Returns:      0               needle not found in haystack
              1               needle found
              -1              comparator does not offer matchtype
*/

static int
compare(struct Sieve * filter, const gstring * needle, const gstring * haystack,
  enum Comparator co, enum MatchType mt)
{
int r = 0;

if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
  {
  debug_printf_indent("String comparison (match ");
  switch (mt)
    {
    case MATCH_IS: debug_printf_indent(":is"); break;
    case MATCH_CONTAINS: debug_printf_indent(":contains"); break;
    case MATCH_MATCHES: debug_printf_indent(":matches"); break;
    }
  debug_printf_indent(", comparison \"");
  switch (co)
    {
    case COMP_OCTET: debug_printf_indent("i;octet"); break;
    case COMP_EN_ASCII_CASEMAP: debug_printf_indent("en;ascii-casemap"); break;
    case COMP_ASCII_NUMERIC: debug_printf_indent("i;ascii-numeric"); break;
    }
  debug_printf_indent("\"):\n");
  debug_printf_indent("  Search = %.*W (%d chars)\n",
				  needle->ptr, needle->s, needle->ptr);
  debug_printf_indent("  Inside = %.*W (%d chars)\n",
				  haystack->ptr, haystack->s, haystack->ptr);
  }
switch (mt)
  {
  case MATCH_IS:
    switch (co)
      {
      case COMP_OCTET:
        if (eq_octet(needle, haystack, FALSE)) r = 1;
        break;
      case COMP_EN_ASCII_CASEMAP:
        if (eq_asciicase(needle, haystack, FALSE)) r = 1;
        break;
      case COMP_ASCII_NUMERIC:
        if (!filter->require_iascii_numeric)
          {
          filter->errmsg = US"missing previous require \"comparator-i;ascii-numeric\";";
          return -1;
          }
        if (eq_asciinumeric(needle, haystack, EQ)) r = 1;
        break;
      }
    break;

  case MATCH_CONTAINS:
    {
    gstring h;

    switch (co)
      {
      case COMP_OCTET:
        for (h = *haystack; h.ptr; ++h.s, --h.ptr)
	 if (eq_octet(needle, &h, TRUE)) { r = 1; break; }
        break;
      case COMP_EN_ASCII_CASEMAP:
        for (h = *haystack; h.ptr; ++h.s, --h.ptr)
	  if (eq_asciicase(needle, &h, TRUE)) { r = 1; break; }
        break;
      default:
        filter->errmsg = US"comparator does not offer specified matchtype";
        return -1;
      }
    break;
    }

  case MATCH_MATCHES:
    switch (co)
      {
      case COMP_OCTET:
        if ((r = eq_glob(needle, haystack, FALSE, TRUE)) == -1)
          {
          filter->errmsg = US"syntactically invalid pattern";
          return -1;
          }
        break;
      case COMP_EN_ASCII_CASEMAP:
        if ((r = eq_glob(needle, haystack, TRUE, TRUE)) == -1)
          {
          filter->errmsg = US"syntactically invalid pattern";
          return -1;
          }
        break;
      default:
        filter->errmsg = US"comparator does not offer specified matchtype";
        return -1;
      }
    break;
  }
if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
  debug_printf_indent("  Result %s\n", r?"true":"false");
return r;
}


/*************************************************
*         Check header field syntax              *
*************************************************/

/*
RFC 2822, section 3.6.8 says:

  field-name      =       1*ftext

  ftext           =       %d33-57 /               ; Any character except
                          %d59-126                ;  controls, SP, and
                                                  ;  ":".

That forbids 8-bit header fields.  This implementation accepts them, since
all of Exim is 8-bit clean, so it adds %d128-%d255.

Arguments:
  header      header field to quote for suitable use in Exim expansions

Returns:      0               string is not a valid header field
              1               string is a value header field
*/

static int
is_header(const gstring *header)
{
size_t l;
const uschar *h;

l = header->ptr;
h = header->s;
if (l == 0) return 0;
while (l)
  {
  if (*h < 33 || *h == ':' || *h == 127)
    return 0;
  ++h;
  --l;
  }
return 1;
}


/*************************************************
*       Quote special characters string          *
*************************************************/

/*
Arguments:
  header      header field to quote for suitable use in Exim expansions
              or as debug output

Returns:      quoted string
*/

static const uschar *
quote(const gstring * header)
{
gstring * quoted = NULL;
size_t l;
const uschar * h;

for (l = header->ptr, h = header->s; l; ++h, --l)
  switch (*h)
    {
    case '\0':
      quoted = string_catn(quoted, US"\\0", 2);
      break;
    case '$':
    case '{':
    case '}':
      quoted = string_catn(quoted, US"\\", 1);
    default:
      quoted = string_catn(quoted, h, 1);
    }

return string_from_gstring(quoted);
}


/*************************************************
*   Add address to list of generated addresses   *
*************************************************/

/*
According to RFC 5228, duplicate delivery to the same address must
not happen, so the list is first searched for the address.

Arguments:
  generated   list of generated addresses
  addr        new address to add
  file        address denotes a file

Returns:      nothing
*/

static void
add_addr(address_item ** generated, const uschar * addr, int file, int maxage,
  int maxmessages, int maxstorage)
{
address_item * new_addr;

for (new_addr = *generated; new_addr; new_addr = new_addr->next)
  if (  Ustrcmp(new_addr->address, addr) == 0
     && (  !file
	|| testflag(new_addr, af_pfr)
	|| testflag(new_addr, af_file)
	)
     )
    {
    if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
      debug_printf_indent("Repeated %s `%s' ignored.\n",
			  file ? "fileinto" : "redirect", addr);

    return;
    }

if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
  debug_printf_indent("%s `%s'\n", file ? "fileinto" : "redirect", addr);

new_addr = deliver_make_addr(addr, TRUE);
if (file)
  {
  setflag(new_addr, af_pfr);
  setflag(new_addr, af_file);
  new_addr->mode = 0;
  }
new_addr->prop.errors_address = NULL;
new_addr->next = *generated;
*generated = new_addr;
}


/*************************************************
*         Return decoded header field            *
*************************************************/

/*
Unfold the header field as described in RFC 2822 and remove all
leading and trailing white space, then perform MIME decoding and
translate the header field to UTF-8.

Arguments:
  value       returned value of the field
  header      name of the header field

Returns:      nothing          The expanded string is empty
                               in case there is no such header
*/

static void
expand_header(gstring * value, const gstring * header)
{
uschar *s, *r, *t;
uschar *errmsg;
const uschar * cs;

value->ptr = 0;
value->s = NULL;

t = r = s = expand_string(string_sprintf("$rheader_%s", quote(header)));
if (!t) return;
while (*r == ' ' || *r == '\t') ++r;
while (*r)
  if (*r == '\n')
    ++r;
  else
    *t++ = *r++;

while (t>s && (*(t-1) == ' ' || *(t-1) == '\t')) --t;
*t = '\0';
cs = rfc2047_decode(s, check_rfc2047_length, US"utf-8", '\0', &value->ptr, &errmsg);

/* possible embedded NUL, so not string_copyn() */
memcpy((value->s = store_get(value->ptr, cs)), cs, (size_t)value->ptr);
}


/*************************************************
*        Parse remaining hash comment            *
*************************************************/

/*
Token definition:
  Comment up to terminating CRLF

Arguments:
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int
parse_hashcomment(struct Sieve * filter)
{
++filter->pc;
while (*filter->pc)
  {
#ifdef RFC_EOL
  if (*filter->pc == '\r' && (filter->pc)[1] == '\n')
#else
  if (*filter->pc == '\n')
#endif
    {
#ifdef RFC_EOL
    filter->pc += 2;
#else
    ++filter->pc;
#endif
    ++filter->line;
    return 1;
    }
  else ++filter->pc;
  }
filter->errmsg = US"missing end of comment";
FDEBUG debug_printf_indent("%s\n", filter->errmsg);
return -1;
}


/*************************************************
*       Parse remaining C-style comment          *
*************************************************/

/*
Token definition:
  Everything up to star slash

Arguments:
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int
parse_comment(struct Sieve *filter)
{
filter->pc += 2;
while (*filter->pc)
  if (*filter->pc == '*' && (filter->pc)[1] == '/')
    {
    filter->pc +=  2;
    return 1;
    }
  else
    ++filter->pc;

filter->errmsg = US"missing end of comment";
FDEBUG debug_printf_indent("%s\n", filter->errmsg);
return -1;
}


/*************************************************
*         Parse optional white space             *
*************************************************/

/*
Token definition:
  Spaces, tabs, CRLFs, hash comments or C-style comments

Arguments:
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int
parse_white(struct Sieve *filter)
{
while (*filter->pc)
  {
  if (*filter->pc == ' ' || *filter->pc == '\t') ++filter->pc;
#ifdef RFC_EOL
  else if (*filter->pc == '\r' && (filter->pc)[1] == '\n')
#else
  else if (*filter->pc == '\n')
#endif
    {
#ifdef RFC_EOL
    filter->pc +=  2;
#else
    ++filter->pc;
#endif
    ++filter->line;
    }
  else if (*filter->pc == '#')
    {
    if (parse_hashcomment(filter) == -1) return -1;
    }
  else if (*filter->pc == '/' && (filter->pc)[1] == '*')
    {
    if (parse_comment(filter) == -1) return -1;
    }
  else break;
  }
return 1;
}


#ifdef ENCODED_CHARACTER
/*************************************************
*      Decode hex-encoded-character string       *
*************************************************/

/*
Encoding definition:
   blank                = SP / TAB / CRLF
   hex-pair-seq         = *blank hex-pair *(1*blank hex-pair) *blank
   hex-pair             = 1*2HEXDIG

Arguments:
  src         points to a hex-pair-seq
  end         points to its end
  dst         points to the destination of the decoded octets,
              optionally to (uschar*)0 for checking only

Returns:      >= 0              number of decoded octets
              -1               syntax error
*/

static int
hex_decode(const uschar * src, const uschar * end, uschar * dst)
{
int decoded = 0;

while (*src == ' ' || *src == '\t' || *src == '\n') ++src;
do
  {
  int x, d, n;

  for (x = 0, d = 0;
      d<2 && src<end && isxdigit(n = tolower(*src));
      x = (x<<4)|(n>= '0' && n<= '9' ? n-'0' : 10+(n-'a')) , ++d, ++src) ;
  if (d == 0) return -1;
  if (dst) *dst++ = x;
  ++decoded;
  if (src == end) return decoded;
  if (*src == ' ' || *src == '\t' || *src == '\n')
    while (*src == ' ' || *src == '\t' || *src == '\n') ++src;
  else
    {
    FDEBUG debug_printf_indent("hex decode: bad syntax\n");
    return -1;
    }
  }
while (src < end);
return decoded;
}


/*************************************************
*    Decode unicode-encoded-character string     *
*************************************************/

/*
Encoding definition:
   blank                = SP / TAB / CRLF
   unicode-hex-seq      = *blank unicode-hex *(blank unicode-hex) *blank
   unicode-hex          = 1*HEXDIG

   It is an error for a script to use a hexadecimal value that isn't in
   either the range 0 to D7FF or the range E000 to 10FFFF.

   At this time, strings are already scanned, thus the CRLF is converted
   to the internally used \n (should RFC_EOL have been used).

Arguments:
  src         points to a unicode-hex-seq
  end         points to its end
  dst         points to the destination of the decoded octets,
              optionally to (uschar*)0 for checking only

Returns:      >= 0              number of decoded octets
              -1               syntax error
              -2               semantic error (character range violation)
*/

static int
unicode_decode(const uschar * src, const uschar * end, uschar * dst)
{
int decoded = 0;

while (*src == ' ' || *src == '\t' || *src == '\n') ++src;
do
  {
  const uschar * hex_seq;
  int c, d, n;

  unicode_hex:
  for (hex_seq = src; src < end && *src == '0'; ) src++;
  for (c = 0, d = 0;
       d < 7 && src < end && isxdigit(n = tolower(*src));
       c = (c<<4)|(n>= '0' && n<= '9' ? n-'0' : 10+(n-'a')), ++d, ++src) ;
  if (src == hex_seq)
    {
    FDEBUG debug_printf_indent("unicode decode: bad syntax\n");
    return -1;
    }
  if (d == 7 || (!((c >= 0 && c <= 0xd7ff) || (c >= 0xe000 && c <= 0x10ffff))))
    {
    FDEBUG debug_printf_indent("unicode decode: char not in range\n");
    return -2;
    }
  if (c<128)
    {
    if (dst) *dst++ = c;
    ++decoded;
    }
  else if (c <= 0x7ff)
    {
    if (dst)
      {
      *dst++ = 192+(c>>6);
      *dst++ = 128+(c&0x3f);
      }
    decoded += 2;
    }
  else if (c <= 0xffff)
    {
    if (dst)
      {
      *dst++ = 224+(c>>12);
      *dst++ = 128+((c>>6)&0x3f);
      *dst++ = 128+(c&0x3f);
      }
    decoded += 3;
    }
  else if (c <= 0x1fffff)
    {
    if (dst)
      {
      *dst++ = 240+(c>>18);
      *dst++ = 128+((c>>10)&0x3f);
      *dst++ = 128+((c>>6)&0x3f);
      *dst++ = 128+(c&0x3f);
      }
    decoded += 4;
    }
  if (*src == ' ' || *src == '\t' || *src == '\n')
    {
    while (*src == ' ' || *src == '\t' || *src == '\n') ++src;
    if (src == end) return decoded;
    goto unicode_hex;
    }
  }
while (src < end);
return decoded;
}


/*************************************************
*       Decode encoded-character string          *
*************************************************/

/*
Encoding definition:
   encoded-arb-octets   = "${hex:" hex-pair-seq "}"
   encoded-unicode-char = "${unicode:" unicode-hex-seq "}"

Arguments:
  encoded     points to an encoded string, returns decoded string
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int
string_decode(struct Sieve * filter, gstring * data)
{
uschar * src, * dst;
const uschar * end;

src = data->s;
dst = src;
end = data->s+data->ptr;
while (src < end)
  {
  uschar * brace;

  if (
      strncmpic(src, US "${hex:", 6) == 0
      && (brace = Ustrchr(src+6, '}')) != (uschar*)0
      && (hex_decode(src+6, brace, (uschar*)0))>= 0
     )
    {
    dst += hex_decode(src+6, brace, dst);
    src = brace+1;
    }
  else if (
           strncmpic(src, US "${unicode:", 10) == 0
           && (brace = Ustrchr(src+10, '}')) != (uschar*)0
          )
    {
    switch (unicode_decode(src+10, brace, (uschar*)0))
      {
      case -2:
        {
        filter->errmsg = US"unicode character out of range";
        return -1;
        }
      case -1:
        {
        *dst++ = *src++;
        break;
        }
      default:
        {
        dst += unicode_decode(src+10, brace, dst);
        src = brace+1;
        }
      }
    }
  else *dst++ = *src++;
  }
  data->ptr = dst-data->s;
  *dst = '\0';
return 1;
}
#endif


/*************************************************
*          Parse an optional string              *
*************************************************/

/*
Token definition:
   quoted-string = DQUOTE *CHAR DQUOTE
           ;; in general, \ CHAR inside a string maps to CHAR
           ;; so \" maps to " and \\ maps to \
           ;; note that newlines and other characters are all allowed
           ;; in strings

   multi-line          = "text:" *(SP / HTAB) (hash-comment / CRLF)
                         *(multi-line-literal / multi-line-dotstuff)
                         "." CRLF
   multi-line-literal  = [CHAR-NOT-DOT *CHAR-NOT-CRLF] CRLF
   multi-line-dotstuff = "." 1*CHAR-NOT-CRLF CRLF
           ;; A line containing only "." ends the multi-line.
           ;; Remove a leading '.' if followed by another '.'.
  string           = quoted-string / multi-line

Arguments:
  filter	points to the Sieve filter including its state
  data		place to return the string
  errstr	error message for no-string-found

Returns:      1                success
              -1               syntax error (errmsg will be set)
              0                no string found (errmsg set: errstr arg)
*/

static int
parse_string(struct Sieve * filter, gstring * data, const uschar * errstr)
{
gstring * g = NULL;

data->ptr = 0;
data->s = NULL;

if (*filter->pc == '"') /* quoted string */
  {
  ++filter->pc;
  while (*filter->pc)
    {
    if (*filter->pc == '"') /* end of string */
      {
      ++filter->pc;

      if (g)
	data->ptr = len_string_from_gstring(g, &data->s);
      else
	data->s = US"\0";
      /* that way, there will be at least one character allocated */

#ifdef ENCODED_CHARACTER
      if (   filter->require_encoded_character
          && string_decode(filter, data) == -1)
        return -1;
#endif
      return 1;
      }
    else if (*filter->pc == '\\' && (filter->pc)[1]) /* quoted character */
      {
      g = string_catn(g, filter->pc+1, 1);
      filter->pc +=  2;
      }
    else /* regular character */
      {
#ifdef RFC_EOL
      if (*filter->pc == '\r' && (filter->pc)[1] == '\n') ++filter->line;
#else
      if (*filter->pc == '\n')
        {
        g = string_catn(g, US"\r", 1);
        ++filter->line;
        }
#endif
      g = string_catn(g, filter->pc, 1);
      filter->pc++;
      }
    }
  filter->errmsg = US"missing end of string";
  goto bad;
  }
else if (Ustrncmp(filter->pc, US"text:", 5) == 0) /* multiline string */
  {
  filter->pc +=  5;
  /* skip optional white space followed by hashed comment or CRLF */
  while (*filter->pc == ' ' || *filter->pc == '\t') ++filter->pc;
  if (*filter->pc == '#')
    {
    if (parse_hashcomment(filter) == -1) return -1;
    }
#ifdef RFC_EOL
  else if (*filter->pc == '\r' && (filter->pc)[1] == '\n')
#else
  else if (*filter->pc == '\n')
#endif
    {
#ifdef RFC_EOL
    filter->pc +=  2;
#else
    ++filter->pc;
#endif
    ++filter->line;
    }
  else
    {
    filter->errmsg = US"syntax error";
    goto bad;
    }
  while (*filter->pc)
    {
#ifdef RFC_EOL
    if (*filter->pc == '\r' && (filter->pc)[1] == '\n') /* end of line */
#else
    if (*filter->pc == '\n') /* end of line */
#endif
      {
      g = string_catn(g, US"\r\n", 2);
#ifdef RFC_EOL
      filter->pc +=  2;
#else
      ++filter->pc;
#endif
      ++filter->line;
#ifdef RFC_EOL
      if (*filter->pc == '.' && (filter->pc)[1] == '\r' && (filter->pc)[2] == '\n') /* end of string */
#else
      if (*filter->pc == '.' && (filter->pc)[1] == '\n') /* end of string */
#endif
        {
	if (g)
	  data->ptr = len_string_from_gstring(g, &data->s);
	else
	  data->s = US"\0";
	/* that way, there will be at least one character allocated */

#ifdef RFC_EOL
        filter->pc +=  3;
#else
        filter->pc +=  2;
#endif
        ++filter->line;
#ifdef ENCODED_CHARACTER
        if (   filter->require_encoded_character
            && string_decode(filter, data) == -1)
          return -1;
#endif
        return 1;
        }
      else if (*filter->pc == '.' && (filter->pc)[1] == '.') /* remove dot stuffing */
        {
        g = string_catn(g, US".", 1);
        filter->pc +=  2;
        }
      }
    else /* regular character */
      {
      g = string_catn(g, filter->pc, 1);
      filter->pc++;
      }
    }
  filter->errmsg = US"missing end of multi line string";
  goto bad;
  }

filter->errmsg = errstr;
return 0;

bad:
  FDEBUG debug_printf_indent("%s\n", filter->errmsg);
  return -1;
}


/*************************************************
*          Parse a specific identifier           *
*************************************************/

/*
Token definition:
  identifier       = (ALPHA / "_") *(ALPHA DIGIT "_")

Arguments:
  filter      points to the Sieve filter including its state
  id          specifies identifier to match
  why		context of parsing, for debug

Returns:      1                success
              0                identifier not matched
*/

static int
parse_identifier(struct Sieve * filter, const uschar * id, const uschar * why)
{
size_t idlen = Ustrlen(id);

if (strncmpic(US filter->pc, US id, idlen) == 0)
  {
  uschar next = filter->pc[idlen];

  if (  next >= 'A' && next <= 'Z'
     || next >= 'a' && next <= 'z'
     || next == '_'
     || next >= '0' && next <= '9'
     ) return 0;

  FDEBUG
    debug_printf_indent("identified: %s '%.*s'\n", why, (int)idlen, filter->pc);
  filter->pc += idlen;
  return 1;
  }
else return 0;
}


/*************************************************
*                 Parse a number                 *
*************************************************/

/*
Token definition:
  number           = 1*DIGIT [QUANTIFIER]
  QUANTIFIER       = "K" / "M" / "G"

Arguments:
  filter      points to the Sieve filter including its state
  data        returns value

Returns:      1                success
              -1               no string list found
*/

static int
parse_number(struct Sieve *filter, unsigned long *data)
{
if (*filter->pc>= '0' && *filter->pc<= '9')
  {
  unsigned long d, u;
  uschar * e;

  errno = 0;
  d = Ustrtoul(filter->pc, &e, 10);
  if (errno == ERANGE)
    {
    filter->errmsg = CUstrerror(ERANGE);
    goto bad;
    }
  filter->pc = e;
  u = 1;
  if (*filter->pc == 'K') { u = 1024; ++filter->pc; }
  else if (*filter->pc == 'M') { u = 1024*1024; ++filter->pc; }
  else if (*filter->pc == 'G') { u = 1024*1024*1024; ++filter->pc; }
  if (d>(ULONG_MAX/u))
    {
    filter->errmsg = CUstrerror(ERANGE);
    goto bad;
    }
  d *= u;
  *data = d;
  return 1;
  }

filter->errmsg = US"missing number";

bad:
  FDEBUG debug_printf_indent("%s\n", filter->errmsg);
  return -1;
}


/*************************************************
*              Parse a string list               *
*************************************************/

/*
Grammar:
  string-list      = "[" string *(", " string) "]" / string

Arguments:
  filter	points to the Sieve filter including its state
  data		returns string list as an array of gstrings,
		terminated by an empty one
  where		item being parsed, for error message

Returns:      1		success
	      0		no string found
              -1	syntax failure
*/

static int
parse_stringlist(struct Sieve * filter, gstring ** data, const uschar * where)
{
const uschar * orig = filter->pc;
int dataCapacity = 0;
int dataLength = 0;
gstring * d = NULL;
int m;

if (*filter->pc == '[') /* string list */
  {
  expand_level++;
  ++filter->pc;
  for (;;)
    {
    if (parse_white(filter) == -1) goto error;
    if (dataLength+1 >= dataCapacity) /* increase buffer */
      {
      gstring * new;

      dataCapacity = dataCapacity ? dataCapacity * 2 : 4;
      new = store_get(sizeof(gstring) * dataCapacity, GET_UNTAINTED);

      if (d) memcpy(new, d, sizeof(gstring)*dataLength);
      d = new;
      }

    m = parse_string(filter, &d[dataLength], US"missing string");
    if (m == 0)
      {
      if (dataLength == 0) break;
      FDEBUG debug_printf_indent("%s\n", filter->errmsg);
      goto error;
      }
    else if (m == -1) goto error;
    else ++dataLength;
    if (parse_white(filter) == -1) goto error;
    if (*filter->pc == ',') ++filter->pc;
    else break;
    }
  if (*filter->pc == ']')
    {
    d[dataLength].s = (uschar*)0;
    d[dataLength].ptr = -1;
    ++filter->pc;
    *data = d;
    expand_level--;
    return 1;
    }
  else
    {
    filter->errmsg = US"missing closing bracket";
    FDEBUG debug_printf_indent("%s\n", filter->errmsg);
    goto error;
    }
 error:
  expand_level--;
  filter->errmsg = string_sprintf("%s, in %s", filter->errmsg, where);
  FDEBUG debug_printf_indent("%s\n", filter->errmsg);
  return -1;
  }
else /* single string */
  {
  d = store_get(sizeof(gstring)*2, GET_UNTAINTED);

  if ((m = parse_string(filter, &d[0], NULL)) != 1)
    {
    filter->errmsg = string_sprintf("%s, in %s", filter->errmsg, where);
    if (m == 0)
      {
      filter->errmsg = string_sprintf("%s string list expected", where);
      filter->pc = orig;
      return 0;
      }
    return -1;
    }

  d[1].s = (uschar*)0;
  d[1].ptr = -1;
  *data = d;
  return 1;
  }
}


/*************************************************
*    Parse an optional address part specifier    *
*************************************************/

/*
Grammar:
  address-part     =  ":localpart" / ":domain" / ":all"
  address-part     = / ":user" / ":detail"

Arguments:
  filter      points to the Sieve filter including its state
  a           returns address part specified

Returns:      1                success
              0                no comparator found
              -1               syntax error
*/

static int
parse_addresspart(struct Sieve *filter, enum AddressPart *a)
{
#ifdef SUBADDRESS
if (parse_identifier(filter, US":user", US"address-part") == 1)
  {
  if (!filter->require_subaddress)
    {
    filter->errmsg = US"missing previous require \"subaddress\";";
    goto bad;
    }
  *a = ADDRPART_USER;
  return 1;
  }
else if (parse_identifier(filter, US":detail", US"address-part") == 1)
  {
  if (!filter->require_subaddress)
    {
    filter->errmsg = US"missing previous require \"subaddress\";";
    goto bad;
    }
  *a = ADDRPART_DETAIL;
  return 1;
  }
else
#endif
if (parse_identifier(filter, US":localpart", US"address-part") == 1)
  {
  *a = ADDRPART_LOCALPART;
  return 1;
  }
else if (parse_identifier(filter, US":domain", US"address-part") == 1)
  {
  *a = ADDRPART_DOMAIN;
  return 1;
  }
else if (parse_identifier(filter, US":all", US"address-part") == 1)
  {
  *a = ADDRPART_ALL;
  return 1;
  }
else return 0;

bad:
  FDEBUG debug_printf_indent("%s\n", filter->errmsg);
  return -1;
}


/*************************************************
*         Parse an optional comparator           *
*************************************************/

/*
Grammar:
  comparator = ":comparator" <comparator-name: string>

Arguments:
  filter      points to the Sieve filter including its state
  c           returns comparator

Returns:      1                success
              0                no comparator found
              -1               incomplete comparator found
*/

static int
parse_comparator(struct Sieve *filter, enum Comparator *c)
{
gstring comparator_name;

if (parse_identifier(filter, US":comparator", US"comparator name") == 0)
  return 0;
if (parse_white(filter) == -1) return -1;
if (parse_string(filter, &comparator_name, US"missing comparator") != 1)
  return -1;

if (eq_asciicase(&comparator_name, &str_ioctet, FALSE))
  *c = COMP_OCTET;
else if (eq_asciicase(&comparator_name, &str_iascii_casemap, FALSE))
  *c = COMP_EN_ASCII_CASEMAP;
else if (eq_asciicase(&comparator_name, &str_enascii_casemap, FALSE))
  *c = COMP_EN_ASCII_CASEMAP;
else if (eq_asciicase(&comparator_name, &str_iascii_numeric, FALSE))
  *c = COMP_ASCII_NUMERIC;
else
  {
  filter->errmsg = US"invalid comparator";
  return -1;
  }
return 1;
}


/*************************************************
*          Parse an optional match type          *
*************************************************/

/*
Grammar:
  match-type = ":is" / ":contains" / ":matches"

Arguments:
  filter      points to the Sieve filter including its state
  m           returns match type

Returns:      1                success
              0                no match type found
*/

static int
parse_matchtype(struct Sieve *filter, enum MatchType *m)
{
if (parse_identifier(filter, US":is", US"match type") == 1)
  { *m = MATCH_IS; return 1; }
else if (parse_identifier(filter, US":contains", US"match type") == 1)
  { *m = MATCH_CONTAINS; return 1; }
else if (parse_identifier(filter, US":matches", US"match type") == 1)
  { *m = MATCH_MATCHES; return 1; }
else return 0;
}

#ifdef BODY
/*************************************************
*          Parse an optional transform type      *
*************************************************/

/*
Grammar:
  xform-type = ":raw" / ":content" <content-types: string-list> / ":text"

Arguments:
  filter      points to the Sieve filter including its state
  m           returns match type

Returns:      1		success
              0		no match type found
	      -1	syntax error
*/

static int
parse_xformtype(struct Sieve * filter, enum XformType * m)
{
if (parse_identifier(filter, US":raw", US"transform type") == 1)
  { *m = XFORM_RAW; return 1; }
else if (parse_identifier(filter, US":content", US"transform type") == 1)
  {
  *m = XFORM_CONTENT;
  if (  parse_white(filter) == 1
     && (parse_stringlist(filter, &sieve_body_content_matchtypes,
			  US"content types")) == 1)
    {
debug_printf_indent("content_matchtypes: ");
for (gstring * g = sieve_body_content_matchtypes; g && g->s; g++)
  debug_printf(" %Y", g);
debug_printf("\n");
    return 1;
    }

  FDEBUG debug_printf_indent(" %s\n", filter->errmsg);
  return -1;
  }
else if (parse_identifier(filter, US":text", US"transform type") == 1)
  { *m = XFORM_TEXT; return 1; }
else return 0;
}
#endif	/*BODY*/


/*************************************************
*   Parse and interpret an optional test list    *
*************************************************/

/*
Grammar:
  test-list = "(" test *("," test) ")"

Arguments:
  filter      points to the Sieve filter including its state
  n           total number of tests
  num_true    number of passed tests
  exec        Execute parsed statements

Returns:      1                success
              0                no test list found
              -1               syntax or execution error
*/

static int
parse_testlist(struct Sieve *filter, int *n, int *num_true, BOOL exec)
{
if (parse_white(filter) == -1) return -1;
if (*filter->pc == '(')
  {
  ++filter->pc;
  *n = 0;
   *num_true = 0;
  for (;;)
    {
    BOOL cond;

    switch (parse_test(filter, &cond, exec))
      {
      case -1: return -1;
      case 0: filter->errmsg = US"missing test";
	      FDEBUG debug_printf_indent("%s\n", filter->errmsg);
	      return -1;
      default: ++*n; if (cond) ++*num_true; break;
      }
    if (parse_white(filter) == -1) return -1;
    if (*filter->pc == ',') ++filter->pc;
    else break;
    }
  if (*filter->pc == ')')
    {
    ++filter->pc;
    return 1;
    }
  else
    {
    filter->errmsg = US"missing closing paren";
    FDEBUG debug_printf_indent("%s\n", filter->errmsg);
    return -1;
    }
  }
else return 0;
}


/* Parse the options on a test.
Arguments:
  filter	points to the Sieve filter including its state
  a, c, m, x	pointers to result enums.  a & x can be null.

Return FALSE for a problem, else TRUE
*/

static BOOL
parse_a_c_m(struct Sieve * filter,
  enum AddressPart * a, enum Comparator * c,
  enum MatchType * m, enum XformType * x)
{
int i;
BOOL ap = FALSE, co = FALSE, mt = FALSE, xt = FALSE;

for (;;)
  {
  if (parse_white(filter) == -1) return FALSE;
  if (a && (i = parse_addresspart(filter, a)) != 0)
    {
    if (i == -1) return FALSE;
    if (ap)
      { filter->errmsg = US"address part already specified"; return FALSE; }
    ap = TRUE;
    }
  else if ((i = parse_comparator(filter, c)) != 0)
    {
    if (i == -1) return FALSE;
    if (co)
      { filter->errmsg = US"comparator already specified"; return FALSE; }
    co = TRUE;
    }
  else if ((i = parse_matchtype(filter, m)) != 0)
    {
    if (i == -1) return FALSE;
    if (mt)
      { filter->errmsg = US"match type already specified"; return FALSE; }
    mt = TRUE;
    }
#ifdef BODY
  else if (x && (i = parse_xformtype(filter, x)) != 0)
    {
    if (i == -1) return FALSE;
    if (xt)
      { filter->errmsg = US"transform type already specified"; return FALSE; }
    xt = TRUE;
    }
#endif
  else
    return TRUE;
  }
}

/*************************************************
*     Parse and interpret an optional test       *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  cond        returned condition status
  exec        Execute parsed statements

Returns:      1                success
              0                no test found
              -1               syntax or execution error
*/

static int
parse_test(struct Sieve * filter, BOOL * cond, BOOL exec)
{
if (parse_white(filter) == -1) goto bad;
if (parse_identifier(filter, US"address", US"test type"))
  {
  /*
  address-test = "address" { [address-part] [comparator] [match-type] }
                 <header-list: string-list> <key-list: string-list>

  header-list From, To, Cc, Bcc, Sender, Resent-From, Resent-To
  */

  enum AddressPart addressPart = ADDRPART_ALL;
  enum Comparator comparator = COMP_EN_ASCII_CASEMAP;
  enum MatchType matchType = MATCH_IS;
  gstring *hdr, *key;
  int m;

  if (!parse_a_c_m(filter, &addressPart, &comparator, &matchType, NULL))
    goto bad;
    
  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &hdr, US"header")) != 1)
    goto bad;
  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &key, US"key")) != 1)
    goto bad;
  *cond = FALSE;
  for (gstring * h = hdr; h->ptr != -1 && !*cond; ++h)
    {
    const uschar * header_value = NULL;
    uschar * extracted_addr;

    if (  !eq_asciicase(h, &str_from, FALSE)
       && !eq_asciicase(h, &str_to, FALSE)
       && !eq_asciicase(h, &str_cc, FALSE)
       && !eq_asciicase(h, &str_bcc, FALSE)
       && !eq_asciicase(h, &str_sender, FALSE)
       && !eq_asciicase(h, &str_resent_from, FALSE)
       && !eq_asciicase(h, &str_resent_to, FALSE)
       )
      {
      filter->errmsg = US"invalid header field";
      goto bad;
      }
    if (exec)
      {
      /* We are only interested in addresses below, so no MIME decoding */
      if (!(header_value = expand_string(string_sprintf("$rheader_%s", quote(h)))))
        {
        filter->errmsg = US"header string expansion failed";
        goto bad;
        }
      f.parse_allow_group = TRUE;
      while (*header_value && !*cond)
        {
        uschar * part = NULL, * error;
	const uschar * end_addr, * ss;
        int start, end, domain;

        end_addr = parse_find_address_end(header_value, FALSE);
	ss = *end_addr
	  ? header_value : string_copyn(header_value, end_addr - header_value);
        extracted_addr = parse_extract_address(ss, &error,
						&start, &end, &domain, FALSE);

        if (extracted_addr) switch (addressPart)
          {
          case ADDRPART_ALL: part = extracted_addr; break;
#ifdef SUBADDRESS
          case ADDRPART_USER:
#endif
          case ADDRPART_LOCALPART: part = extracted_addr; part[domain-1] = '\0'; break;
          case ADDRPART_DOMAIN: part = extracted_addr+domain; break;
#ifdef SUBADDRESS
          case ADDRPART_DETAIL: part = NULL; break;
#endif
          }

        if (part && extracted_addr)
	  {
	  gstring partStr = {.s = part, .ptr = Ustrlen(part), .size = Ustrlen(part)+1};
          for (gstring * k = key; k->ptr != - 1; ++k)
	    switch (compare(filter, k, &partStr, comparator, matchType))
	      {
	      case -1: goto bad;
	      case +1: *cond = TRUE; goto a_done;
	      }
	  a_done: ;
	  }

        if (*end_addr) break;
        header_value = end_addr + 1;
        }
      f.parse_allow_group = FALSE;
      f.parse_found_group = FALSE;
      }
    }
  return 1;
  }
else if (parse_identifier(filter, US"allof", US"test type"))
  {
  /*
  allof-test   = "allof" <tests: test-list>
  */

  int n, num_true;

  switch (parse_testlist(filter, &n, &num_true, exec))
    {
    case -1: goto bad;
    case 0: filter->errmsg = US"missing test list"; goto bad;
    default: *cond = (n == num_true); return 1;
    }
  }
else if (parse_identifier(filter, US"anyof", US"test type"))
  {
  /*
  anyof-test   = "anyof" <tests: test-list>
  */

  int n, num_true;

  switch (parse_testlist(filter, &n, &num_true, exec))
    {
    case -1: goto bad;
    case 0: filter->errmsg = US"missing test list"; goto bad;
    default: *cond = (num_true > 0); return 1;
    }
  }
else if (parse_identifier(filter, US"exists", US"test type"))
  {
  /*
  exists-test = "exists" <header-names: string-list>
  */

  gstring *hdr;
  int m;

  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &hdr, US"header")) != 1)
    goto bad;
  if (exec)
    {
    *cond = TRUE;
    for (gstring * h = hdr; h->ptr != -1 && *cond; ++h)
      {
      const uschar * header_def = expand_string(string_sprintf(
				"${if def:header_%s {true}{false}}", quote(h)));
      if (!header_def)
        {
        filter->errmsg = US"header string expansion failed";
        goto bad;
        }
      if (Ustrcmp(header_def,"false") == 0) *cond = FALSE;
      }
    }
  return 1;
  }
else if (parse_identifier(filter, US"false", US"test type"))
  {
  /*
  false-test = "false"
  */

  *cond = FALSE;
  return 1;
  }
else if (parse_identifier(filter, US"header", US"test type"))
  {
  /*
  header-test = "header" { [comparator] [match-type] }
                <header-names: string-list> <key-list: string-list>
  */

  enum Comparator comparator = COMP_EN_ASCII_CASEMAP;
  enum MatchType matchType = MATCH_IS;
  gstring *hdr, *key;
  int m;

  if (!parse_a_c_m(filter, NULL, &comparator, &matchType, NULL))
    goto bad;
    
  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &hdr, US"header")) != 1)
    goto bad;
  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &key, US"key")) != 1)
    goto bad;
  *cond = FALSE;
  for (gstring * h = hdr; h->ptr != -1 && !*cond; ++h)
    {
    if (!is_header(h))
      {
      filter->errmsg = US"invalid header field";
      goto bad;
      }
    if (exec)
      {
      gstring header_value;
      const uschar * header_def;

      expand_header(&header_value, h);
      header_def = expand_string(string_sprintf(
				"${if def:header_%s {true}{false}}", quote(h)));
      if (!header_value.s || !header_def)
        {
        filter->errmsg = US"header string expansion failed";
        goto bad;
        }
      for (gstring * k = key; k->ptr != -1; ++k)
	  switch (compare(filter, k, &header_value, comparator, matchType))
	    {
	    case -1: goto bad;
	    case +1: *cond = TRUE; goto h_done;
	    }
      h_done: ;
      }
    }
  return 1;
  }
else if (parse_identifier(filter, US"not", US"test type"))
  {
  if (parse_white(filter) == -1) goto bad;
  switch (parse_test(filter, cond, exec))
    {
    case -1: goto bad;
    case 0: filter->errmsg = US"missing test"; goto bad;
    default: *cond = !*cond; return 1;
    }
  }
else if (parse_identifier(filter, US"size", US"test type"))
  {
  /*
  relop = ":over" / ":under"
  size-test = "size" relop <limit: number>
  */

  unsigned long limit;
  int overNotUnder;

  if (parse_white(filter) == -1) goto bad;
  if (parse_identifier(filter, US":over", US"test type")) overNotUnder = 1;
  else if (parse_identifier(filter, US":under", US"test type")) overNotUnder = 0;
  else
    {
    filter->errmsg = US"missing :over or :under";
    goto bad;
    }
  if (parse_white(filter) == -1) goto bad;
  if (parse_number(filter, &limit) == -1) goto bad;
  *cond = overNotUnder ? (message_size > limit) : (message_size < limit);
  return 1;
  }
else if (parse_identifier(filter, US"true", US"test type"))
  {
  *cond = TRUE;
  return 1;
  }
else if (parse_identifier(filter, US"envelope", US"test type"))
  {
  /*
  envelope-test = "envelope" { [comparator] [address-part] [match-type] }
                  <envelope-part: string-list> <key-list: string-list>

  envelope-part is case insensitive "from" or "to"
#ifdef ENVELOPE_AUTH
  envelope-part = / "auth"
#endif
  */

  enum Comparator comparator = COMP_EN_ASCII_CASEMAP;
  enum AddressPart addressPart = ADDRPART_ALL;
  enum MatchType matchType = MATCH_IS;
  gstring *env, *key;
  int m;

  if (!filter->require_envelope)
    {
    filter->errmsg = US"missing previous require \"envelope\";";
    goto bad;
    }

  if (!parse_a_c_m(filter, &addressPart, &comparator, &matchType, NULL))
    goto bad;
    
  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &env, US"envelope")) != 1)
    goto bad;
  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &key, US"key")) != 1)
    goto bad;
  *cond = FALSE;
  for (gstring * e = env; e->ptr != -1 && !*cond; ++e)
    {
    const uschar * envelopeExpr = NULL;

    if (eq_asciicase(e, &str_from, FALSE))
      {
      switch (addressPart)
        {
        case ADDRPART_ALL: envelopeExpr = US"$sender_address"; break;
#ifdef SUBADDRESS
        case ADDRPART_USER:
#endif
        case ADDRPART_LOCALPART: envelopeExpr = US"${local_part:$sender_address}"; break;
        case ADDRPART_DOMAIN: envelopeExpr = US"${domain:$sender_address}"; break;
#ifdef SUBADDRESS
        case ADDRPART_DETAIL: envelopeExpr = NULL; break;
#endif
        }
      }
    else if (eq_asciicase(e, &str_to, FALSE))
      {
      switch (addressPart)
        {
        case ADDRPART_ALL: envelopeExpr = US"$local_part_prefix$local_part$local_part_suffix@$domain"; break;
#ifdef SUBADDRESS
        case ADDRPART_USER: envelopeExpr = filter->useraddress; break;
        case ADDRPART_DETAIL: envelopeExpr = filter->subaddress; break;
#endif
        case ADDRPART_LOCALPART: envelopeExpr = US"$local_part_prefix$local_part$local_part_suffix"; break;
        case ADDRPART_DOMAIN: envelopeExpr = US"$domain"; break;
        }
      }
#ifdef ENVELOPE_AUTH
    else if (eq_asciicase(e, &str_auth, FALSE))
      {
      switch (addressPart)
        {
        case ADDRPART_ALL: envelopeExpr = US"$authenticated_sender"; break;
#ifdef SUBADDRESS
        case ADDRPART_USER:
#endif
        case ADDRPART_LOCALPART: envelopeExpr = US"${local_part:$authenticated_sender}"; break;
        case ADDRPART_DOMAIN: envelopeExpr = US"${domain:$authenticated_sender}"; break;
#ifdef SUBADDRESS
        case ADDRPART_DETAIL: envelopeExpr = NULL; break;
#endif
        }
      }
#endif
    else
      {
      filter->errmsg = US"invalid envelope string";
      goto bad;
      }
    if (exec && envelopeExpr)
      {
      uschar * envelope;
      if (!(envelope = expand_string(US envelopeExpr)))
        {
        filter->errmsg = US"header string expansion failed";
        goto bad;
        }
      for (gstring * k = key; k->ptr != -1; ++k)
        {
        gstring envelopeStr = {.s = envelope, .ptr = Ustrlen(envelope), .size = Ustrlen(envelope)+1};

	switch (compare(filter, k, &envelopeStr, comparator, matchType))
	  {
	  case -1: goto bad;
	  case +1: *cond = TRUE; goto e_done;
	  }
        }
      e_done: ;
      }
    }
  return 1;
  }
#ifdef ENOTIFY
else if (parse_identifier(filter, US"valid_notify_method", US"test type"))
  {
  /*
  valid_notify_method = "valid_notify_method"
                        <notification-uris: string-list>
  */

  gstring *uris;
  int m;

  if (!filter->require_enotify)
    {
    filter->errmsg = US"missing previous require \"enotify\";";
    goto bad;
    }
  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &uris, US"URI")) != 1)
    goto bad;
  if (exec)
    {
    *cond = TRUE;
    for (gstring * u = uris; u->ptr != -1 && *cond; ++u)
      {
        string_item * recipient = NULL;
        gstring header =  { .s = NULL, .ptr = -1 };
        gstring subject = { .s = NULL, .ptr = -1 };
        gstring body =    { .s = NULL, .ptr = -1 };

        if (parse_mailto_uri(filter, u->s, &recipient, &header, &subject, &body) != 1)
          *cond = FALSE;
      }
    }
  return 1;
  }
else if (parse_identifier(filter, US"notify_method_capability", US"test type"))
  {
  /*
  notify_method_capability = "notify_method_capability" [COMPARATOR] [MATCH-TYPE]
                             <notification-uri: string>
                             <notification-capability: string>
                             <key-list: string-list>
  */

  int m;

  enum Comparator comparator = COMP_EN_ASCII_CASEMAP;
  enum MatchType matchType = MATCH_IS;
  gstring uri, capa, *keys;

  if (!filter->require_enotify)
    {
    filter->errmsg = US"missing previous require \"enotify\";";
    goto bad;
    }
  if (!parse_a_c_m(filter, NULL, &comparator, &matchType, NULL))
    goto bad;
    
  if (parse_string(filter, &uri, US"missing notification URI string") != 1)
    goto bad;
  if (parse_white(filter) == -1)
    goto bad;
  if (parse_string(filter, &capa, US"missing notification capability string") != 1)
    goto bad;
  if (parse_white(filter) == -1)
    goto bad;
  if ((m = parse_stringlist(filter, &keys, US"key")) != 1)
    goto bad;
  if (exec)
    {
    string_item * recipient = NULL;
    gstring header =  { .s = NULL, .ptr = -1 };
    gstring subject = { .s = NULL, .ptr = -1 };
    gstring body =    { .s = NULL, .ptr = -1 };

    *cond = FALSE;
    if (parse_mailto_uri(filter, uri.s, &recipient, &header, &subject, &body) == 1)
      if (eq_asciicase(&capa, &str_online,  FALSE) == 1)
	for (gstring * k = keys; k->ptr != -1; ++k)
	  switch (compare(filter, k, &str_maybe, comparator, matchType))
	    {
	    case -1: goto bad;
	    case +1: *cond = TRUE; goto i_done;
	    }
    i_done: ;
    }
  return 1;
  }
#endif	/*ENOTIFY*/
#ifdef BODY
else if (parse_identifier(filter, US"body", US"test type"))
  {
  /* RFC 5173
  body-test = "body" { [comparator] [match-type] [body-transform] }
                <key-list: string-list>
  */

  enum Comparator comparator = COMP_EN_ASCII_CASEMAP;
  enum MatchType matchType = MATCH_IS;
  enum XformType xformType = XFORM_TEXT;
  gstring * key;

  if (!filter->require_body)
    {
    filter->errmsg = US"missing previous require \"body\";";
    goto bad;
    }

  if (  !parse_a_c_m(filter, NULL, &comparator, &matchType, &xformType)
     || parse_white(filter) == -1
     || parse_stringlist(filter, &key, US"key") != 1
     )
    goto bad;

  /* A "content" transform forces a "contains" matchtype */

  if (xformType == XFORM_CONTENT)
    matchType = MATCH_CONTAINS;

  if (!sieve_body_test(filter, comparator, matchType, xformType, key, cond))
    goto bad;

  return 1;
  }
#endif	/*BODY*/

else
  return 0;

bad:
  FDEBUG debug_printf_indent(" %s\n", filter->errmsg);
  return -1;
}


/*************************************************
*     Parse and interpret an optional block      *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  exec        Execute parsed statements
  generated   where to hang newly-generated addresses

Returns:      2                success by stop
              1                other success
              0                no block command found
              -1               syntax or execution error
*/

static int
parse_block(struct Sieve * filter, BOOL exec, address_item ** generated)
{
if (parse_white(filter) == -1)
  return -1;
if (*filter->pc == '{')
  {
  int r;

  ++filter->pc;
  expand_level++;
  if ((r = parse_commands(filter, exec, generated)) == -1 || r == 2) return r;
  if (*filter->pc == '}')
    {
    ++filter->pc;
    expand_level--;
    return 1;
    }
  filter->errmsg = US"expecting command or closing brace";
  FDEBUG debug_printf_indent("%s\n", filter->errmsg);
  expand_level--;
  return -1;
  }
return 0;
}


/*************************************************
*           Match a semicolon                    *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int
parse_semicolon(struct Sieve *filter)
{
if (parse_white(filter) == -1)
  return -1;
if (*filter->pc == ';')
  {
  ++filter->pc;
  return 1;
  }
filter->errmsg = US"missing semicolon";
FDEBUG debug_printf_indent("%s\n", filter->errmsg);
return -1;
}


/*************************************************
*     Parse and interpret a Sieve command        *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  exec        Execute parsed statements
  generated   where to hang newly-generated addresses

Returns:      2                success by stop
              1                other success
              -1               syntax or execution error
*/
static int
parse_commands(struct Sieve *filter, BOOL exec, address_item **generated)
{
while (*filter->pc)
  {
  if (parse_white(filter) == -1)
    return -1;
  if (parse_identifier(filter, US"if", US"command"))
    {
    /*
    if-command = "if" test block *( "elsif" test block ) [ else block ]
    */

    BOOL cond, unsuccessful;

    expand_level++;
    /* test block */
    if (parse_white(filter) == -1)
      goto bad;
    switch (parse_test(filter, &cond, exec))
      {
      case -1: goto bad;
      case 0: filter->errmsg = US"missing test"; goto bad;
      }
    if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
      {
      if (exec) debug_printf_indent("if %s\n", cond?"true":"false");
      }
    switch (parse_block(filter, exec && cond, generated))
      {
      case -1:	goto bad;
      case 2:	goto exit_stop;
      case 0:	filter->errmsg = US"missing block"; goto bad;
      }
    unsuccessful = !cond;
    for (;;) /* elsif test block */
      {
      if (parse_white(filter) == -1)
	goto bad;
      if (parse_identifier(filter, US"elsif", US"command"))
        {
        if (parse_white(filter) == -1)
	  goto bad;
	switch (parse_test(filter, &cond, exec && unsuccessful))
	  {
	  case -1:	goto bad;
	  case 2:	goto exit_stop;
	  case 0:	filter->errmsg = US"missing test"; goto bad;
	  }
	if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
          {
          if (exec) debug_printf_indent("elsif %s\n", cond?"true":"false");
          }
	switch (parse_block(filter, exec && unsuccessful && cond, generated))
	  {
	  case -1:	goto bad;
	  case 2:	goto exit_stop;
	  case 0:	filter->errmsg = US"missing block"; goto bad;
	  }
        if (exec && unsuccessful && cond)
	  unsuccessful = FALSE;
        }
      else break;
      }
    /* else block */
    if (parse_white(filter) == -1)
      goto bad;
    if (parse_identifier(filter, US"else", US"command"))
      switch (parse_block(filter, exec && unsuccessful, generated))
	{
	case -1:	goto bad;
	case 2:		goto exit_stop;
	case 0:		filter->errmsg = US"missing block"; goto bad;
	}
    }
  else if (parse_identifier(filter, US"stop", US"command"))
    {
    /*
    stop-command     =  "stop" { stop-options } ";"
    stop-options     =
    */

    expand_level++;
    if (parse_semicolon(filter) == -1)
      goto bad;
    if (exec)
      {
      filter->pc += Ustrlen(filter->pc);
      goto exit_stop;
      }
    }
  else if (parse_identifier(filter, US"keep", US"command"))
    {
    /*
    keep-command     =  "keep" { keep-options } ";"
    keep-options     =
    */

    expand_level++;
    if (parse_semicolon(filter) == -1)
      goto bad;
    if (exec)
      {
      add_addr(generated, filter->inbox, 1, 0, 0, 0);
      filter->keep = FALSE;
      }
    }
  else if (parse_identifier(filter, US"discard", US"command"))
    {
    /*
    discard-command  =  "discard" { discard-options } ";"
    discard-options  =
    */

    expand_level++;
    if (parse_semicolon(filter) == -1)
      goto bad;
    if (exec) filter->keep = FALSE;
    }
  else if (parse_identifier(filter, US"redirect", US"command"))
    {
    /*
    redirect-command =  "redirect" redirect-options "string" ";"
    redirect-options =
    redirect-options = ) ":copy"
    */

    gstring recipient;
    BOOL copy = FALSE;

    expand_level++;
    for (;;)
      {
      if (parse_white(filter) == -1)
	goto bad;
      if (parse_identifier(filter, US":copy", US"command") == 1)
        {
        if (!filter->require_copy)
          {
          filter->errmsg = US"missing previous require \"copy\";";
	  goto bad;
          }
	copy = TRUE;
        }
      else break;
      }
    if (parse_white(filter) == -1)
      goto bad;
    if (parse_string(filter, &recipient, US"missing redirect recipient string") != 1)
      goto bad;
    if (strchr(CCS recipient.s, '@') == NULL)
      {
      filter->errmsg = US"unqualified recipient address";
      goto bad;
      }
    if (exec)
      {
      add_addr(generated, recipient.s, 0, 0, 0, 0);
      if (!copy) filter->keep = FALSE;
      }
    if (parse_semicolon(filter) == -1) goto bad;
    }
  else if (parse_identifier(filter, US"fileinto", US"command"))
    {
    /*
    fileinto-command =  "fileinto" { fileinto-options } string ";"
    fileinto-options =
    fileinto-options = ) [ ":copy" ]
    */

    gstring folder;
    uschar *s;
    int m;
    unsigned long maxage, maxmessages, maxstorage;
    BOOL copy = FALSE;

    expand_level++;
    maxage = maxmessages = maxstorage = 0;
    if (!filter->require_fileinto)
      {
      filter->errmsg = US"missing previous require \"fileinto\";";
      goto bad;
      }
    for (;;)
      {
      if (parse_white(filter) == -1)
	goto bad;
      if (parse_identifier(filter, US":copy", US"command") == 1)
        {
        if (!filter->require_copy)
          {
          filter->errmsg = US"missing previous require \"copy\";";
          goto bad;
          }
          copy = TRUE;
        }
      else break;
      }
    if (parse_white(filter) == -1)
      goto bad;
    if (parse_string(filter, &folder, US"missing fileinto folder string") != 1)
      goto bad;

    m = 0; s = folder.s;
    if (folder.ptr == 0)
      m = 1;
    if (Ustrcmp(s,"..") == 0 || Ustrncmp(s,"../", 3) == 0)
      m = 1;
    else while (*s)
      {
      if (Ustrcmp(s,"/..") == 0 || Ustrncmp(s,"/../", 4) == 0) { m = 1; break; }
      ++s;
      }
    if (m)
      {
      filter->errmsg = US"invalid folder";
      goto bad;
      }
    if (exec)
      {
      add_addr(generated, folder.s, 1, maxage, maxmessages, maxstorage);
      if (!copy) filter->keep = FALSE;
      }
    if (parse_semicolon(filter) == -1)
      goto bad;
    }
#ifdef ENOTIFY
  else if (parse_identifier(filter, US"notify", US"command"))
    {
    /*
    notify-command =  "notify" { notify-options } <method: string> ";"
    notify-options =  [":from" string]
                      [":importance" <"1" / "2" / "3">]
                      [":options" 1*(string-list / number)]
                      [":message" string]
    */

    gstring from =       { .s = NULL, .ptr = -1 };
    gstring importance = { .s = NULL, .ptr = -1 };
    gstring message =    { .s = NULL, .ptr = -1 };
    gstring method;
    struct Notification *already;
    string_item * recipient = NULL;
    gstring header =     { .s = NULL, .ptr = -1 };
    gstring subject =    { .s = NULL, .ptr = -1 };
    gstring body =       { .s = NULL, .ptr = -1 };
    uschar *envelope_from;
    gstring auto_submitted_value;
    uschar *auto_submitted_def;

    expand_level++;
    if (!filter->require_enotify)
      {
      filter->errmsg = US"missing previous require \"enotify\";";
      goto bad;
      }
    envelope_from = sender_address && sender_address[0]
     ? expand_string(US"$local_part_prefix$local_part$local_part_suffix@$domain") : US "";
    if (!envelope_from)
      {
      filter->errmsg = US"expansion failure for envelope from";
      goto bad;
      }

    for (;;)
      {
      if (parse_white(filter) == -1)
	goto bad;
      if (parse_identifier(filter, US":from", US"notify") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        if (parse_string(filter, &from, US"from string expected") != 1)
	  goto bad;
        }
      else if (parse_identifier(filter, US":importance", US"notify") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        if (parse_string(filter, &importance, US"importance string expected") != 1)
	  goto bad;

        if (importance.ptr != 1 || importance.s[0] < '1' || importance.s[0] > '3')
          {
          filter->errmsg = US"invalid importance";
          goto bad;
          }
        }
      else if (parse_identifier(filter, US":options", US"notify") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        }
      else if (parse_identifier(filter, US":message", US"notify") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        if (parse_string(filter, &message, US"message string expected") != 1)
	  goto bad;
        }
      else
	break;
      }

    if (parse_white(filter) == -1)
      goto bad;
    if (parse_string(filter, &method, US"missing method string") != 1)
      goto bad;
    if (parse_semicolon(filter) == -1)
      goto bad;
    if (parse_mailto_uri(filter, method.s, &recipient, &header, &subject, &body) != 1)
      goto bad;
    if (exec)
      {
      if (message.ptr == -1)
	message = subject;
      if (message.ptr == -1)
	expand_header(&message, &str_subject);
      expand_header(&auto_submitted_value, &str_auto_submitted);
      auto_submitted_def = expand_string(US"${if def:header_auto-submitted {true}{false}}");
      if (!auto_submitted_value.s || !auto_submitted_def)
        {
        filter->errmsg = US"header string expansion failed";
        goto bad;
        }
        if (Ustrcmp(auto_submitted_def,"true") != 0 || Ustrcmp(auto_submitted_value.s,"no") == 0)
        {
        for (already = filter->notified; already; already = already->next)
          {
          if (   already->method.ptr == method.ptr
              && (method.ptr == -1 || Ustrcmp(already->method.s, method.s) == 0)
              && already->importance.ptr == importance.ptr
              && (importance.ptr == -1 || Ustrcmp(already->importance.s, importance.s) == 0)
              && already->message.ptr == message.ptr
              && (message.ptr == -1 || Ustrcmp(already->message.s, message.s) == 0))
            break;
          }
        if (!already)
          /* New notification, process it */
          {
          struct Notification * sent = store_get(sizeof(struct Notification), GET_UNTAINTED);
          sent->method = method;
          sent->importance = importance;
          sent->message = message;
          sent->next = filter->notified;
          filter->notified = sent;
#ifndef COMPILE_SYNTAX_CHECKER
          if (filter_test == FTEST_NONE)
            {
            pid_t pid;
            int fd;

            if ((pid = child_open_exim2(&fd, envelope_from, envelope_from,
			US"sieve-notify")) >= 1)
              {
              FILE * f = fdopen(fd, "wb");

              fprintf(f,"From: %s\n", from.ptr == -1
		? expand_string(US"$local_part_prefix$local_part$local_part_suffix@$domain")
		: from.s);
              for (string_item * p = recipient; p; p = p->next)
	       	fprintf(f, "To: %s\n", p->text);
              fprintf(f, "Auto-Submitted: auto-notified; %s\n", filter->enotify_mailto_owner);
              if (header.ptr > 0) fprintf(f, "%s", header.s);
              if (message.ptr == -1)
                {
                message.s = US"Notification";
                message.ptr = Ustrlen(message.s);
                }
              if (message.ptr != -1)
		fprintf(f, "Subject: %s\n", parse_quote_2047(message.s,
		  message.ptr, US"utf-8", TRUE));
              fprintf(f,"\n");
              if (body.ptr > 0) fprintf(f, "%s\n", body.s);
              fflush(f);
              (void)fclose(f);
              (void)child_close(pid, 0);
              }
            }
	  if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
            debug_printf_indent("Notification to `%s': '%s'.\n", method.s, message.ptr != -1 ? message.s : US"");
#endif
          }
        else
	  if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
            debug_printf_indent("Repeated notification to `%s' ignored.\n", method.s);
        }
      else
	if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
          debug_printf_indent("Ignoring notification, triggering message contains Auto-submitted: field.\n");
      }
    }
#endif /*COMPILE_SYNTAX_CHECKER*/
#ifdef VACATION
  else if (parse_identifier(filter, US"vacation", US"command"))
    {
    /*
    vacation-command =  "vacation" { vacation-options } <reason: string> ";"
    vacation-options =  [":days" number]
                        [":subject" string]
                        [":from" string]
                        [":addresses" string-list]
                        [":mime"]
                        [":handle" string]
    */

    unsigned long days;
    gstring subject;
    gstring from;
    gstring *addresses;
    int reason_is_mime;
    string_item *aliases;
    gstring handle;
    gstring reason;

    expand_level++;
    if (!filter->require_vacation)
      {
      filter->errmsg = US"missing previous require \"vacation\";";
      goto bad;
      }
    if (exec)
      {
      if (filter->vacation_ran)
        {
        filter->errmsg = US"trying to execute vacation more than once";
        goto bad;
        }
      filter->vacation_ran = TRUE;
      }
    days = VACATION_MIN_DAYS>7 ? VACATION_MIN_DAYS : 7;
    subject.s = (uschar*)0;
    subject.ptr = -1;
    from.s = (uschar*)0;
    from.ptr = -1;
    addresses = (gstring*)0;
    aliases = NULL;
    reason_is_mime = 0;
    handle.s = (uschar*)0;
    handle.ptr = -1;
    for (;;)
      {
      if (parse_white(filter) == -1)
	goto bad;
      if (parse_identifier(filter, US":days", US"vacation") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        if (parse_number(filter, &days) == -1)
	  goto bad;
        if (days<VACATION_MIN_DAYS)
	  days = VACATION_MIN_DAYS;
        else if (days>VACATION_MAX_DAYS)
	  days = VACATION_MAX_DAYS;
        }
      else if (parse_identifier(filter, US":subject", US"vacation") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        if (parse_string(filter, &subject, US"subject string expected") != 1)
	  goto bad;
        }
      else if (parse_identifier(filter, US":from", US"vacation") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        if (parse_string(filter, &from, US"from string expected") != 1)
	  goto bad;
        if (check_mail_address(filter, &from) != 1)
          goto bad;
        }
      else if (parse_identifier(filter, US":addresses", US"vacation") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        if (parse_stringlist(filter, &addresses, US"addresses") != 1)
	  goto bad;
        for (gstring * a = addresses; a->ptr != -1; ++a)
          {
          string_item * new = store_get(sizeof(string_item), GET_UNTAINTED);

          new->text = store_get(a->ptr+1, a->s);
          if (a->ptr) memcpy(new->text, a->s, a->ptr);
          new->text[a->ptr] = '\0';
          new->next = aliases;
          aliases = new;
          }
        }
      else if (parse_identifier(filter, US":mime", US"vacation") == 1)
        reason_is_mime = 1;
      else if (parse_identifier(filter, US":handle", US"vacation") == 1)
        {
        if (parse_white(filter) == -1)
	  goto bad;
        if (parse_string(filter, &from, US"handle string expected") != 1)
	  goto bad;
        }
      else break;
      }
    if (parse_white(filter) == -1)
      goto bad;
    if (parse_string(filter, &reason, US"missing reason string") != 1)
      goto bad;
    if (reason_is_mime)
      {
      const uschar * s, * end;

      for (s = reason.s, end = reason.s + reason.ptr;
	  s<end && (*s&0x80) == 0; ) s++;
      if (s<end)
        {
        filter->errmsg = US"MIME reason string contains 8bit text";
        goto bad;
        }
      }
    if (parse_semicolon(filter) == -1) goto bad;

    if (exec)
      {
      address_item * addr;
      md5 base;
      gstring * once;
      misc_module_info * mi;
      typedef BOOL (*fn_t)(string_item *, BOOL);

      if (!(mi = misc_mod_find(US"exim_filter", NULL)))
        {
        filter->errmsg = US"test for 'personal': module not available";
        goto bad;
        }
      if ((((fn_t *) mi->functions)[EXIM_FILTER_PERSONAL])(aliases, TRUE))
        {
	uschar digest[16], hexdigest[33];

        if (filter_test == FTEST_NONE)
          {
          /* ensure oncelog directory exists; failure will be detected later */

          (void)directory_make(NULL, filter->vacation_directory, 0700, FALSE);
          }
        /* build oncelog filename */

        md5_start(&base);

        if (handle.ptr == -1)
          {
	  gstring * key = NULL;
          if (subject.ptr != -1)
	    key = string_catn(key, subject.s, subject.ptr);
          if (from.ptr != -1)
	    key = string_catn(key, from.s, from.ptr);
          key = string_catn(key, reason_is_mime?US"1":US"0", 1);
          key = string_catn(key, reason.s, reason.ptr);
	  md5_end(&base, key->s, key->ptr, digest);
          }
        else
	  md5_end(&base, handle.s, handle.ptr, digest);

        for (int i = 0; i < 16; i++)
	  sprintf(CS (hexdigest+2*i), "%02X", digest[i]);

	if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
          debug_printf_indent("Sieve: mail was personal, vacation file basename: %s\n", hexdigest);

        if (filter_test == FTEST_NONE)
          {
          once = string_cat (NULL, filter->vacation_directory);
          once = string_catn(once, US"/", 1);
          once = string_catn(once, hexdigest, 33);

          /* process subject */

          if (subject.ptr == -1)
            {
            const uschar * subject_def = expand_string(
				    US"${if def:header_subject {true}{false}}");
            if (subject_def && Ustrcmp(subject_def,"true") == 0)
              {
	      gstring * g = string_catn(NULL, US"Auto: ", 6);

              expand_header(&subject, &str_subject);
              g = string_catn(g, subject.s, subject.ptr);
	      subject.ptr = len_string_from_gstring(g, &subject.s);
              }
            else
              {
              subject.s = US"Automated reply";
              subject.ptr = Ustrlen(subject.s);
              }
            }

          /* add address to list of generated addresses */

          addr = deliver_make_addr(string_sprintf(">%.256s", sender_address), FALSE);
          setflag(addr, af_pfr);
          addr->prop.ignore_error = TRUE;
          addr->next = *generated;
          *generated = addr;
          addr->reply = store_get(sizeof(reply_item), GET_UNTAINTED);
          memset(addr->reply, 0, sizeof(reply_item)); /* XXX */
          addr->reply->to = string_copy(sender_address);
          if (from.ptr == -1)
            addr->reply->from = expand_string(US"$local_part@$domain");
          else
            addr->reply->from = from.s;
	  /* deconst cast safe as we pass in a non-const item */
          addr->reply->subject = US parse_quote_2047(subject.s, subject.ptr, US"utf-8", TRUE);
          addr->reply->oncelog = string_from_gstring(once);
          addr->reply->once_repeat = days*86400;

          /* build body and MIME headers */

          if (reason_is_mime)
            {
            uschar *mime_body, *reason_end;
            static const uschar nlnl[] = "\r\n\r\n";

            for
              (
              mime_body = reason.s, reason_end = reason.s + reason.ptr;
              mime_body < (reason_end-(sizeof(nlnl)-1)) && memcmp(mime_body, nlnl, (sizeof(nlnl)-1));
	      ) mime_body++;

            addr->reply->headers = string_copyn(reason.s, mime_body-reason.s);

            if (mime_body+(sizeof(nlnl)-1)<reason_end)
	      mime_body += (sizeof(nlnl)-1);
            else mime_body = reason_end-1;
            addr->reply->text = string_copyn(mime_body, reason_end-mime_body);
            }
          else
            {
            addr->reply->headers = US"MIME-Version: 1.0\n"
                                   "Content-Type: text/plain;\n"
                                   "\tcharset=\"utf-8\"\n"
                                   "Content-Transfer-Encoding: quoted-printable";
            addr->reply->text = quoted_printable_encode(&reason)->s;
            }
          }
        }
	else if ((filter_test != FTEST_NONE && ANY_DEBUG) || IS_FDEBUG)
          debug_printf_indent("Sieve: mail was not personal, vacation would ignore it\n");
      }
    }
#endif
    else
      break;

  expand_level--;
  }
return 1;

exit_stop:
  expand_level--;
  return 2;

bad:
  FDEBUG debug_printf_indent("%s\n", filter->errmsg);
  expand_level--;
  return -1;
}


/*************************************************
*       Parse and interpret a sieve filter       *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  exec        Execute parsed statements
  generated   where to hang newly-generated addresses

Returns:      1                success
              -1               syntax or execution error
*/

static int
parse_start(struct Sieve *filter, BOOL exec, address_item **generated)
{
filter->pc = filter->filter;
filter->line = 1;
filter->keep = TRUE;
filter->require_envelope = FALSE;
filter->require_fileinto = FALSE;
#ifdef BODY
filter->require_body = FALSE;
#endif
#ifdef ENCODED_CHARACTER
filter->require_encoded_character = FALSE;
#endif
#ifdef ENVELOPE_AUTH
filter->require_envelope_auth = FALSE;
#endif
#ifdef ENOTIFY
filter->require_enotify = FALSE;
filter->notified = (struct Notification*)0;
#endif
#ifdef SUBADDRESS
filter->require_subaddress = FALSE;
#endif
#ifdef VACATION
filter->require_vacation = FALSE;
filter->vacation_ran = FALSE;
#endif
filter->require_copy = FALSE;
filter->require_iascii_numeric = FALSE;

if (parse_white(filter) == -1) return -1;

if (exec && filter->vacation_directory && filter_test == FTEST_NONE)
  {
  DIR *oncelogdir;
  struct dirent *oncelog;
  struct stat properties;
  time_t now;

  /* clean up old vacation log databases */

  if (  !(oncelogdir = exim_opendir(filter->vacation_directory))
     && errno != ENOENT)
    {
    filter->errmsg = US"unable to open vacation directory";
    goto bad;
    }

  if (oncelogdir)
    {
    time(&now);

    while ((oncelog = readdir(oncelogdir)))
      if (strlen(oncelog->d_name) == 32)
        {
        uschar *s = string_sprintf("%s/%s", filter->vacation_directory, oncelog->d_name);
        if (Ustat(s, &properties) == 0 && properties.st_mtime+VACATION_MAX_DAYS*86400 < now)
          Uunlink(s);
        }
    closedir(oncelogdir);
    }
  }

while (parse_identifier(filter, US"require", US"command"))
  {
  /*
  require-command = "require" <capabilities: string-list>
  */

  gstring * cap;

  if (parse_white(filter) == -1) return -1;
  if (parse_stringlist(filter, &cap, US"capability") != 1)
    goto bad;

  for (gstring * check = cap; check->s; ++check)
    if (eq_octet(check, &str_envelope, FALSE))
      filter->require_envelope = TRUE;
    else if (eq_octet(check, &str_fileinto, FALSE))
      filter->require_fileinto = TRUE;
#ifdef BODY
    else if (eq_octet(check, &str_body, FALSE))
      filter->require_body = TRUE;
#endif
#ifdef ENCODED_CHARACTER
    else if (eq_octet(check, &str_encoded_character, FALSE))
      filter->require_encoded_character = TRUE;
#endif
#ifdef ENVELOPE_AUTH
    else if (eq_octet(check, &str_envelope_auth, FALSE))
      filter->require_envelope_auth = TRUE;
#endif
#ifdef ENOTIFY
    else if (eq_octet(check, &str_enotify, FALSE))
      {
      if (!filter->enotify_mailto_owner)
        { filter->errmsg = US"enotify disabled"; goto bad; }
      filter->require_enotify = TRUE;
      }
#endif
#ifdef SUBADDRESS
    else if (eq_octet(check, &str_subaddress, FALSE))
      filter->require_subaddress = TRUE;
#endif
#ifdef VACATION
    else if (eq_octet(check, &str_vacation, FALSE))
      {
      if (filter_test == FTEST_NONE && !filter->vacation_directory)
        { filter->errmsg = US"vacation disabled"; goto bad; }
      filter->require_vacation = TRUE;
      }
#endif
    else if (eq_octet(check, &str_copy, FALSE)) filter->require_copy = TRUE;
    else if (eq_octet(check, &str_comparator_ioctet, FALSE)) ;
    else if (eq_octet(check, &str_comparator_iascii_casemap, FALSE)) ;
    else if (eq_octet(check, &str_comparator_enascii_casemap, FALSE)) ;
    else if (eq_octet(check, &str_comparator_iascii_numeric, FALSE))
      filter->require_iascii_numeric = TRUE;
    else
      {
      filter->errmsg = string_sprintf("unknown capability '%Y'", check);
      goto bad;
      }

    if (parse_semicolon(filter) == -1) return -1;
  }

if (parse_commands(filter, exec, generated) == -1) return -1;
if (*filter->pc)
  {
  filter->errmsg = US"syntax error";
  goto bad;
  }
return 1;

bad:
  FDEBUG debug_printf_indent("%s\n", filter->errmsg);
  return -1;
}


/* Module API: module initialisation */
static BOOL
sieve_init(void * p)
{
/* More expensive than a static init, but safer vs. future edits */
for (gstring * const * gp = sieve_wordlist;
     gp < sieve_wordlist + nelem(sieve_wordlist); gp++)
  { gstring * g = *gp; g->size = (g->ptr = Ustrlen(g->s)) + 1; }
return TRUE;
}


/*************************************************
*            Interpret a sieve filter file       *
*************************************************/

/* Module API:
Arguments:
  filter      points to the entire filter file,
	      read into store as a single string
  options     controls whether various special things are allowed, and requests
              special actions (not currently used)
  sb		(NULL for defaults)
    vacation_directory		where to store vacation "once" files
    enotify_mailto_owner	owner of mailto notifications
    useraddress			string expression for :user part of address
    subaddress			string expression for :subaddress part of address
    inbox			string expression for "keep"
  generated   where to hang newly-generated addresses
  error       where to pass back an error text

Returns:      FF_DELIVERED     success, a significant action was taken
              FF_NOTDELIVERED  success, no significant action
              FF_DEFER         defer requested
              FF_FAIL          fail requested
              FF_FREEZE        freeze requested
              FF_ERROR         there was a problem
*/

int
sieve_interpret(const uschar * filter, int options, const sieve_block * sb,
  address_item ** generated, uschar ** error)
{
struct Sieve sieve;
int r;
uschar * msg;

FDEBUG debug_printf_indent("Sieve: start of processing\n");
expand_level++;
sieve.filter = filter;

GET_OPTION("sieve_vacation_directory");
if (!sb || !sb->vacation_dir)
  sieve.vacation_directory = NULL;
else if (!(sieve.vacation_directory = expand_string(sb->vacation_dir)))
  {
  *error = string_sprintf("failed to expand %q "
    "(sieve_vacation_directory): %s", sb->vacation_dir, expand_string_message);
  return FF_ERROR;
  }

GET_OPTION("sieve_vacation_directory");
if (!sb || !sb->inbox)
  sieve.inbox = US"inbox";
else if (!(sieve.inbox = expand_string(sb->inbox)))
  {
  *error = string_sprintf("failed to expand %q "
    "(sieve_inbox): %s", sb->inbox, expand_string_message);
  return FF_ERROR;
  }

GET_OPTION("sieve_enotify_mailto_owner");
if (!sb || !sb->enotify_mailto_owner)
  sieve.enotify_mailto_owner = NULL;
else if (!(sieve.enotify_mailto_owner = expand_string(sb->enotify_mailto_owner)))
  {
  *error = string_sprintf("failed to expand %q "
    "(sieve_enotify_mailto_owner): %s", sb->enotify_mailto_owner,
    expand_string_message);
  return FF_ERROR;
  }

GET_OPTION("sieve_useraddress");
sieve.useraddress = sb && sb->useraddress
  ? sb->useraddress : US"$local_part_prefix$local_part$local_part_suffix";
GET_OPTION("sieve_subaddress");
sieve.subaddress = sb ? sb->subaddress : NULL;

#ifdef COMPILE_SYNTAX_CHECKER
if (parse_start(&sieve, FALSE, generated) == 1)
#else
if (parse_start(&sieve, TRUE, generated) == 1)
#endif
  if (sieve.keep)
    {
    add_addr(generated, sieve.inbox, 1, 0, 0, 0);
    msg = US"Implicit keep";
    r = FF_DELIVERED;
    }
  else
    {
    msg = US"No implicit keep";
    r = FF_DELIVERED;
    }
else
  {
  const uschar * start, * end;
  for (start = sieve.pc; start > sieve.filter && start[-1] != '\n'; ) start--;
  for (end = sieve.pc; *end != '\r' && *end != '\n' && *end; ) end++;
  msg = string_sprintf("Sieve error: %s in line %d:\n"
	  " %.*s\n"
	  " %*s^",
	  sieve.errmsg, sieve.line,
	  (int)(end - start), start,
	  (int)(sieve.pc - start), "^"
	  );
#ifdef COMPILE_SYNTAX_CHECKER
  r = FF_ERROR;
  *error = msg;
#else
  add_addr(generated, sieve.inbox, 1, 0, 0, 0);
  r = FF_DELIVERED;
#endif
  }

#ifndef COMPILE_SYNTAX_CHECKER
if (filter_test != FTEST_NONE) printf("%s\n", (const char*) msg);
  else debug_printf_indent("%s\n", msg);
#endif

expand_level--;
FDEBUG debug_printf_indent("Sieve: end of processing\n");
return r;
}


/* Module API: print list of supported sieve extensions to given stream */
static void
sieve_extensions(FILE * fp)
{
for (const uschar ** pp = exim_sieve_extension_list; *pp; ++pp)
  fprintf(fp, "%s\n", *pp);
}


/******************************************************************************/
/* Module API */

static void * sieve_functions[] = {
  [SIEVE_INTERPRET] =	(void *) sieve_interpret,
  [SIEVE_EXTENSIONS] =	(void *) sieve_extensions,
};

misc_module_info sieve_filter_module_info =
{
  .name =		US"sieve_filter",
# ifdef DYNLOOKUP
  .dyn_magic =		MISC_MODULE_MAGIC,
# endif
  .init =		sieve_init,

  .functions =		sieve_functions,
  .functions_count =	nelem(sieve_functions),
};

/* End of sieve_filter.c */
/* vi: aw ai sw=2
*/
