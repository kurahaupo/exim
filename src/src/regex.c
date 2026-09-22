/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * Copyright (c) The Exim Maintainers 2016 - 2026
 * Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-2015
 * License: GPL
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Regular-expression routines.

Also, WITH_CONTENT_SCAN: match routines for REs against headers and body.
(Called from acl.c)
*/

#include "exim.h"

#ifdef WITH_CONTENT_SCAN
# include <unistd.h>
# include <sys/mman.h>

/* Structure to hold a list of Regular expressions */
typedef struct pcre_list {
  const pcre2_code *	re;
  uschar *		pcre_text;
  struct pcre_list *	next;
} pcre_list;

extern FILE * mime_stream;
extern const uschar * mime_current_boundary;
#endif


/*************************************************
*      Function interface to store functions     *
*************************************************/

/* We need some real functions to pass to the PCRE regular expression library
for store allocation via Exim's store manager. The normal calls are actually
macros that pass over location information to make tracing easier. These
functions just interface to the standard macro calls. A good compiler will
optimize out the tail recursion and so not make them too expensive. */

static void *
function_store_malloc(PCRE2_SIZE size, void * tag)
{
if (size > INT_MAX)
  log_write_die(LOG_MAIN, "excessive memory alloc request");
return store_malloc((int)size);
}

static void
function_store_free(void * block, void * tag)
{
/* At least some version of pcre2 pass a null pointer */
if (block) store_free(block);
}


static void *
function_store_get(PCRE2_SIZE size, void * tag)
{
if (size > INT_MAX)
  log_write_die(LOG_MAIN, "excessive memory alloc request");
return store_get((int)size, GET_UNTAINTED);	/* loses track of taint */
}

static void
function_store_nullfree(void * block, void * tag)
{
/* We cannot free memory allocated using store_get() */
}



void
pcre_init(void)
{
pcre_mlc_ctx = pcre2_general_context_create(function_store_malloc, function_store_free, NULL);
pcre_gen_ctx = pcre2_general_context_create(function_store_get, function_store_nullfree, NULL);

pcre_mlc_cmp_ctx = pcre2_compile_context_create(pcre_mlc_ctx);
pcre_gen_cmp_ctx = pcre2_compile_context_create(pcre_gen_ctx);

pcre_gen_mtc_ctx = pcre2_match_context_create(pcre_gen_ctx);
}





/*************************************************
*   Execute regular expression and set strings   *
*************************************************/

/* This function runs a regular expression match, and sets up the pointers to
the matched substrings.  The matched strings are copied so the lifetime of
the subject is not a problem.  Matched strings will have the same taint status
as the subject string (this is not a de-taint method, and must not be made so
given the support for wildcards in REs).

Arguments:
  re          the compiled expression
  subject     the subject string
  options     additional PCRE options
  setup       if < 0 do full setup
              if >= 0 setup from setup+1 onwards,
                excluding the full matched string

Returns:      TRUE if matched, or FALSE
*/

BOOL
regex_match_and_setup(const pcre2_code * re, const uschar * subject,
  int options, int setup)
{
pcre2_match_data * md = pcre2_match_data_create(EXPAND_MAXN + 1, pcre_gen_ctx);
int res = pcre2_match(re, (PCRE2_SPTR)subject, PCRE2_ZERO_TERMINATED, 0,
			PCRE_EOPT | options, md, pcre_gen_mtc_ctx);
BOOL yield;

if ((yield = (res >= 0)))
  {
  const PCRE2_SIZE * ovec = pcre2_get_ovector_pointer(md);
  expand_nmax = setup < 0 ? 0 : setup + 1;
  for (int matchnum = setup < 0 ? 0 : 1; matchnum < res; matchnum++)
    {
    /* Although PCRE2 has a pcre2_substring_get_bynumber() conveneience, it
    seems to return a bad pointer when a capture group had no data, eg. (.*)
    matching zero letters.  So use the underlying ovec and hope (!) that the
    offsets are sane (including that case).  Should we go further and range-
    check each one vs. the subject string length? */
    int m_off = matchnum * 2;
    int len = ovec[m_off + 1] - ovec[m_off];
    expand_nstring[expand_nmax] = string_copyn(subject + ovec[m_off], len);
    expand_nlength[expand_nmax++] = len;
    }
  expand_nmax--;
  }
else if (res != PCRE2_ERROR_NOMATCH) DEBUG(any)
  {
  uschar errbuf[128];
  pcre2_get_error_message(res, errbuf, sizeof(errbuf));
  debug_printf_indent("pcre2: %s\n", errbuf);
  }
/* pcre2_match_data_free(md);	gen ctx needs no free */
return yield;
}


/* Check just for match with regex.  Uses the common memory-handling.

Arguments:
	re	compiled regex
	subject	string to be checked
	slen	length of subject; -1 for nul-terminated
	rptr	pointer for matched string, copied, or NULL

Return: TRUE for a match.
*/

BOOL
regex_match(const pcre2_code * re, const uschar * subject, int slen, uschar ** rptr)
{
pcre2_match_data * md = pcre2_match_data_create(1, pcre_gen_ctx);
int rc = pcre2_match(re, (PCRE2_SPTR)subject,
		      slen >= 0 ? slen : PCRE2_ZERO_TERMINATED,
		      0, PCRE_EOPT, md, pcre_gen_mtc_ctx);
const PCRE2_SIZE * ovec = pcre2_get_ovector_pointer(md);
BOOL ret = FALSE;

if (rc >= 0)
  {
  if (rptr)
    *rptr = string_copyn(subject + ovec[0], ovec[1] - ovec[0]);
  ret = TRUE;
  }
/* pcre2_match_data_free(md);	gen ctx needs no free */
return ret;
}


#ifdef WITH_CONTENT_SCAN

static pcre_list *
compile(const uschar * list, BOOL cacheable, int * cntp)
{
int sep = 0, cnt = 0;
uschar * regex_string;
pcre_list * re_list_head = NULL, * ri;

/* precompile our regexes */
while ((regex_string = string_nextinlist(&list, &sep, NULL, 0)))
  if (strcmpic(regex_string, US"false") != 0 && Ustrcmp(regex_string, "0") != 0)
    {
    /* compile our regular expression */
    uschar * errstr;
    const pcre2_code * re = regex_compile(regex_string,
      cacheable ? MCS_CACHEABLE : MCS_NOFLAGS, &errstr, pcre_gen_cmp_ctx);

    if (!re)
      {
      log_write(LOG_MAIN, "regex acl condition warning - %s, skipped", errstr);
      continue;
      }

    ri = store_get(sizeof(pcre_list), GET_UNTAINTED);
    ri->re = re;
    ri->pcre_text = regex_string;
    ri->next = re_list_head;
    re_list_head = ri;
    cnt++;
    }
if (cntp) *cntp = cnt;
return re_list_head;
}


/* Check list of REs against buffer, returning OK for (first) match,
else FAIL.  On match return allocated result strings in regex_vars[].

We use the perm-pool for that, so that our caller can release
other allocations.
*/
static int
matcher(pcre_list * re_list_head, uschar * linebuffer, int len)
{
pcre2_match_data * md = pcre2_match_data_create(REGEX_VARS + 1, pcre_gen_ctx);

for (pcre_list * ri = re_list_head; ri; ri = ri->next)
  {
  int n;

  /* try matcher on the line */
  if ((n = pcre2_match(ri->re, (PCRE2_SPTR)linebuffer, len, 0, 0, md, pcre_gen_mtc_ctx)) > 0)
    {
    int save_pool = store_pool;
    store_pool = POOL_PERM;

    regex_match_string = string_copy(ri->pcre_text);

    for (int nn = 1; nn < n; nn++)
      {
      const PCRE2_SIZE * ovec = pcre2_get_ovector_pointer(md);
      int moff = nn * 2;
      int mlen = ovec[moff + 1] - ovec[moff];
      regex_vars[nn-1] = string_copyn(linebuffer + ovec[moff], mlen);
      }

    store_pool = save_pool;
    return OK;
    }
  }
/* pcre2_match_data_free(md);	gen ctx needs no free */
return FAIL;
}


/* reset expansion variables */
void
regex_vars_clear(void)
{
regex_match_string = NULL;
for (int i = 0; i < REGEX_VARS; i++) regex_vars[i] = NULL;
}



int
exim_regex(const uschar ** listptr, BOOL cacheable)
{
unsigned long mbox_size;
FILE * mbox_file;
pcre_list * re_list_head;
long f_pos = 0;
int ret = FAIL, cnt, lcount = REGEX_LOOPCOUNT_STORE_RESET;

regex_vars_clear();

if (!mime_stream)				/* We are in the DATA ACL */
  {
  if (!(mbox_file = spool_mbox(&mbox_size, NULL, NULL)))
    {						/* error while spooling */
    log_write(LOG_MAIN|LOG_PANIC,
	   "regex acl condition: error while creating mbox spool file");
    return DEFER;
    }
  }
else
  {
  if ((f_pos = ftell(mime_stream)) < 0)
    {
    log_write(LOG_MAIN|LOG_PANIC,
	   "regex acl condition: mime_stream: %s", strerror(errno));
    return DEFER;
    }
  mbox_file = mime_stream;
  }

  /* precompile our regexes */
  if ((re_list_head = compile(*listptr, cacheable, &cnt)))
    {
    rmark reset_point = store_mark();

    /* match each line against all regexes */
    while (fgets(C(big_buffer), big_buffer_size, mbox_file))
      {
      if (  mime_stream && mime_current_boundary		/* check boundary */
	 && Ustrncmp(big_buffer, "--", 2) == 0
	 && Ustrncmp((big_buffer+2), mime_current_boundary,
		      Ustrlen(mime_current_boundary)) == 0)
	break;						/* found boundary */

      if ((ret = matcher(re_list_head, big_buffer, (int)Ustrlen(big_buffer))) == OK)
	break;

      if ((lcount -= cnt) <= 0)
	{
	store_reset(reset_point); reset_point = store_mark();
	lcount = REGEX_LOOPCOUNT_STORE_RESET;
	}
      }

    store_reset(reset_point);
    }

if (!mime_stream)
  (void)fclose(mbox_file);
else
  {
  clearerr(mime_stream);
  if (fseek(mime_stream, f_pos, SEEK_SET) == -1)
    {
    log_write(LOG_MAIN|LOG_PANIC,
	   "regex acl condition: mime_stream: %s", strerror(errno));
    clearerr(mime_stream);
    }
  }

return ret;
}


int
mime_regex(const uschar **listptr, BOOL cacheable)
{
pcre_list * re_list_head = NULL;
FILE * f;
uschar * mime_subject = NULL;
int ret = FAIL, mime_subject_len;
rmark reset_point;

regex_vars_clear();

/* check if the file is already decoded */
if (!mime_decoded_filename)
  {				/* no, decode it first */
  const uschar *empty = US"";
  mime_decode(&empty);
  if (!mime_decoded_filename)
    {				/* decoding failed */
    log_write(LOG_MAIN,
       "mime_regex acl condition warning - could not decode MIME part to file");
    return DEFER;
    }
  }

/* open file */
if (!(f = fopen(C(mime_decoded_filename), "rb")))
  {
  log_write(LOG_MAIN,
       "mime_regex acl condition warning - can't open '%s' for reading",
       mime_decoded_filename);
  return DEFER;
  }

reset_point = store_mark();
  {
  /* precompile our regexes */
  if ((re_list_head = compile(*listptr, cacheable, NULL)))
    {
    /* get 32k memory, tainted */
    mime_subject = store_get(32767, GET_TAINTED);

    mime_subject_len = fread(mime_subject, 1, 32766, f);

    ret = matcher(re_list_head, mime_subject, mime_subject_len);
    }
  }
store_reset(reset_point);
(void)fclose(f);
return ret;
}

#endif /* WITH_CONTENT_SCAN */
