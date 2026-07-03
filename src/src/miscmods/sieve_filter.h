/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
Copyright (c) The Exim Maintainers 2016 - 2026
Copyright (c) Michael Haardt 2003 - 2015
See the file NOTICE for conditions of use and distribution.
SPDX-License-Identifier: GPL-2.0-or-later
*/

/* This code was originally contributed by Michael Haardt. */

#include "../exim.h"

/* Define this for RFC compliant \r\n end-of-line terminators.      */
/* Undefine it for UNIX-style \n end-of-line terminators (default). */
#undef RFC_EOL

/* Define this for the Sieve extension "body". */
#if HAVE_ICONV && defined(WITH_CONTENT_SCAN)
# define BODY
#endif

/* Define this for development of the Sieve extension "encoded-character". */
#define ENCODED_CHARACTER

/* Define this for development of the Sieve extension "envelope-auth". */
#undef ENVELOPE_AUTH

/* Define this for development of the Sieve extension "enotify".    */
#define ENOTIFY

/* Define this for the Sieve extension "subaddress".                */
#define SUBADDRESS

/* Define this for the Sieve extension "vacation".                  */
#define VACATION

/* Must be >= 1                                                     */
#define VACATION_MIN_DAYS 1
/* Must be >= VACATION_MIN_DAYS, must be > 7, should be > 30        */
#define VACATION_MAX_DAYS 31

/* Keep this at 75 to accept only RFC compliant MIME words.         */
/* Increase it if you want to match headers from buggy MUAs.        */
#define MIMEWORD_LENGTH 75

typedef struct Sieve {
  const uschar *filter;
  const uschar *pc;
  int	line;
  const uschar *errmsg;
  BOOL	keep;
#ifdef BODY
  BOOL	require_body;
#endif
  BOOL	require_envelope;
  BOOL	require_fileinto;
#ifdef ENCODED_CHARACTER
  BOOL	require_encoded_character;
#endif
#ifdef ENVELOPE_AUTH
  BOOL	require_envelope_auth;		/*XXX never tested? */
#endif
#ifdef ENOTIFY
  BOOL	require_enotify;
  struct Notification *notified;
#endif
  const uschar *enotify_mailto_owner;
#ifdef SUBADDRESS
  BOOL	require_subaddress;
#endif
#ifdef VACATION
  BOOL	require_vacation;
  BOOL	vacation_ran;
#endif
  const uschar *inbox;
  const uschar *vacation_directory;
  const uschar *subaddress;
  const uschar *useraddress;
  BOOL	require_copy;
  BOOL	require_iascii_numeric;
} sieve_t;

enum Comparator { COMP_OCTET, COMP_EN_ASCII_CASEMAP, COMP_ASCII_NUMERIC };
enum MatchType { MATCH_IS, MATCH_CONTAINS, MATCH_MATCHES };
enum XformType { XFORM_RAW, XFORM_CONTENT, XFORM_TEXT };

extern gstring * sieve_body_content_matchtypes;

extern BOOL sieve_body_test(sieve_t *,
	      enum Comparator, enum MatchType, enum XformType, gstring *,
	      BOOL *);

extern const in_processing * qp_push_receive_functions(const in_processing *);
extern const in_processing * b64_push_receive_functions(const in_processing *);
extern const in_processing * iconv_push_receive_functions(const in_processing *, const uschar *);

#define SIEVE_BODY_REGEX_WORK_SIZE      200

#define SIEVE_MIME_BOUNDARY_ERROR	-1
#define SIEVE_MIME_BOUNDARY_NONLAST	0
#define SIEVE_MIME_BOUNDARY_LAST	1
#define SIEVE_MIME_BOUNDARY_EOD		2

extern const in_processing * mime_push_receive_functions(const in_processing *,
  const pcre2_code *, pcre2_match_context *, pcre2_match_data * md);
extern int mime_clear_boundary(const in_processing * inp);

#define IS_FDEBUG	IS_DEBUG(sieve|filter)
#define FDEBUG		DEBUG(sieve|filter)

/* End of sieve_filter.h */
/* vi: aw ai sw=2
*/
