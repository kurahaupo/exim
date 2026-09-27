/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2026 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef MACROS_H
#define MACROS_H

/* These two macros make it possible to obtain the result of macro-expanding
a string as a text string. This is sometimes useful for debugging output. */

#define mac_string(s) # s
#define mac_expanded_string(s) mac_string(s)

/* Number of elements of an array */
#define nelem(arr) (sizeof(arr) / sizeof(*arr))

/* Maximum of two items */
#ifndef MAX
# define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


/* When running in the test harness, the load average is fudged. */

#define OS_GETLOADAVG() \
  (f.running_in_test_harness? (test_harness_load_avg += 10) : os_getloadavg())


/* The address_item structure has a struct full of 1-bit flags. These macros
manipulate them. */

#define setflag(addr, flagname)    addr->flags.flagname = TRUE
#define clearflag(addr, flagname)  addr->flags.flagname = FALSE

#define testflag(addr, flagname)   (addr->flags.flagname)

#define copyflag(addrnew, addrold, flagname) \
  addrnew->flags.flagname = addrold->flags.flagname


/* For almost all calls to convert things to printing characters, we want to
allow tabs & spaces. A macro just makes life a bit easier. */

#define string_printing(s) string_printing2((s), 0)
#define SP_TAB		BIT(0)
#define SP_SPACE	BIT(1)
#define SP_DQUOTES	BIT(2)


/* We need a special return code for "no recipients and failed to send an error
message". ANSI C defines only EXIT_FAILURE and EXIT_SUCCESS. On the assumption
that these are always 1 and 0 on Unix systems ... */

#define EXIT_NORECIPIENTS 2


/* Character-handling macros. It seems that the set of standard functions in
ctype.h aren't actually all that useful. One reason for this is that email is
international, so the concept of using a locale to vary what they do is not
helpful. Another problem is that in different operating systems, the libraries
yield different results, even in the default locale. For example, Linux yields
TRUE for iscntrl() for all characters > 127, whereas many other systems yield
FALSE. For these reasons we define our own set of macros for a number of
character testing functions. Ensure that all these tests treat their arguments
as unsigned. */

#define mac_iscntrl(c) \
  ((uschar)(c) < 32 || (uschar)(c) == 127)

#define mac_iscntrl_or_special(c) \
  ((uschar)(c) < 32 || strchr(" ()<>@,;:\\\".[]\177", (uschar)(c)) != NULL)

#define mac_isgraph(c) \
  ((uschar)(c) > 32 && (uschar)(c) != 127)

#define mac_isprint(c) \
  (((uschar)(c) >= 32 && (uschar)(c) <= 126) || c == '\t' || \
  ((uschar)(c) > 127 && print_topbitchars))



/* Define which ends of pipes are for reading and writing, as some systems
don't make the file descriptors two-way. */

#define pipe_read  0
#define pipe_write 1

/* The RFC 1413 ident port */

#define IDENT_PORT 113

/* A macro to simplify testing bits in lookup types */

#define mac_islookup(li,b) ((li)->type & (b))

/* The default From: text for DSNs */

#define DEFAULT_DSN_FROM "Mail Delivery System <Mailer-Daemon@$qualify_domain>"

/* The size of the vector for saving/restoring address expansion pointers while
verifying. This has to be explicit because it is referenced in more than one
source module. */

#define ADDRESS_EXPANSIONS_COUNT 21

/* The maximum permitted number of command-line (-D) macro definitions. We
need a limit only to make it easier to generate argument vectors for re-exec
of Exim. */

#define MAX_CLMACROS 10

/* The number of integer variables available in filter files. If this is
changed, then the tables in expand.c for accessing them must be changed too. */

#define FILTER_VARIABLE_COUNT 10

/* The size of the vector holding delay warning times */

#define DELAY_WARNING_SIZE 12

/* The size of the buffer holding the processing information string. */

#define PROCESS_INFO_SIZE 384

/* The size of buffer to get for constructing log entries. Make it big
enough to hold all the headers from a normal kind of message. */

#define LOG_BUFFER_SIZE 8192

#define LOG_NAME_SIZE 256

/* The size of the circular buffer that remembers recent SMTP commands */

#define SMTP_HBUFF_SIZE 20
#define SMTP_HBUFF_PREV(n)	((n) ? (n)-1 : SMTP_HBUFF_SIZE-1)

/* The initial size of a big buffer for use in various places. It gets put
into big_buffer_size and in some circumstances increased. It should be at least
as long as the maximum path length PLUS room for string additions.
Let's go with "at least twice as large as maximum path length".
*/

#ifdef AUTH_HEIMDAL_GSSAPI
		/* RFC 4121 section 5.2, SHOULD support 64K input buffers */
# define __BIG_BUFFER_SIZE 65536
#else
# define __BIG_BUFFER_SIZE 16384
#endif

#ifndef PATH_MAX
/* exim.h will have ensured this exists before including us. */
# error headers confusion, PATH_MAX missing in macros.h
#endif
#if (PATH_MAX*2) > __BIG_BUFFER_SIZE
# define BIG_BUFFER_SIZE (PATH_MAX*2)
#else
# define BIG_BUFFER_SIZE __BIG_BUFFER_SIZE
#endif

/* header size of pipe content
   currently: char id, char subid, char[5] length */
#define PIPE_HEADER_SIZE 7

/* This limits the length of data returned by local_scan(). Because it is
written on the spool, it gets read into big_buffer. */

#define LOCAL_SCAN_MAX_RETURN (BIG_BUFFER_SIZE - 24)

/* The length of the base names of spool files, which consist of an internal
message id with a trailing "-H" or "-D" added. */

#define SPOOL_NAME_LENGTH_OLD	(MESSAGE_ID_LENGTH_OLD + 2)
#define SPOOL_NAME_LENGTH	(MESSAGE_ID_LENGTH     + 2)

/* The maximum number of message ids to store in a waiting database
record, and the max number of continuation records allowed. */

#define WAIT_NAME_MAX 50
#define WAIT_CONT_MAX 1000

/* Fixed option values for all PCRE functions */

#define PCRE_COPT 0   /* compile */
#define PCRE_EOPT 0   /* exec */

/* Macros for trivial functions */

#define xstr(x)		#x
#define str(x)		xstr(x)	/* stringize, expanding macros in arg first */
#define mac_ismsgid(s)	(regex_match(regex_ismsgid, (s), -1, NULL))


/* Options for dns_next_rr */

enum { RESET_NEXT, RESET_ANSWERS, RESET_AUTHORITY, RESET_ADDITIONAL };

/* Argument values for the time-of-day function */

enum { tod_log, tod_log_bare, tod_log_zone, tod_log_datestamp_daily,
       tod_log_datestamp_monthly, tod_zone, tod_full, tod_bsdin,
       tod_mbx, tod_epoch, tod_epoch_l, tod_zulu };

/* For identifying types of driver */

enum {
  EXIM_DTYPE_NONE,
  EXIM_DTYPE_ROUTER,
  EXIM_DTYPE_TRANSPORT
};

/* Error numbers for generating error messages when reading a message on the
standard input. */

enum {
  ERRMESS_BADARGADDRESS,    /* Bad address via argument list */
  ERRMESS_BADADDRESS,       /* Bad address read via -t */
  ERRMESS_NOADDRESS,        /* Message has no addresses */
  ERRMESS_IGADDRESS,        /* All -t addresses ignored */
  ERRMESS_BADNOADDRESS,     /* Bad address via -t, leaving none */
  ERRMESS_IOERR,            /* I/O error while reading a message */
  ERRMESS_VLONGHEADER,      /* Excessively long message header */
  ERRMESS_VLONGHDRLINE,     /* Excessively long single line in header */
  ERRMESS_TOOBIG,           /* Message too big */
  ERRMESS_TOOMANYRECIP,     /* Too many recipients */
  ERRMESS_LOCAL_SCAN,       /* Rejected by local scan */
  ERRMESS_LOCAL_ACL,        /* Rejected by non-SMTP ACL */
  ERRMESS_DMARC_FORENSIC    /* DMARC Forensic Report */
};

/* Error handling styles - set by option, and apply only when receiving
a local message not via SMTP. */

enum {
  ERRORS_SENDER,            /* Return to sender (default) */
  ERRORS_STDERR             /* Write on stderr */
};

/* Exec control values when Exim execs itself via child_exec_exim. */

enum {
  CEE_RETURN_ARGV,          /* Don't exec, just build and return argv */
  CEE_EXEC_EXIT,            /* Just exit if exec fails */
  CEE_EXEC_PANIC            /* Panic-die if exec fails */
};

/* Bit values for filter_test */

#define FTEST_NONE     0    /* Not filter testing */
#define FTEST_USER     1    /* Testing user filter */
#define FTEST_SYSTEM   2    /* Testing system filter */

/* Returns from the routing, transport and authentication functions (not all
apply to all of them). Some other functions also use these convenient values,
and some additional values are used only by non-driver functions.

OK, FAIL, DEFER, ERROR, and FAIL_FORCED are also declared in local_scan.h for
use in the local_scan() function and in ${dlfunc loaded functions. Do not
change them unilaterally.

Use rc_names[] for debug strings. */

#define  OK            0    /* Successful match */
#define  DEFER         1    /* Defer - some problem */
#define  FAIL          2    /* Matching failed */
#define  ERROR         3    /* Internal or config error */
#define  FAIL_FORCED   4    /* "Forced" failure */
/***********/
#define DECLINE        5    /* Declined to handle the address, pass to next
                                 router unless no_more is set */
#define PASS           6    /* Pass to next driver, or to pass_router,
                                 even if no_more is set */
#define DISCARD        7    /* Address routed to :blackhole: or "seen finish" */
#define SKIP           8    /* Skip this router (used in route_address only) */
#define REROUTED       9    /* Address was changed and child created*/
#define PANIC         10    /* Hard failed with internal error */
#define BAD64         11    /* Bad base64 data (auth) */
#define UNEXPECTED    12    /* Unexpected initial auth data */
#define CANCELLED     13    /* Authentication cancelled */
#define FAIL_SEND     14    /* send() failed in authenticator */
#define FAIL_DROP     15    /* Fail and drop connection (used in ACL) */
#define DANE	      16    /* Deferred for domain mismatch (used in transport) */

/* Returns from the deliver_message() function */

#define DELIVER_ATTEMPTED_NORMAL   0  /* Tried a normal delivery */
#define DELIVER_MUA_SUCCEEDED      1  /* Success when mua_wrapper is set */
#define DELIVER_MUA_FAILED         2  /* Failure when mua_wrapper is set */
#define DELIVER_NOT_ATTEMPTED      3  /* Not tried (no msg or is locked */

/* Returns from DNS lookup functions. Use dns_rc_names[] for debug strings */

enum { DNS_SUCCEED, DNS_NOMATCH, DNS_NODATA, DNS_AGAIN, DNS_FAIL };

/* Ending states when reading a message. The order is important. The test
for having to swallow the rest of an SMTP message is whether the value is
>= END_NOTENDED. */

#define END_NOTSTARTED 0    /* Message not started */
#define END_DOT        1    /* Message ended with '.' */
#define END_EOF        2    /* Message ended with EOF (error for SMTP) */
#define END_NOTENDED   3    /* Message reading not yet ended */
#define END_SIZE       4    /* Reading ended because message too big */
#define END_WERROR     5    /* Write error while reading the message */
#define END_PROTOCOL   6    /* Protocol error in CHUNKING sequence */

/* result codes for bdat_getc() (which can also return EOF) */

#define EOD (-2)
#define ERR (-3)


/* Bit masks for debug and log selectors */

#ifndef bitmask_word_t
# define bitmask_word_t          uint64_t
#endif

/* Assume words are at least 32 bits wide. Tiny waste of space on 64 bit
platforms, but this ensures bit vectors always work the same way. */
#ifdef EXIM_BITMAP_WORD_BITS
# define BITWORDSIZE EXIM_BITMAP_WORD_BITS
#else
# define BITWORDSIZE 64
#endif

/* This macro is for single-word bit vectors: the debug selector,
and the first word of the log selector. For multi-word vectors we
use inlinable functions. */

#define BIT(n) ((bitmask_word_t)1 << (n))

#define BITWORD(n) (    (n) / BITWORDSIZE)
#define BITMASK(n) (BIT((n) % BITWORDSIZE))

/* Debugging control */

#define DEBUG_SELECTOR_SIZE		(BITWORD(debug_chan_count) + 1)

extern bitmask_word_t * debug_selector;   /* Debugging bits */

static inline bitmask_word_t
bit_test(bitmask_word_t * tbl, unsigned bitnum)
{ return tbl[BITWORD(bitnum)] & BITMASK(bitnum); }
#define DEBUG_BIT(n)	(debug_selector && bit_test(debug_selector, n))
#define ANY_DEBUG	DEBUG_BIT(BIT_TABLE_IDX_NONZERO)

extern BOOL    is_debug(const uschar *);
#define IS_DEBUG(list)	(ANY_DEBUG && is_debug(US # list))
#define DEBUG(list)	if (IS_DEBUG(list))
#define HDEBUG(list)	if (host_checking || IS_DEBUG(list))

#define EARLY_DEBUG(x, fmt, ...) \
  if (debug_fd >= 0) \
    { DEBUG(x) debug_printf_indent(fmt, __VA_ARGS__); } \
  else if (debug_startup) \
    fprintf(stderr, "%s", string_sprintf(fmt, __VA_ARGS__));

/* IOTA allows us to keep an implicit sequential count, like a simple enum,
but we can have sequentially numbered identifiers which are not declared
sequentially. We use this for more compact declarations of bit indexes and
masks, alternating between sequential bit index and corresponding mask. */

#define IOTA(iota)      (__LINE__ - iota)
#define IOTA_INIT(zero) (__LINE__ - zero + 1)

/* Options bits for debugging.
Because of the history of debug within Exim, we have to generate various
meta-info bits.  Also, we want to be able to determine quickly when debug
is not enabled (that being the common case).  On the other hand we want to
have many individually selectable debug channels; possibly more than there
are bits in a single word. So we use a multiword array of bits, and reserve
some in the first word for the meta-info. One of those is a single bit OR
of all the channel bits, giving us the fast test. Code testing the specific
channel enables is then out-of-line and can be slow.  We use the channel
names in the sourcecode, converting to channel numbers to do the test against
the array of bits. */

/* Special bits used for debug and logging control. These are summarizing sets
of enabled channels, and are in the first word of the selector array for quick
access. */

#define BIT_TABLE_IDX_ALL	0	/* code for nearly-all-bits-set */
#define BIT_TABLE_IDX_NONZERO	1	/* at least one bit is set */
#define BIT_TABLE_IDX_NONVERB	2	/* a bit apart from "v" is set */
#define BIT_TABLE_IDX_IS_ANY	3	/* a bit apart from "v'-like ones is set */
#define BIT_TABLE_IDX_USABLE	4	/* first named bit */

#define BIT_TABLE_SUMMARY_MASK (BIT(BIT_TABLE_IDX_NONZERO) \
				| BIT(BIT_TABLE_IDX_NONVERB) \
				| BIT(BIT_TABLE_IDX_NONVERB))

#define BITMASK_IDX_TO_BIT(idx) ((bitmask_word_t)1 << (idx))
#define BIT_TABLE_BIT(class, name) \
			class##i_##name = IOTA(class##i_iota), \
			class##_##name = BITMASK_IDX_TO_BIT(class##i_##name)


/* Bits for debug triggers */

enum {
  DTi_panictrigger,
  DTi_pretrigger,
};

/* Options bits for logging. Those that have values < BITWORDSIZE can be used
in calls to log_write(). The others are put into later words in log_selector
and are only ever tested independently, so they do not need bit mask
declarations. The "all" name string is recognized specially by decode_bits().
Add also to log_options[] when creating new ones. */

/*XXX The use of this facility in calls to log_write() forces the presence and
maintenance of this separate table.  It would be good to lose it.  Why cannot
the LOGWRITE() macro be tested at the call point?
- currently we debug-output the log call even when a requested log channel
  is not enabled. A naive replacement would lose that.
- the fn arg only controls LOG_MAIN log output, not LOG_REJECT or LOG_PANIC
  - are there such cases?
    - receive.c 2359, 3330
    - smtp_in.c 2620, 3706, 5088, 5136
    - all main+reject
    - though the docs say only "a log line is written", so a quiet behaviour
      change could be argued for
*/

#define LOG_BIT(name) BIT_TABLE_BIT(L, name)

/* Bit numbers used by calls to log_write() */

enum logwrite_bit {
  Li_iota = IOTA_INIT(0),
  LOG_BIT(address_rewrite),
  LOG_BIT(all_parents),
  LOG_BIT(connection_reject),
  LOG_BIT(delay_delivery),
  LOG_BIT(dnslist_defer),
  LOG_BIT(etrn),
  LOG_BIT(host_lookup_failed),
  LOG_BIT(lost_incoming_connection),	/* 7 */
  LOG_BIT(queue_run),
  LOG_BIT(retry_defer),
  LOG_BIT(size_reject),
  LOG_BIT(skip_delivery),
  LOG_BIT(smtp_connection),
  LOG_BIT(smtp_incomplete_transaction),
  LOG_BIT(smtp_protocol_error),
  LOG_BIT(smtp_syntax_error),		/* 15 */
};

/* Bit numbers used by the LOGGING() macro */

enum logging_test_bit {	/* names matching log_channels[] */
  Lt_all = BIT_TABLE_IDX_ALL,		/* 0 */

  Lt_8bitmime = BIT_TABLE_IDX_USABLE,	/* 4 */
  Lt_acl_warn_skipped,
  Lt_address_rewrite,
  Lt_all_parents,			/* 7 */
  Lt_arguments,
  Lt_connection_id,
  Lt_connection_reject,
  Lt_delay_delivery,
  Lt_deliver_time,
  Lt_delivery_size,
  Lt_dkim,
  Lt_dkim_verbose,			/* 15 */
  Lt_dmarc,
  Lt_dmarc_verbose,
  Lt_dnslist_defer,
  Lt_dnssec,
  Lt_dsn,
  Lt_etrn,
  Lt_host_lookup_failed,
  Lt_ident_timeout,
  Lt_incoming_interface,
  Lt_incoming_port,
  Lt_lost_incoming_connection,
  Lt_millisec,
  Lt_msg_id,
  Lt_msg_id_created,
  Lt_outgoing_interface,
  Lt_outgoing_port,			/* 31 */
  Lt_pid,
  Lt_pipelining,
  Lt_protocol_detail,
  Lt_proxy,
  Lt_queue_run,
  Lt_queue_time,
  Lt_queue_time_exclusive,
  Lt_queue_time_overall,
  Lt_receive_time,
  Lt_received_recipients,
  Lt_received_sender,
  Lt_rejected_header,
  Lt_retry_defer,
  Lt_return_path_on_delivery,
  Lt_sender_on_delivery,
  Lt_sender_verify_fail,		/* 47 */
  Lt_size_reject,
  Lt_skip_delivery,
  Lt_smtp_confirmation,
  Lt_smtp_connection,
  Lt_smtp_incomplete_transaction,
  Lt_smtp_mailauth,
  Lt_smtp_no_mail,
  Lt_smtp_protocol_error,
  Lt_smtp_syntax_error,
  Lt_spf,
  Lt_spf_verbose,
  Lt_subject,
  Lt_tls_certificate_verified,
  Lt_tls_cipher,
  Lt_tls_on_connect,
  Lt_tls_peerdn,			/* 63 */
  Lt_tls_resumption,
  Lt_tls_sni,
  Lt_unknown_in_list,

  log_selector_size = BITWORD(Lt_unknown_in_list) + 1
};

#define LOGGING(opt) bit_test(log_selector, Lt_##opt)

/* Private error numbers for delivery failures, set negative so as not
to conflict with system errno values.  Take care to maintain the string
table exim_errstrings[] in log.c */

#define ERRNO_UNKNOWNERROR    (-1)
#define ERRNO_USERSLASH       (-2)
#define ERRNO_EXISTRACE       (-3)
#define ERRNO_NOTREGULAR      (-4)
#define ERRNO_NOTDIRECTORY    (-5)
#define ERRNO_BADUGID         (-6)
#define ERRNO_BADMODE         (-7)
#define ERRNO_INODECHANGED    (-8)
#define ERRNO_LOCKFAILED      (-9)
#define ERRNO_BADADDRESS2    (-10)
#define ERRNO_FORBIDPIPE     (-11)
#define ERRNO_FORBIDFILE     (-12)
#define ERRNO_FORBIDREPLY    (-13)
#define ERRNO_MISSINGPIPE    (-14)
#define ERRNO_MISSINGFILE    (-15)
#define ERRNO_MISSINGREPLY   (-16)
#define ERRNO_BADREDIRECT    (-17)
#define ERRNO_SMTPCLOSED     (-18)
#define ERRNO_SMTPFORMAT     (-19)
#define ERRNO_SPOOLFORMAT    (-20)
#define ERRNO_NOTABSOLUTE    (-21)
#define ERRNO_EXIMQUOTA      (-22)   /* Exim-imposed quota */
#define ERRNO_HELD           (-23)
#define ERRNO_FILTER_FAIL    (-24)   /* Delivery filter process failure */
#define ERRNO_CHHEADER_FAIL  (-25)   /* Delivery add/remove header failure */
#define ERRNO_WRITEINCOMPLETE (-26)  /* Delivery write incomplete error */
#define ERRNO_EXPANDFAIL     (-27)   /* Some expansion failed */
#define ERRNO_GIDFAIL        (-28)   /* Failed to get gid */
#define ERRNO_UIDFAIL        (-29)   /* Failed to get uid */
#define ERRNO_BADTRANSPORT   (-30)   /* Unset or non-existent transport */
#define ERRNO_MBXLENGTH      (-31)   /* MBX length mismatch */
#define ERRNO_UNKNOWNHOST    (-32)   /* Lookup failed routing or in smtp tpt */
#define ERRNO_FORMATUNKNOWN  (-33)   /* Can't match format in appendfile */
#define ERRNO_BADCREATE      (-34)   /* Creation outside home in appendfile */
#define ERRNO_LISTDEFER      (-35)   /* Can't check a list; lookup defer */
#define ERRNO_DNSDEFER       (-36)   /* DNS lookup defer */
#define ERRNO_TLSFAILURE     (-37)   /* Failed to start TLS session */
#define ERRNO_TLSREQUIRED    (-38)   /* Mandatory TLS session not started */
#define ERRNO_CHOWNFAIL      (-39)   /* Failed to chown a file */
#define ERRNO_PIPEFAIL       (-40)   /* Failed to create a pipe */
#define ERRNO_CALLOUTDEFER   (-41)   /* When verifying */
#define ERRNO_AUTHFAIL       (-42)   /* When required by client */
#define ERRNO_CONNECTTIMEOUT (-43)   /* Used internally in smtp transport */
#define ERRNO_RCPT4XX        (-44)   /* RCPT gave 4xx error */
#define ERRNO_MAIL4XX        (-45)   /* MAIL gave 4xx error */
#define ERRNO_DATA4XX        (-46)   /* DATA gave 4xx error */
#define ERRNO_PROXYFAIL      (-47)   /* Negotiation failed for proxy configured host */
#define ERRNO_AUTHPROB       (-48)   /* Authenticator "other" failure */
#define ERRNO_UTF8_FWD       (-49)   /* target not supporting SMTPUTF8 */
#define ERRNO_HOST_IS_LOCAL  (-50)   /* Transport refuses to talk to localhost */
#define ERRNO_PASSONE        (-51)   /* first-pass-only routing */
#define ERRNO_NOROUTER       (-52)   /* ran out of routers */
#define ERRNO_ROUTERDEFER    (-53)   /* redirect router :defer: */
#define ERRNO_ROUTERFAIL     (-54)   /* redirect router :fail: */
#define ERRNO_MXDEFER	     (-55)   /* missing MX, defer requested */
#define ERRNO_TPTLIMIT       (-57)   /* transport limit */
#define ERRNO_TAINT          (-58)   /* Transport refuses to use tainted filename */

/* These must be last, so all retry deferments can easily be identified */

#define ERRNO_RETRY_BASE     (-59)   /* Base to test against */
#define ERRNO_RRETRY         (-59)   /* Not time for routing */

#define ERRNO_WARN_BASE      (-60)   /* Base to test against */
#define ERRNO_LRETRY         (-60)   /* Not time for local delivery */
#define ERRNO_HRETRY         (-61)   /* Not time for any remote host */
#define ERRNO_LOCAL_ONLY     (-62)   /* Local-only delivery */
#define ERRNO_QUEUE_DOMAIN   (-63)   /* Domain in queue_domains */
#define ERRNO_TRETRY         (-64)   /* Transport concurrency limit */
#define ERRNO_EVENT	     (-65)   /* Event processing request alternate response */



/* Special actions to take after failure or deferment. */

enum {
  SPECIAL_NONE,             /* No special action */
  SPECIAL_FREEZE,           /* Freeze message */
  SPECIAL_FAIL,             /* Fail the delivery */
  SPECIAL_WARN              /* Send a warning message */
};

/* Flags that get ORed into the more_errno field of an address to give more
information about errors for retry purposes. They are greater than 256, because
the bottom byte contains 'A' or 'M' for remote addresses, to indicate whether
the name was looked up only via an address record or whether MX records were
used, respectively. */

#define RTEF_CTOUT     0x0100      /* Connection timed out */

/* Permission and other options for parse_extract_addresses(),
filter_interpret(), and rda_interpret(), i.e. what special things are allowed
in redirection operations. Not all apply to all cases. Some of the bits allow
and some forbid, reflecting the "allow" and "forbid" options in the redirect
router, which were chosen to represent the standard situation for users'
.forward files. */

#define RDO_BLACKHOLE    0x00000001  /* Forbid :blackhole: */
#define RDO_DEFER        0x00000002  /* Allow :defer: or "defer" */
#define RDO_EACCES       0x00000004  /* Ignore EACCES */
#define RDO_ENOTDIR      0x00000008  /* Ignore ENOTDIR */
#define RDO_EXISTS       0x00000010  /* Forbid "exists" in expansion in filter */
#define RDO_FAIL         0x00000020  /* Allow :fail: or "fail" */
#define RDO_FILTER       0x00000040  /* Allow a filter script */
#define RDO_FREEZE       0x00000080  /* Allow "freeze" */
#define RDO_INCLUDE      0x00000100  /* Forbid :include: */
#define RDO_LOG          0x00000200  /* Forbid "log" */
#define RDO_LOOKUP       0x00000400  /* Forbid "lookup" in expansion in filter */
#define RDO_PERL         0x00000800  /* Forbid "perl" in expansion in filter */
#define RDO_READFILE     0x00001000  /* Forbid "readfile" in exp in filter */
#define RDO_READSOCK     0x00002000  /* Forbid "readsocket" in exp in filter */
#define RDO_RUN          0x00004000  /* Forbid "run" in expansion in filter */
#define RDO_DLFUNC       0x00008000  /* Forbid "dlfunc" in expansion in filter */
#define RDO_REALLOG      0x00010000  /* Really do log (not testing/verifying) */
#define RDO_REWRITE      0x00020000  /* Rewrite generated addresses */
#define RDO_EXIM_FILTER  0x00040000  /* Forbid Exim filters */
#define RDO_SIEVE_FILTER 0x00080000  /* Forbid Sieve filters */
#define RDO_PREPEND_HOME 0x00100000  /* Prepend $home to relative paths in Exim filter save commands */

/* This is the set that apply to expansions in filters */

#define RDO_FILTER_EXPANSIONS \
  (RDO_EXISTS|RDO_LOOKUP|RDO_PERL|RDO_READFILE|RDO_READSOCK|RDO_RUN|RDO_DLFUNC)

/* As well as the RDO bits themselves, we need the bit numbers in order to
access (most of) the individual bits as separate options. This could be
automated, but I haven't bothered. Keep this list in step with the above! */

enum { RDON_BLACKHOLE, RDON_DEFER, RDON_EACCES, RDON_ENOTDIR, RDON_EXISTS,
  RDON_FAIL, RDON_FILTER, RDON_FREEZE, RDON_INCLUDE, RDON_LOG, RDON_LOOKUP,
  RDON_PERL, RDON_READFILE, RDON_READSOCK, RDON_RUN, RDON_DLFUNC, RDON_REALLOG,
  RDON_REWRITE, RDON_EXIM_FILTER, RDON_SIEVE_FILTER, RDON_PREPEND_HOME };

/* Results of filter or forward file processing. Some are only from a filter;
some are only from a forward file. */

enum {
  FF_DELIVERED,         /* Success, took significant action */
  FF_NOTDELIVERED,      /* Success, didn't take significant action */
  FF_BLACKHOLE,         /* Blackholing requested */
  FF_DEFER,             /* Defer requested */
  FF_FAIL,              /* Fail requested */
  FF_INCLUDEFAIL,       /* :include: failed */
  FF_NONEXIST,          /* Forward file does not exist */
  FF_FREEZE,            /* Freeze requested */
  FF_ERROR              /* We have a problem */
};

/* Values for identifying particular headers; printing characters are used, so
they can be read in the spool file for those headers that are permanently
marked. The lower case values don't get onto the spool; they are used only as
return values from header_checkname(). */

#define htype_other         ' '   /* Unspecified header */
#define htype_from          'F'
#define htype_to            'T'
#define htype_cc            'C'
#define htype_bcc           'B'
#define htype_id            'I'   /* for message-id */
#define htype_reply_to      'R'
#define htype_received      'P'   /* P for Postmark */
#define htype_sender        'S'
#define htype_old           '*'   /* Replaced header */

#define htype_date          'd'
#define htype_return_path   'p'
#define htype_delivery_date 'x'
#define htype_envelope_to   'e'
#define htype_subject       's'

/* These values are used only when adding new headers from an ACL; they too
never get onto the spool. The type of the added header is set by reference
to the header name, by calling header_checkname(). */

#define htype_add_top       'a'
#define htype_add_rec       'r'
#define htype_add_bot       'z'
#define htype_add_rfc       'f'

/* Types of item in options lists. These are the bottom 8 bits of the "type"
field, which is an int. The opt_void value is used for entries in tables that
point to special types of value that are accessed only indirectly (e.g. the
rewrite data that is built out of a string option.) We need to have some values
visible in local_scan, so the following are declared there:

  opt_stringptr, opt_int, opt_octint, opt_mkint, opt_Kint, opt_fixed, opt_time,
  opt_bool

To make sure we don't conflict, the local_scan.h values start from zero, and
those defined here start from 32. The boolean ones must all be together so they
can be easily tested as a group. That is the only use of opt_bool_last. */

enum { opt_bit = 32, opt_bool_verify, opt_bool_set, opt_expand_bool,
  opt_bool_last,
  opt_rewrite, opt_timelist, opt_uid, opt_gid, opt_uidlist, opt_gidlist,
  opt_expand_uid, opt_expand_gid, opt_func, opt_void,
  opt_lookup_module, opt_misc_module };

/* There's a high-ish bit which is used to flag duplicate options, kept
for compatibility, which shouldn't be output. Also used for hidden options
that are automatically maintained from others. Another high bit is used to
flag driver options that although private (so as to be settable only on some
drivers), are stored in the instance block so as to be accessible from outside.
A third high bit is set when an option is read, so as to be able to give an
error if any option is set twice. Finally, there's a bit which is set when an
option is set with the "hide" prefix, to prevent -bP from showing it to
non-admin callers. The next byte up in the int is used to keep the bit number
for booleans that are kept in one bit. */

#define opt_hidden  0x100      /* Private to Exim */
#define opt_public  0x200      /* Stored in the main instance block */
#define opt_set     0x400      /* Option is set */
#define opt_secure  0x800      /* "hide" prefix used */
#define opt_rep_con 0x1000     /* Can be appended to by a repeated line (condition) */
#define opt_rep_str 0x2000     /* Can be appended to by a repeated line (string) */
#define opt_mask    0x00ff

/* Verify types when directing and routing */

enum { v_none, v_sender, v_recipient, v_expn };

/* Option flags for verify_address() */

#define vopt_fake_sender          0x0001   /* for verify=sender=<address> */
#define vopt_is_recipient         0x0002
#define vopt_qualify              0x0004
#define vopt_expn                 0x0008
#define vopt_callout_fullpm       0x0010   /* full postmaster during callout */
#define vopt_callout_random       0x0020   /* during callout */
#define vopt_callout_no_cache     0x0040   /* disable callout cache */
#define vopt_callout_recipsender  0x0080   /* use real sender to verify recip */
#define vopt_callout_r_pmaster	  0x0100   /* use postmaster to verify recip */
#define vopt_callout_r_tptsender  0x0200   /* use s from tpt to verify recip */
#define vopt_callout_hold	  0x0400   /* lazy close connection */
#define vopt_success_on_redirect  0x0800
#define vopt_quota                0x1000   /* quota check, to local/appendfile */
#define vopt_atrn		  0x2000   /* ATRN customer mode */

/* Values for fields in callout cache records */

#define ccache_unknown         0       /* test hasn't been done */
#define ccache_accept          1
#define ccache_reject          2       /* All rejections except */
#define ccache_reject_mfnull   3       /* MAIL FROM:<> was rejected */

/* Options for lookup functions */

#define lookup_querystyle      1    /* query-style lookup */
#define lookup_absfile         2    /* requires absolute file name */
#define lookup_absfilequery    4    /* query-style starts with file name */

/* Status values for host_item blocks. Require hstatus_unusable and
hstatus_unusable_expired to be last. */

enum { hstatus_unknown, hstatus_usable, hstatus_unusable,
       hstatus_unusable_expired };

/* Reasons why a host is unusable (for clearer log messages) */

enum { hwhy_unknown, hwhy_retry, hwhy_insecure, hwhy_failed, hwhy_deferred,
       hwhy_ignored };

/* Domain lookup types for routers */

#define LK_DEFAULT	BIT(0)
#define LK_BYNAME	BIT(1)
#define LK_BYDNS	BIT(2)	/* those 3 should be mutually exclusive */

#define LK_IPV4_ONLY	BIT(3)
#define LK_IPV4_PREFER	BIT(4)

/* Values for the self_code fields */

enum { self_freeze, self_defer, self_send, self_reroute, self_pass, self_fail };

/* Flags for rewrite rules */

#define rewrite_sender       0x0001
#define rewrite_from         0x0002
#define rewrite_to           0x0004
#define rewrite_cc           0x0008
#define rewrite_bcc          0x0010
#define rewrite_replyto      0x0020
#define rewrite_all_headers  0x003F  /* all header flags */

#define rewrite_envfrom      0x0040
#define rewrite_envto        0x0080
#define rewrite_all_envelope 0x00C0  /* all envelope flags */

#define rewrite_all      (rewrite_all_headers | rewrite_all_envelope)

#define rewrite_smtp         0x0100  /* rewrite at SMTP time */
#define rewrite_smtp_sender  0x0200  /* SMTP sender rewrite (allows <>) */
#define rewrite_qualify      0x0400  /* qualify if necessary */
#define rewrite_repeat       0x0800  /* repeat rewrite rule */

#define rewrite_whole        0x1000  /* option bit for headers */
#define rewrite_quit         0x2000  /* "no more" option */

/* Flags for log_write(); LOG_MAIN, LOG_PANIC, and LOG_REJECT are also in
local_scan.h */

#define LOG_MAIN           1      /* Write to the main log */
#define LOG_PANIC          2      /* Write to the panic log */
#define LOG_PANIC_DIE      6      /* Write to the panic log and then die */
#define LOG_REJECT        16      /* Write to the reject log, with headers */
#define LOG_SENDER        32      /* Add raw sender to the message */
#define LOG_RECIPIENTS    64      /* Add raw recipients to the message */
#define LOG_CONFIG       128      /* Add "Exim configuration error" */
#define LOG_CONFIG_FOR  (256+128) /* Add " for" instead of ":\n" */
#define LOG_CONFIG_IN   (512+128) /* Add " in line x[ of file y]" */

/* flags for decode_bits */

#define DCB_LOG		BIT(0)
#define DCB_DEBUG	BIT(1)
#define DCB_FROM_CONFIG	BIT(2)

/* SMTP command identifiers for the smtp_connection_had field that records the
most recent SMTP commands. SCH_NONE is "empty".  The smtp_names array must have
an entry for each. */

enum { SCH_NONE, SCH_AUTH, SCH_DATA, SCH_BDAT,
       SCH_EHLO, SCH_ATRN, SCH_ETRN, SCH_EXPN, SCH_HELO,
       SCH_HELP, SCH_MAIL, SCH_NOOP, SCH_QUIT, SCH_RCPT, SCH_RSET, SCH_STARTTLS,
       SCH_VRFY,
#ifndef DISABLE_WELLKNOWN
       SCH_WELLKNOWN,
#endif
#ifdef EXPERIMENTAL_XCLIENT
       SCH_XCLIENT,
#endif
       };

/* Returns from host_find_by{name,dns}() */

enum {
  HOST_FIND_FAILED,     /* failed to find the host */
  HOST_FIND_AGAIN,      /* could not resolve at this time */
  HOST_FIND_SECURITY,   /* dnssec required but not acheived */
  HOST_FOUND,           /* found host */
  HOST_FOUND_LOCAL,     /* found, but MX points to local host */
  HOST_IGNORED          /* found but ignored - used internally only */
};

/* Flags for host_find_bydns() */

#define HOST_FIND_BY_SRV          BIT(0)
#define HOST_FIND_BY_MX           BIT(1)
#define HOST_FIND_BY_A            BIT(2)
#define HOST_FIND_BY_AAAA         BIT(3)
#define HOST_FIND_QUALIFY_SINGLE  BIT(4)
#define HOST_FIND_SEARCH_PARENTS  BIT(5)
#define HOST_FIND_IPV4_FIRST	  BIT(6)
#define HOST_FIND_IPV4_ONLY	  BIT(7)

/* Actions applied to specific messages. */

enum { MSG_DELIVER, MSG_FREEZE, MSG_REMOVE, MSG_THAW, MSG_ADD_RECIPIENT,
       MSG_MARK_ALL_DELIVERED, MSG_MARK_DELIVERED, MSG_EDIT_SENDER,
       MSG_SHOW_COPY, MSG_LOAD, MSG_SETQUEUE,
       /* These ones must be last: a test for >= MSG_SHOW_BODY is used
       to test for actions that list individual spool files. */
       MSG_SHOW_BODY, MSG_SHOW_HEADER, MSG_SHOW_LOG };

/* Returns from the spool_read_header() function */

enum {
  spool_read_OK,        /* success */
  spool_read_notopen,   /* open failed */
  spool_read_enverror,  /* error in the envelope */
  spool_read_hdrerror   /* error in the headers */
};

/* Options for transport_write_message */

#define topt_add_return_path    BIT(0)
#define topt_add_delivery_date  BIT(1)
#define topt_add_envelope_to    BIT(2)
#define topt_escape_headers     BIT(3)	/* Apply escape check to headers */
#define topt_truncate_headers   BIT(4)	/* Truncate header lines at 998 chars */
#define topt_use_crlf           BIT(5)	/* Terminate lines with CRLF */
#define topt_no_headers         BIT(6)	/* Omit headers */
#define topt_no_body            BIT(7)	/* Omit body */
#define topt_end_dot            BIT(8)	/* Send terminating dot line */
#define topt_no_flush		BIT(9)	/* more data expected after message (eg QUIT) */
#define topt_use_bdat		BIT(10)	/* prepend chunks with RFC3030 BDAT header */
#define topt_output_string	BIT(11)	/* create string rather than write to fd */
#define topt_continuation	BIT(12)	/* do not reset buffer */
#define topt_not_socket		BIT(13)	/* cannot do socket-only syscalls */

/* Options for smtp_write_command */

enum {
  SCMD_FLUSH = 0,	/* write to kernel */
  SCMD_MORE,		/* write to kernel, but likely more soon */
  SCMD_BUFFER		/* stash in application cmd output buffer */
};

/* Flags for recipient_block, used in DSN support */

#define rf_notify_unset		0x00
#define rf_dsnlasthop           0x01  /* Do not propagate DSN any further */
#define rf_notify_never         0x02  /* NOTIFY= settings */
#define rf_notify_success       0x04
#define rf_notify_failure       0x08
#define rf_notify_delay         0x10

#define rf_dsnflags  (rf_notify_never | rf_notify_success | \
                      rf_notify_failure | rf_notify_delay)

/* DSN RET types */

#define dsn_ret_full            1
#define dsn_ret_hdrs            2

#define dsn_support_unknown     0
#define dsn_support_yes         1
#define dsn_support_no          2


/* Codes for the host_find_failed and host_all_ignored options. */

#define hff_freeze   0
#define hff_defer    1
#define hff_pass     2
#define hff_decline  3
#define hff_fail     4
#define hff_ignore   5

/* Router information flags */

#define ri_yestransport    0x0001    /* Must have a transport */
#define ri_notransport     0x0002    /* Must not have a transport */

/* Codes for match types in match_check_list; to any of them, MCL_NOEXPAND may
be added */

#define MCL_NOEXPAND  16

enum { MCL_STRING, MCL_DOMAIN, MCL_HOST, MCL_ADDRESS, MCL_LOCALPART };

/* Codes for the places from which ACLs can be called. These are cunningly
ordered to make it easy to implement tests for certain ACLs when processing
"control" modifiers, by means of a maximum "where" value. Do not modify this
order without checking carefully!

**** IMPORTANT***
****   Furthermore, remember to keep these in step with the tables
****   of names and response codes in globals.c.
**** IMPORTANT ****
*/

enum { ACL_WHERE_RCPT,		/* Some controls are for RCPT only */
       ACL_WHERE_MAIL,		/* )						*/
       ACL_WHERE_PREDATA,	/* ) There are several tests for "in message",	*/
       ACL_WHERE_MIME,		/* ) implemented by <= WHERE_NOTSMTP		*/
       ACL_WHERE_DKIM,		/* )						*/
       ACL_WHERE_DATA,		/* )						*/
#ifndef DISABLE_PRDR
       ACL_WHERE_PRDR,		/* )						*/
#endif
       ACL_WHERE_NOTSMTP,	/* )						*/

       ACL_WHERE_AUTH,		/* These remaining ones are not currently	*/
       ACL_WHERE_ATRN,		/* */
       ACL_WHERE_CONNECT,	/* required to be in a special order so they	*/
       ACL_WHERE_ETRN,		/* are just alphabetical.			*/
       ACL_WHERE_EXPN,
       ACL_WHERE_HELO,
       ACL_WHERE_MAILAUTH,
       ACL_WHERE_NOTSMTP_START,
       ACL_WHERE_NOTQUIT,
       ACL_WHERE_QUIT,
       ACL_WHERE_STARTTLS,
#ifndef DISABLE_WELLKNOWN
       ACL_WHERE_WELLKNOWN,
#endif
       ACL_WHERE_VRFY,

       ACL_WHERE_DELIVERY,
       ACL_WHERE_UNKNOWN     /* Currently used by a ${acl:name} expansion */
     };

#define ACL_BIT_RCPT		BIT(ACL_WHERE_RCPT)
#define ACL_BIT_MAIL		BIT(ACL_WHERE_MAIL)
#define ACL_BIT_PREDATA		BIT(ACL_WHERE_PREDATA)
#define ACL_BIT_MIME		BIT(ACL_WHERE_MIME)
#define ACL_BIT_DKIM		BIT(ACL_WHERE_DKIM)
#define ACL_BIT_DATA		BIT(ACL_WHERE_DATA)
#ifdef DISABLE_PRDR
# define ACL_BIT_PRDR		0
#else
# define ACL_BIT_PRDR		BIT(ACL_WHERE_PRDR)
#endif
#define ACL_BIT_NOTSMTP		BIT(ACL_WHERE_NOTSMTP)
#define ACL_BIT_AUTH		BIT(ACL_WHERE_AUTH)
#define ACL_BIT_CONNECT		BIT(ACL_WHERE_CONNECT)
#define ACL_BIT_ATRN		BIT(ACL_WHERE_ATRN)
#define ACL_BIT_ETRN		BIT(ACL_WHERE_ETRN)
#define ACL_BIT_EXPN		BIT(ACL_WHERE_EXPN)
#define ACL_BIT_HELO		BIT(ACL_WHERE_HELO)
#define ACL_BIT_MAILAUTH	BIT(ACL_WHERE_MAILAUTH)
#define ACL_BIT_NOTSMTP_START	BIT(ACL_WHERE_NOTSMTP_START)
#define ACL_BIT_NOTQUIT		BIT(ACL_WHERE_NOTQUIT)
#define ACL_BIT_QUIT		BIT(ACL_WHERE_QUIT)
#define ACL_BIT_STARTTLS	BIT(ACL_WHERE_STARTTLS)
#define ACL_BIT_VRFY		BIT(ACL_WHERE_VRFY)
#ifndef DISABLE_WELLKNOWN
# define ACL_BIT_WELLKNOWN	BIT(ACL_WHERE_WELLKNOWN)
#endif
#define ACL_BIT_DELIVERY	BIT(ACL_WHERE_DELIVERY)
#define ACL_BIT_UNKNOWN		BIT(ACL_WHERE_UNKNOWN)

#define ACL_BITS_HAVEDATA	(ACL_BIT_MIME | ACL_BIT_DKIM | ACL_BIT_DATA \
				| ACL_BIT_PRDR \
				| ACL_BIT_NOTSMTP | ACL_BIT_QUIT | ACL_BIT_NOTQUIT)


/* Situations for spool_write_header() */

enum { SW_RECEIVING, SW_DELIVERING, SW_MODIFYING };

/* MX fields for hosts not obtained from MX records are always negative.
MX_NONE is the default case; lesser values are used when the hosts are
randomized in batches. */

#define MX_NONE           (-1)

/* host_item.port defaults to PORT_NONE; the only current case where this
is changed before running the transport is when an dnslookup router sets an
explicit port number. */

#define PORT_NONE     (-1)

/* Flags for single-key search defaults */

#define SEARCH_STAR       0x01
#define SEARCH_STARAT     0x02

/* Filter types */

enum { FILTER_UNSET, FILTER_FORWARD, FILTER_EXIM, FILTER_SIEVE };

/* Codes for ESMTP facilities offered by peer */

#define OPTION_TLS		BIT(0)
#define OPTION_IGNQ		BIT(1)
#define OPTION_PRDR		BIT(2)
#define OPTION_UTF8		BIT(3)
#define OPTION_DSN		BIT(4)
#define OPTION_PIPE		BIT(5)
#define OPTION_SIZE		BIT(6)
#define OPTION_CHUNKING		BIT(7)
#define OPTION_EARLY_PIPE	BIT(8)

/* Argument for *_getc */

#define GETC_BUFFER_UNLIMITED	UINT_MAX

/* Options on tls_close */
#define TLS_NO_SHUTDOWN		0	/* Just forget the context */
#define TLS_SHUTDOWN_NOWAIT	1	/* Send alert; do not wait */
#define TLS_SHUTDOWN_WAIT	2	/* Send alert & wait for peer's alert */
#define TLS_SHUTDOWN_WONLY	3	/* only wait for peer's alert */

#ifdef COMPILE_UTILITY
# define ALARM(seconds) alarm(seconds);
# define ALARM_CLR(seconds) alarm(seconds);
#else
/* For debugging of odd alarm-signal problems, stash caller info while the
alarm is active.  Clear it down on cancelling the alarm so we can tell there
should not be one active. */

# define ALARM(seconds) \
    ANY_DEBUG \
    ? (sigalarm_setter = U(__FUNCTION__), alarm(seconds)) : alarm(seconds);
# define ALARM_CLR(seconds) \
    ANY_DEBUG \
    ? (sigalarm_setter = NULL, alarm(seconds)) : alarm(seconds);
#endif

#define AUTHS_REGEX US"\\n250[\\s\\-]AUTH\\s+([\\-\\w \\t]+)(?:\\n|$)"

#define EARLY_PIPE_FEATURE_NAME "PIPECONNECT"
#define EARLY_PIPE_FEATURE_LEN  11


/* Flags for auth_client_item() */

#define AUTH_ITEM_FIRST	BIT(0)
#define AUTH_ITEM_LAST	BIT(1)
#define AUTH_ITEM_IGN64	BIT(2)


/* Flags for tls_{in,out}_resumption */
#define RESUME_SUPPORTED	BIT(0)
#define RESUME_CLIENT_REQUESTED	BIT(1)
#define RESUME_CLIENT_SUGGESTED	BIT(2)
#define RESUME_SERVER_TICKET	BIT(3)
#define RESUME_USED		BIT(4)

#define RESUME_DECODE_STRING \
  US"not requested or offered" \
    ": 0x02 :client requested, no server ticket" \
    ": 0x04 : 0x05 " \
    ": 0x06 :client offered session, no server action" \
    ": 0x08 :no client request" \
    ": 0x0A :client requested new ticket, server provided" \
    ": 0x0C :client offered session, not used" \
    ": 0x0E :client offered session, server only provided new ticket" \
    ": 0x10 :session resumed unasked" \
    ": 0x12 :session resumed unasked" \
    ": 0x14 : 0x15" \
    ": 0x16 :session resumed" \
    ": 0x18 :session resumed unasked" \
    ": 0x1A :session resumed unasked" \
    ": 0x1C :session resumed" \
    ": 0x1E :session resumed, also new ticket"

/* Flags for string_vformat */
#define SVFMT_EXTEND		BIT(0)
#define SVFMT_REBUFFER		BIT(1)
#define SVFMT_TAINT_NOCHK	BIT(2)


#define NOTIFIER_SOCKET_NAME	"exim_daemon_notify"
/* Notify message types */
#define NOTIFY_MSG_QRUN		1	/* 2stage qrun fast-ramp trigger */
#define NOTIFY_QUEUE_SIZE_REQ	2	/* obtain current queue count */
#define NOTIFY_REGEX		3	/* an RE for caching */

/* Flags for match_check_string() */
typedef unsigned mcs_flags;
#define MCS_NOFLAGS		0
#define MCS_PARTIAL		BIT(0)	/* permit partial- search types */
#define MCS_CASELESS		BIT(1)	/* caseless matching where possible */
#define MCS_AT_SPECIAL		BIT(2)	/* recognize @, @[], etc. */
#define MCS_CACHEABLE		BIT(3)	/* no dynamic expansions used for pattern */

/* Flags for open() */
#ifdef O_CLOEXEC
# define EXIM_CLOEXEC O_CLOEXEC
#else
# define EXIM_CLOEXEC 0
#endif
#ifdef O_NOFOLLOW
# define EXIM_NOFOLLOW O_NOFOLLOW
#else
# define EXIM_NOFOLLOW 0
#endif

/* A big number for (effectively) unlimited envelope addresses */
#define UNLIMITED_ADDRS		999999

/* Flags for queue_list() */
#define QL_BASIC		0
#define QL_UNDELIVERED_ONLY	1
#define QL_PLUS_GENERATED	2
#define QL_MSGID_ONLY		3
#define QL_UNSORTED		8

/* Flags for transport_set_up_command() */
#define TSUC_EXPAND_ARGS	BIT(0)
#define TSUC_ALLOW_TAINTED_ARGS	BIT(1)
#define TSUC_ALLOW_RECIPIENTS	BIT(2)

/* Flags for smtp_printf */
#define SP_MORE		TRUE
#define SP_NO_MORE	FALSE

/* Flags for smtp_respond */
#define SR_FINAL	TRUE
#define SR_NOT_FINAL	FALSE

/* Flags for continued-TLS-connection */
#define CTF_CV	BIT(0)
#define CTF_DV	BIT(1)
#define CTF_TR	BIT(2)

/* Return codes for smtp_write_mail_and_rcpt_cmds() */
typedef enum {
  sw_mrc_ok,	/* good, rcpt results in addr->transport_return (PENDING_OK, DEFER, FAIL) */
  sw_mrc_bad_mail,		/* MAIL response error */
  sw_mrc_bad_read,		/* any non-MAIL read i/o error */
  sw_mrc_nonmail_read_timeo,	/* non-MAIL response timeout */
  sw_mrc_bad_internal,		/* internal error; channel still usable */
  sw_mrc_tx_fail,		/* transmit failed */
} sw_mrc_t;

/* Recent versions of PCRE2 are allocating 20kB per match, rather than the previous 112 B.
When doing en extended loop of matching, release store periodically. */

#define	REGEX_LOOPCOUNT_STORE_RESET	1000

/* Debug an option access. Use for non-list ones about to be expanded
(lists have their own debugging, under D_list). */
#define GET_OPTION(name) \
  DEBUG(expand) debug_printf_indent("try option '" name "'\n");


#ifdef EXPERIMENTAL_SRV_SMTPS
/* Service name for the feature; used in DNS SRV RRs */
# define SRV_SMTPS_SERVICE_NAME	"smtp-tls"	/* Per version 5 draft */
#endif

/* Arg for smtp_fflush */
#define SFF_UNCORK	TRUE
#define SFF_NO_UNCORK	FALSE

/* Arg for wouldblock_reading */
#define WBR_DATA_OR_EOF	TRUE
#define WBR_DATA_ONLY	FALSE

/* Secondary-result bits for macros_expand() */
#define MACRO_FOUND	BIT(0)	/* At least one macro was found in the line */
#define MACRO_FIRST	BIT(1)	/* A macro was the first thing in the line */

#endif	/* whole file */
/* End of macros.h */
/* vi: aw ai sw=2
*/
