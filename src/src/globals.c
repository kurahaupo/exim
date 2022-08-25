/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* All the global variables are defined together in this one module, so
that they are easy to find. */

#include "exim.h"


/* Generic options for auths, all of which live inside auth_instance
data blocks and hence have the opt_public flag set. */

optionlist optionlist_auths[] = {
  { "client_condition", opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, client_condition) },
  { "client_set_id", opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, set_client_id) },
  { "driver",        opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, driver_name) },
  { "public_name",   opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, public_name) },
  { "server_advertise_condition", opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, advertise_condition)},
  { "server_condition", opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, server_condition) },
  { "server_debug_print", opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, server_debug_string) },
  { "server_mail_auth_condition", opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, mail_auth_condition) },
  { "server_set_id", opt_stringptr | opt_public,
                 OPT_OFF(auth_instance, set_id) }
};

int     optionlist_auths_size = nelem(optionlist_auths);

/* An empty host aliases list. */

cuschar *no_aliases             = NULL;


/* For comments on these variables, see globals.h. I'm too idle to
duplicate them here... */

#ifdef EXIM_PERL
cuschar *opt_perl_startup       = NULL;
BOOL    opt_perl_at_start      = FALSE;
BOOL    opt_perl_started       = FALSE;
BOOL    opt_perl_taintmode     = FALSE;
#endif

#ifdef EXPAND_DLFUNC
tree_node *dlobj_anchor        = NULL;
#endif

#ifdef LOOKUP_IBASE
cuschar *ibase_servers          = NULL;
#endif

#ifdef LOOKUP_LDAP
cuschar *eldap_ca_cert_dir      = NULL;
cuschar *eldap_ca_cert_file     = NULL;
cuschar *eldap_cert_file        = NULL;
cuschar *eldap_cert_key         = NULL;
cuschar *eldap_cipher_suite     = NULL;
cuschar *eldap_default_servers  = NULL;
cuschar *eldap_require_cert     = NULL;
int     eldap_version          = -1;
BOOL    eldap_start_tls        = FALSE;
#endif

#ifdef LOOKUP_MYSQL
cuschar *mysql_servers          = NULL;
#endif

#ifdef LOOKUP_ORACLE
cuschar *oracle_servers         = NULL;
#endif

#ifdef LOOKUP_PGSQL
cuschar *pgsql_servers          = NULL;
#endif

#ifdef LOOKUP_REDIS
cuschar *redis_servers          = NULL;
#endif

#ifdef LOOKUP_SQLITE
cuschar *sqlite_dbfile	       = NULL;
int     sqlite_lock_timeout    = 5;
#endif

#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
BOOL    move_frozen_messages   = FALSE;
#endif

/* These variables are outside the #ifdef because it keeps the code less
cluttered in several places (e.g. during logging) if we can always refer to
them. Also, the tls_ variables are now always visible.  Note that these are
only used for smtp connections, not for service-daemon access. */

tls_support tls_in = {
 .active =		{.sock = -1}
 /* all other elements zero */
};
tls_support tls_out = {
 .active =		{.sock = -1},
 /* all other elements zero */
};

cuschar *dsn_envid              = NULL;
int     dsn_ret                = 0;
const pcre2_code  *regex_DSN         = NULL;
cuschar *dsn_advertise_hosts    = NULL;

#ifndef DISABLE_TLS
BOOL    gnutls_compat_mode     = FALSE;
BOOL    gnutls_allow_auto_pkcs11 = FALSE;
cuschar *hosts_require_alpn     = NULL;
cuschar *openssl_options        = NULL;
const pcre2_code *regex_STARTTLS     = NULL;
cuschar *tls_advertise_hosts    = cUS("*");
cuschar *tls_alpn	       = cUS("smtp:esmtp");
cuschar *tls_certificate        = NULL;
cuschar *tls_crl                = NULL;
/* This default matches NSS DH_MAX_P_BITS value at current time (2012), because
that's the interop problem which has been observed: GnuTLS suggesting a higher
bit-count as "NORMAL" (2432) and Thunderbird dropping connection. */
int     tls_dh_max_bits        = 2236;
cuschar *tls_dhparam            = NULL;
cuschar *tls_eccurve            = cUS("auto");
# ifndef DISABLE_OCSP
cuschar *tls_ocsp_file          = NULL;
# endif
cuschar *tls_privatekey         = NULL;
BOOL    tls_remember_esmtp     = FALSE;
cuschar *tls_require_ciphers    = NULL;
# ifndef DISABLE_TLS_RESUME
cuschar *tls_resumption_hosts   = NULL;
# endif
cuschar *tls_try_verify_hosts   = NULL;
cuschar *tls_verify_certificates= cUS("system");
cuschar *tls_verify_hosts       = NULL;
int     tls_watch_fd	       = -1;
time_t  tls_watch_trigger_time = (time_t)0;
#else	/*DISABLE_TLS*/
cuschar *tls_advertise_hosts    = NULL;
#endif

#ifndef DISABLE_PRDR
/* Per Recipient Data Response variables */
BOOL    prdr_enable            = FALSE;
BOOL    prdr_requested         = FALSE;
const pcre2_code *regex_PRDR         = NULL;
#endif

#ifdef SUPPORT_I18N
const pcre2_code *regex_UTF8         = NULL;
#endif

/* Input-reading functions for messages, so we can use special ones for
incoming TCP/IP. The defaults use stdin. We never need these for any
stand-alone tests. */

#if !defined(STAND_ALONE) && !defined(MACRO_PREDEF)
int	(*lwr_receive_getc)(unsigned)	= stdin_getc;
cuschar * (*lwr_receive_getbuf)(unsigned *) = NULL;
int	(*lwr_receive_ungetc)(int)	= stdin_ungetc;
BOOL	(*lwr_receive_hasc)(void)	= stdin_hasc;

int	(*receive_getc)(unsigned) 	= stdin_getc;
cuschar * (*receive_getbuf)(unsigned *) 	= NULL;
void	(*receive_get_cache)(unsigned)	= NULL;
BOOL	(*receive_hasc)(void)		= stdin_hasc;
int	(*receive_ungetc)(int)    	= stdin_ungetc;
int	(*receive_feof)(void)     	= stdin_feof;
int	(*receive_ferror)(void)   	= stdin_ferror;
#endif


/* List of per-address expansion variables for clearing and saving/restoring
when verifying one address while routing/verifying another. We have to have
the size explicit, because it is referenced from more than one module. */

cuschar **address_expansions[ADDRESS_EXPANSIONS_COUNT] = {
  &deliver_address_data,
  &deliver_domain,
  &deliver_domain_data,
  &deliver_domain_orig,
  &deliver_domain_parent,
  &deliver_localpart,
  &deliver_localpart_data,
  &deliver_localpart_orig,
  &deliver_localpart_parent,
  &deliver_localpart_prefix,
  &deliver_localpart_suffix,
  (cuschar **) &deliver_recipients,
  &deliver_host,
  &deliver_home,
  &address_file,
  &address_pipe,
  &self_hostname,
  NULL };

int address_expansions_count = sizeof(address_expansions)/sizeof(uschar **);

/******************************************************************************/
/* General global variables.  Boolean flags are done as a group
so that only one bit each is needed, packed, for all those we never
need to take a pointer - and only a char for the rest.
This means a struct, unfortunately since it clutters the sourcecode. */

struct global_flags f =
{
	.acl_temp_details       = FALSE,
	.active_local_from_check = FALSE,
	.active_local_sender_retain = FALSE,
	.address_test_mode      = FALSE,
	.admin_user             = FALSE,
	.allow_auth_unadvertised= FALSE,
	.allow_unqualified_recipient = TRUE,    /* For local messages */
	.allow_unqualified_sender = TRUE,       /* Reset for SMTP */
	.authentication_local   = FALSE,

	.background_daemon      = TRUE,
	.bdat_readers_wanted    = FALSE,

	.chunking_offered       = FALSE,
	.config_changed         = FALSE,
	.continue_more          = FALSE,

	.daemon_listen          = FALSE,
	.daemon_scion           = FALSE,
	.debug_daemon           = FALSE,
	.deliver_firsttime      = FALSE,
	.deliver_force          = FALSE,
	.deliver_freeze         = FALSE,
	.deliver_force_thaw     = FALSE,
	.deliver_manual_thaw    = FALSE,
	.deliver_selectstring_regex = FALSE,
	.deliver_selectstring_sender_regex = FALSE,
	.disable_callout_flush  = FALSE,
	.disable_delay_flush    = FALSE,
	.disable_logging        = FALSE,
#ifndef DISABLE_DKIM
	.dkim_disable_verify      = FALSE,
	.dkim_init_done           = FALSE,
#endif
#ifdef SUPPORT_DMARC
	.dmarc_has_been_checked  = FALSE,
	.dmarc_disable_verify    = FALSE,
	.dmarc_enable_forensic   = FALSE,
#endif
	.dont_deliver           = FALSE,
	.dot_ends               = TRUE,

	.enable_dollar_recipients = FALSE,
	.expand_string_forcedfail = FALSE,

	.filter_running         = FALSE,

	.header_rewritten       = FALSE,
	.helo_verified          = FALSE,
	.helo_verify_failed     = FALSE,
	.host_checking_callout  = FALSE,
	.host_find_failed_syntax= FALSE,

	.inetd_wait_mode        = FALSE,
	.is_inetd               = FALSE,

	.local_error_message    = FALSE,
	.log_testing_mode       = FALSE,

#ifdef WITH_CONTENT_SCAN
	.no_mbox_unspool        = FALSE,
#endif
	.no_multiline_responses = FALSE,

	.parse_allow_group      = FALSE,
	.parse_found_group      = FALSE,
	.pipelining_enable      = TRUE,
#if defined(SUPPORT_PROXY) || defined(SUPPORT_SOCKS)
	.proxy_session_failed   = FALSE,
#endif

	.queue_2stage           = FALSE,
	.queue_only_policy      = FALSE,
	.queue_run_first_delivery = FALSE,
	.queue_run_force        = FALSE,
	.queue_run_local        = FALSE,
	.queue_running          = FALSE,
	.queue_smtp             = FALSE,

	.really_exim            = TRUE,
	.receive_call_bombout   = FALSE,
	.recipients_discarded   = FALSE,
	.running_in_test_harness = FALSE,

	.search_find_defer      = FALSE,
	.sender_address_forced  = FALSE,
	.sender_host_notsocket  = FALSE,
	.sender_host_unknown    = FALSE,
	.sender_local           = FALSE,
	.sender_name_forced     = FALSE,
	.sender_set_untrusted   = FALSE,
	.smtp_authenticated     = FALSE,
#ifndef DISABLE_PIPE_CONNECT
	.smtp_in_early_pipe_advertised = FALSE,
	.smtp_in_early_pipe_no_auth = FALSE,
	.smtp_in_early_pipe_used = FALSE,
#endif
	.smtp_in_pipelining_advertised = FALSE,
	.smtp_in_pipelining_used = FALSE,
	.smtp_in_quit		= FALSE,
	.spool_file_wireformat  = FALSE,
	.submission_mode        = FALSE,
	.suppress_local_fixups  = FALSE,
	.suppress_local_fixups_default = FALSE,
	.synchronous_delivery   = FALSE,
	.system_filtering       = FALSE,

	.taint_check_slow       = FALSE,
	.testsuite_delays	= TRUE,
	.tcp_fastopen_ok        = FALSE,
	.tcp_in_fastopen        = FALSE,
	.tcp_in_fastopen_data   = FALSE,
	.tcp_in_fastopen_logged = FALSE,
	.tcp_out_fastopen_logged= FALSE,
	.timestamps_utc         = FALSE,
	.transport_filter_timed_out = FALSE,
	.trusted_caller         = FALSE,
	.trusted_config         = TRUE,
};

/******************************************************************************/
/* These are the flags which are either variables or mainsection options,
so an address is needed for access, or are exported to local_scan. */

BOOL    accept_8bitmime        = TRUE; /* deliberately not RFC compliant */
BOOL    allow_domain_literals  = FALSE;
BOOL    allow_mx_to_ip         = FALSE;
BOOL    allow_utf8_domains     = FALSE;
BOOL    authentication_failed  = FALSE;

BOOL    bounce_return_body     = TRUE;
BOOL    bounce_return_message  = TRUE;
BOOL    check_rfc2047_length   = TRUE;
BOOL    commandline_checks_require_admin = FALSE;

#ifdef EXPERIMENTAL_DCC
BOOL    dcc_direct_add_header  = FALSE;
#endif
BOOL    debug_store            = FALSE;
BOOL    delivery_date_remove   = TRUE;
BOOL    deliver_drop_privilege = FALSE;
#ifdef ENABLE_DISABLE_FSYNC
BOOL    disable_fsync          = FALSE;
#endif
BOOL    disable_ipv6           = FALSE;
BOOL    dns_csa_use_reverse    = TRUE;
BOOL    drop_cr                = FALSE;         /* No longer used */

BOOL    envelope_to_remove     = TRUE;
BOOL    exim_gid_set           = TRUE;          /* This gid is always set */
BOOL    exim_uid_set           = TRUE;          /* This uid is always set */
BOOL    extract_addresses_remove_arguments = TRUE;

BOOL    host_checking          = FALSE;
BOOL    host_lookup_deferred   = FALSE;
BOOL    host_lookup_failed     = FALSE;
BOOL    ignore_fromline_local  = FALSE;

BOOL    local_from_check       = TRUE;
BOOL    local_sender_retain    = FALSE;
BOOL    log_timezone           = FALSE;
BOOL    message_body_newlines  = FALSE;
BOOL    message_logs           = TRUE;
#ifdef SUPPORT_I18N
BOOL    message_smtputf8       = FALSE;
#endif
BOOL    mua_wrapper            = FALSE;

BOOL    preserve_message_logs  = FALSE;
BOOL    print_topbitchars      = FALSE;
BOOL    prod_requires_admin    = TRUE;
#if defined(SUPPORT_PROXY) || defined(SUPPORT_SOCKS)
BOOL    proxy_session          = FALSE;
#endif

#ifndef DISABLE_QUEUE_RAMP
BOOL    queue_fast_ramp		= TRUE;
#endif
BOOL    queue_list_requires_admin = TRUE;
BOOL    queue_only             = FALSE;
BOOL    queue_only_load_latch  = TRUE;
BOOL    queue_only_override    = TRUE;
BOOL    queue_run_in_order     = FALSE;
BOOL    recipients_max_reject  = FALSE;
BOOL    return_path_remove     = TRUE;

BOOL    smtp_batched_input     = FALSE;
BOOL    sender_helo_dnssec     = FALSE;
BOOL    sender_host_dnssec     = FALSE;
BOOL    smtp_accept_keepalive  = TRUE;
BOOL    smtp_check_spool_space = TRUE;
BOOL    smtp_enforce_sync      = TRUE;
BOOL    smtp_etrn_serialize    = TRUE;
BOOL    smtp_input             = FALSE;
BOOL    smtp_return_error_details = FALSE;
#ifdef SUPPORT_SPF
BOOL    spf_result_guessed     = FALSE;
#endif
BOOL    split_spool_directory  = FALSE;
BOOL    spool_wireformat       = FALSE;
BOOL    strict_acl_vars        = FALSE;
BOOL    strip_excess_angle_brackets = FALSE;
BOOL    strip_trailing_dot     = FALSE;
BOOL    syslog_duplication     = TRUE;
BOOL    syslog_pid             = TRUE;
BOOL    syslog_timestamp       = TRUE;
BOOL    system_filter_gid_set  = FALSE;
BOOL    system_filter_uid_set  = FALSE;

BOOL    tcp_nodelay            = TRUE;
BOOL    write_rejectlog        = TRUE;

/******************************************************************************/

header_line *acl_added_headers = NULL;
tree_node *acl_anchor          = NULL;
cuschar *acl_arg[9]       = {NULL, NULL, NULL, NULL, NULL,
                                  NULL, NULL, NULL, NULL};
int     acl_narg               = 0;

int     acl_level	       = 0;

cuschar *acl_not_smtp          = NULL;
#ifdef WITH_CONTENT_SCAN
cuschar *acl_not_smtp_mime     = NULL;
#endif
cuschar *acl_not_smtp_start    = NULL;
cuschar *acl_removed_headers   = NULL;
cuschar *acl_smtp_auth         = NULL;
cuschar *acl_smtp_connect      = NULL;
cuschar *acl_smtp_data         = NULL;
#ifndef DISABLE_PRDR
cuschar *acl_smtp_data_prdr    = cUS("accept");
#endif
#ifndef DISABLE_DKIM
cuschar *acl_smtp_dkim         = NULL;
#endif
cuschar *acl_smtp_etrn         = NULL;
cuschar *acl_smtp_expn         = NULL;
cuschar *acl_smtp_helo         = NULL;
cuschar *acl_smtp_mail         = NULL;
cuschar *acl_smtp_mailauth     = NULL;
#ifdef WITH_CONTENT_SCAN
cuschar *acl_smtp_mime         = NULL;
#endif
cuschar *acl_smtp_notquit      = NULL;
cuschar *acl_smtp_predata      = NULL;
cuschar *acl_smtp_quit         = NULL;
cuschar *acl_smtp_rcpt         = NULL;
cuschar *acl_smtp_starttls     = NULL;
cuschar *acl_smtp_vrfy         = NULL;

tree_node *acl_var_c                = NULL;
tree_node *acl_var_m                = NULL;
cuschar *acl_verify_message    = NULL;
string_item *acl_warn_logged        = NULL;

/* Names of SMTP places for use in ACL error messages, and corresponding SMTP
error codes - keep in step with definitions of ACL_WHERE_xxxx in macros.h. */

cuschar *acl_wherenames[] = { cUS("RCPT"),
                                   cUS("MAIL"),
                                   cUS("PREDATA"),
                                   cUS("MIME"),
                                   cUS("DKIM"),
                                   cUS("DATA"),
#ifndef DISABLE_PRDR
                                   cUS("PRDR"),
#endif
                                   cUS("non-SMTP"),
                                   cUS("AUTH"),
                                   cUS("connection"),
                                   cUS("ETRN"),
                                   cUS("EXPN"),
                                   cUS("EHLO or HELO"),
                                   cUS("MAILAUTH"),
                                   cUS("non-SMTP-start"),
                                   cUS("NOTQUIT"),
                                   cUS("QUIT"),
                                   cUS("STARTTLS"),
                                   cUS("VRFY"),
				   cUS("delivery"),
				   cUS("unknown")
                                 };

cuschar *acl_wherecodes[] = { cUS("550"),     /* RCPT */
                                   cUS("550"),     /* MAIL */
                                   cUS("550"),     /* PREDATA */
                                   cUS("550"),     /* MIME */
                                   cUS("550"),     /* DKIM */
                                   cUS("550"),     /* DATA */
#ifndef DISABLE_PRDR
                                   cUS("550"),    /* RCPT PRDR */
#endif
                                   cUS("0"),       /* not SMTP; not relevant */
                                   cUS("503"),     /* AUTH */
                                   cUS("550"),     /* connect */
                                   cUS("458"),     /* ETRN */
                                   cUS("550"),     /* EXPN */
                                   cUS("550"),     /* HELO/EHLO */
                                   cUS("0"),       /* MAILAUTH; not relevant */
                                   cUS("0"),       /* not SMTP; not relevant */
                                   cUS("0"),       /* NOTQUIT; not relevant */
                                   cUS("0"),       /* QUIT; not relevant */
                                   cUS("550"),     /* STARTTLS */
                                   cUS("252"),     /* VRFY */
				   cUS("0"),       /* delivery; not relevant */
				   cUS("0")        /* unknown; not relevant */
                                 };

cuschar *add_environment        = NULL;
address_item  *addr_duplicate  = NULL;

address_item address_defaults = {
  .next =		NULL,
  .parent =		NULL,
  .first =		NULL,
  .dupof =		NULL,
  .start_router =	NULL,
  .router =		NULL,
  .transport =		NULL,
  .host_list =		NULL,
  .host_used =		NULL,
  .fallback_hosts =	NULL,
  .reply =		NULL,
  .retries =		NULL,
  .address =		NULL,
  .unique =		NULL,
  .cc_local_part =	NULL,
  .lc_local_part =	NULL,
  .local_part =		NULL,
  .prefix =		NULL,
  .prefix_v =		NULL,
  .suffix =		NULL,
  .suffix_v =		NULL,
  .domain =		NULL,
  .address_retry_key =	NULL,
  .domain_retry_key =	NULL,
  .current_dir =	NULL,
  .home_dir =		NULL,
  .message =		NULL,
  .user_message =	NULL,
  .onetime_parent =	NULL,
  .pipe_expandn =	NULL,
  .return_filename =	NULL,
  .self_hostname =	NULL,
  .shadow_message =	NULL,
#ifndef DISABLE_TLS
  .cipher =		NULL,
  .ourcert =		NULL,
  .peercert =		NULL,
  .peerdn =		NULL,
  .ocsp =		OCSP_NOT_REQ,
#endif
#ifdef EXPERIMENTAL_DSN_INFO
  .smtp_greeting =	NULL,
  .helo_response =	NULL,
#endif
  .authenticator =	NULL,
  .auth_id =		NULL,
  .auth_sndr =		NULL,
  .dsn_orcpt =		NULL,
  .dsn_flags =		0,
  .dsn_aware =		0,
  .uid =		(uid_t)(-1),
  .gid =		(gid_t)(-1),
  .flags =		{ 0 },
  .domain_cache =	{ 0 },                /* domain_cache - any larger array should be zeroed */
  .localpart_cache =	{ 0 },                /* localpart_cache - ditto */
  .mode =		-1,
  .more_errno =		0,
  .delivery_time =	{.tv_sec = 0, .tv_usec = 0},
  .basic_errno =	ERRNO_UNKNOWNERROR,
  .child_count =	0,
  .return_file =	-1,
  .special_action =	SPECIAL_NONE,
  .transport_return =	DEFER,
  .prop = {					/* fields that are propagated to children */
    .address_data =	NULL,
    .domain_data =	NULL,
    .localpart_data =	NULL,
    .errors_address =	NULL,
    .extra_headers =	NULL,
    .remove_headers =	NULL,
    .variables =	NULL,
    .ignore_error =	FALSE,
#ifdef SUPPORT_I18N
    .utf8_msg =		FALSE,
    .utf8_downcvt =	FALSE,
    .utf8_downcvt_maybe = FALSE
#endif
  }
};

cuschar *address_file           = NULL;
cuschar *address_pipe           = NULL;
tree_node *addresslist_anchor  = NULL;
int     addresslist_count      = 0;
gid_t  *admin_groups           = NULL;

#ifdef EXPERIMENTAL_ARC
struct arc_set *arc_received	= NULL;
int     arc_received_instance	= 0;
int     arc_oldest_pass		= 0;
cuschar *arc_state		= NULL;
cuschar *arc_state_reason	= NULL;
#endif

cuschar *authenticated_fail_id  = NULL;
cuschar *authenticated_id       = NULL;
cuschar *authenticated_sender   = NULL;
auth_instance  *auths          = NULL;
cuschar *auth_advertise_hosts   = cUS("*");
auth_instance auth_defaults    = {
    .next =		NULL,
    .name =		NULL,
    .info =		NULL,
    .options_block =	NULL,
    .driver_name =	NULL,
    .advertise_condition = NULL,
    .client_condition =	NULL,
    .public_name =	NULL,
    .set_id =		NULL,
    .set_client_id =	NULL,
    .mail_auth_condition = NULL,
    .server_debug_string = NULL,
    .server_condition =	NULL,
    .client =		FALSE,
    .server =		FALSE,
    .advertised =	FALSE
};

cuschar *auth_defer_msg   = cUS("reason not recorded");
cuschar *auth_defer_user_msg = cUS("");
cuschar *auth_vars[AUTH_VARS];
cuschar *authenticator_name = NULL;
int     auto_thaw              = 0;
#ifdef WITH_CONTENT_SCAN
int     av_failed              = FALSE;	/* boolean but accessed as vtype_int*/
cuschar *av_scanner       = cUS("sophie:/var/run/sophie");  /* AV scanner */
#endif

#if BASE_62 == 62
cuschar *base62_chars=
    cUS("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
#else
cuschar *base62_chars= cUS("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
#endif

cuschar *bi_command             = NULL;
cuschar *big_buffer             = NULL;
int     big_buffer_size        = BIG_BUFFER_SIZE;
#ifdef EXPERIMENTAL_BRIGHTMAIL
cuschar *bmi_alt_location       = NULL;
cuschar *bmi_base64_tracker_verdict = NULL;
cuschar *bmi_base64_verdict     = NULL;
cuschar *bmi_config_file        = cUS("/opt/brightmail/etc/brightmail.cfg");
int     bmi_deliver            = 1;
int     bmi_run                = 0;
cuschar *bmi_verdicts           = NULL;
#endif
int     bsmtp_transaction_linecount = 0;
int     body_8bitmime          = 0;
int     body_linecount         = 0;
int     body_zerocount         = 0;
cuschar *bounce_message_file    = NULL;
cuschar *bounce_message_text    = NULL;
cuschar *bounce_recipient       = NULL;
int     bounce_return_linesize_limit = 998;
int     bounce_return_size_limit = 100*1024;
cuschar *bounce_sender_authentication = NULL;

cuschar *callout_address        = NULL;
int     callout_cache_domain_positive_expire = 7*24*60*60;
int     callout_cache_domain_negative_expire = 3*60*60;
int     callout_cache_positive_expire = 24*60*60;
int     callout_cache_negative_expire = 2*60*60;
cuschar *callout_random_local_part = cUS("$primary_hostname-$tod_epoch-testing");
cuschar *check_dns_names_pattern= cUS("(?i)^(?>(?(1)\\.|())[^\\W](?>[a-z0-9/_-]*[^\\W])?)+(\\.?)$");
int     check_log_inodes       = 100;
int_eximarith_t check_log_space = 10*1024;	/* 10K Kbyte == 10MB */
int     check_spool_inodes     = 100;
int_eximarith_t check_spool_space = 10*1024;	/* 10K Kbyte == 10MB */

cuschar *chunking_advertise_hosts = cUS("*");
unsigned chunking_datasize     = 0;
unsigned chunking_data_left    = 0;
chunking_state_t chunking_state= CHUNKING_NOT_OFFERED;
const pcre2_code *regex_CHUNKING     = NULL;

#ifdef EXPERIMENTAL_ESMTP_LIMITS
const pcre2_code *regex_LIMITS        = NULL;
#endif

cuschar *client_authenticator   = NULL;
cuschar *client_authenticated_id = NULL;
cuschar *client_authenticated_sender = NULL;
#ifndef DISABLE_CLIENT_CMD_LOG
gstring *client_cmd_log        = NULL;
#endif
int     clmacro_count          = 0;
cuschar *clmacros[MAX_CLMACROS];
FILE   *config_file            = NULL;
cuschar *config_filename  = NULL;
int     config_lineno          = 0;
#ifdef CONFIGURE_GROUP
gid_t   config_gid             = CONFIGURE_GROUP;
#else
gid_t   config_gid             = 0;
#endif
cuschar *config_main_filelist   = cUS(CONFIGURE_FILE
                         "\0<-----------Space to patch configure_filename->");
cuschar *config_main_filename   = NULL;
cuschar *config_main_directory  = NULL;

#ifdef CONFIGURE_OWNER
uid_t   config_uid             = CONFIGURE_OWNER;
#else
uid_t   config_uid             = 0;
#endif

int     connection_max_messages= -1;
cuschar *continue_proxy_cipher  = NULL;
BOOL    continue_proxy_dane    = FALSE;
cuschar *continue_proxy_sni     = NULL;
cuschar *continue_hostname      = NULL;
cuschar *continue_host_address  = NULL;
int     continue_sequence      = 1;
cuschar *continue_transport     = NULL;
#ifdef EXPERIMENTAL_ESMTP_LIMITS
unsigned continue_limit_mail   = 0;
unsigned continue_limit_rcpt   = 0;
unsigned continue_limit_rcptdom= 0;
#endif

cuschar *csa_status             = NULL;
cut_t   cutthrough = {
  .callout_hold_only =	FALSE,				/* verify-only: normal delivery */
  .delivery =		FALSE,				/* when to attempt */
  .defer_pass =		FALSE,				/* on defer: spool locally */
  .is_tls =		FALSE,				/* not a TLS conn yet */
  .cctx =		{.sock = -1},			/* open connection */
  .nrcpt =		0,				/* number of addresses */
};

int	daemon_notifier_fd     = -1;
cuschar *daemon_smtp_port       = cUS("smtp");
int     daemon_startup_retries = 9;
int     daemon_startup_sleep   = 30;

#ifdef EXPERIMENTAL_DCC
cuschar *dcc_header             = NULL;
cuschar *dcc_result             = NULL;
cuschar *dccifd_address         = cUS("/usr/local/dcc/var/dccifd");
cuschar *dccifd_options         = cUS("header");
#endif

int     debug_fd               = -1;
FILE   *debug_file             = NULL;
int     debug_notall[]         = {
  Di_memory,
  Di_noutf8,
  -1
};
const bit_table debug_options[] = { /* must be in alphabetical order and use
				 only the enum values from macro.h */
  BIT_TABLE(D, acl),
  BIT_TABLE(D, all),
  BIT_TABLE(D, auth),
  BIT_TABLE(D, deliver),
  BIT_TABLE(D, dns),
  BIT_TABLE(D, dnsbl),
  BIT_TABLE(D, exec),
  BIT_TABLE(D, expand),
  BIT_TABLE(D, filter),
  BIT_TABLE(D, hints_lookup),
  BIT_TABLE(D, host_lookup),
  BIT_TABLE(D, ident),
  BIT_TABLE(D, interface),
  BIT_TABLE(D, lists),
  BIT_TABLE(D, load),
  BIT_TABLE(D, local_scan),
  BIT_TABLE(D, lookup),
  BIT_TABLE(D, memory),
  BIT_TABLE(D, noutf8),
  BIT_TABLE(D, pid),
  BIT_TABLE(D, process_info),
  BIT_TABLE(D, queue_run),
  BIT_TABLE(D, receive),
  BIT_TABLE(D, resolver),
  BIT_TABLE(D, retry),
  BIT_TABLE(D, rewrite),
  BIT_TABLE(D, route),
  BIT_TABLE(D, timestamp),
  BIT_TABLE(D, tls),
  BIT_TABLE(D, transport),
  BIT_TABLE(D, uid),
  BIT_TABLE(D, verify),
};
int      debug_options_count	= nelem(debug_options);
uschar   debuglog_name[LOG_NAME_SIZE] = {0};
unsigned debug_pretrigger_bsize	= 0;
cuschar * debug_pretrigger_buf	= NULL;
unsigned int debug_selector	= 0;

int     delay_warning[DELAY_WARNING_SIZE] = { DELAY_WARNING_SIZE, 1, 24*60*60 };
cuschar *delay_warning_condition=
  cUS("${if or {"
            "{ !eq{$h_list-id:$h_list-post:$h_list-subscribe:}{} }"
            "{ match{$h_precedence:}{(?i)bulk|list|junk} }"
            "{ match{$h_auto-submitted:}{(?i)auto-generated|auto-replied} }"
            "} {no}{yes}}");
cuschar *deliver_address_data   = NULL;
int     deliver_datafile       = -1;
cuschar *deliver_domain   = NULL;
cuschar *deliver_domain_data    = NULL;
cuschar *deliver_domain_orig = NULL;
cuschar *deliver_domain_parent = NULL;
time_t  deliver_frozen_at      = 0;
cuschar *deliver_home           = NULL;
cuschar *deliver_host     = NULL;
cuschar *deliver_host_address = NULL;
int     deliver_host_port      = 0;
cuschar *deliver_in_buffer      = NULL;
ino_t   deliver_inode          = 0;
cuschar *deliver_localpart      = NULL;
cuschar *deliver_localpart_data = NULL;
cuschar *deliver_localpart_orig = NULL;
cuschar *deliver_localpart_parent = NULL;
cuschar *deliver_localpart_prefix = NULL;
cuschar *deliver_localpart_prefix_v = NULL;
cuschar *deliver_localpart_suffix = NULL;
cuschar *deliver_localpart_suffix_v = NULL;
cuschar *deliver_out_buffer     = NULL;
int     deliver_queue_load_max = -1;
address_item  *deliver_recipients = NULL;
cuschar *deliver_selectstring   = NULL;
cuschar *deliver_selectstring_sender = NULL;

#ifndef DISABLE_DKIM
unsigned dkim_collect_input      = 0;
cuschar *dkim_cur_signer          = NULL;
int     dkim_key_length          = 0;
void   *dkim_signatures		 = NULL;
cuschar *dkim_signers             = NULL;
cuschar *dkim_signing_domain      = NULL;
cuschar *dkim_signing_selector    = NULL;
cuschar *dkim_verify_hashes       = cUS("sha256:sha512");
cuschar *dkim_verify_keytypes     = cUS("ed25519:rsa");
cuschar *dkim_verify_min_keysizes = cUS("rsa=1024 ed25519=250");
BOOL	dkim_verify_minimal      = FALSE;
cuschar *dkim_verify_overall      = NULL;
cuschar *dkim_verify_signers      = cUS("$dkim_signers");
cuschar *dkim_verify_status	 = NULL;
cuschar *dkim_verify_reason	 = NULL;
#endif
#ifdef SUPPORT_DMARC
cuschar *dmarc_domain_policy     = NULL;
cuschar *dmarc_forensic_sender   = NULL;
cuschar *dmarc_history_file      = NULL;
cuschar *dmarc_status            = NULL;
cuschar *dmarc_status_text       = NULL;
cuschar *dmarc_tld_file          = NULL;
cuschar *dmarc_used_domain       = NULL;
#endif

cuschar *dns_again_means_nonexist = NULL;
int     dns_csa_search_limit   = 5;
int	dns_cname_loops	       = 1;
#ifdef SUPPORT_DANE
int     dns_dane_ok            = -1;
#endif
cuschar *dns_ipv4_lookup        = NULL;
int     dns_retrans            = 0;
int     dns_retry              = 0;
int     dns_dnssec_ok          = -1; /* <0 = not coerced */
cuschar *dns_trust_aa           = NULL;
int     dns_use_edns0          = -1; /* <0 = not coerced */
cuschar *dnslist_domain         = NULL;
cuschar *dnslist_matched        = NULL;
cuschar *dnslist_text           = NULL;
cuschar *dnslist_value          = NULL;
tree_node *domainlist_anchor   = NULL;
int     domainlist_count       = 0;
cuschar *driver_srcfile   = NULL;
int     driver_srcline	       = 0;
cuschar *dsn_from               = cUS(DEFAULT_DSN_FROM);
unsigned int dtrigger_selector = 0;

int     errno_quota            = ERRNO_QUOTA;
cuschar *errors_copy            = NULL;
int     error_handling         = ERRORS_SENDER;
cuschar *errors_reply_to        = NULL;
int     errors_sender_rc       = EXIT_FAILURE;
#ifndef DISABLE_EVENT
cuschar *event_action             = NULL;	/* expansion for delivery events */
cuschar *event_data               = NULL;	/* auxiliary data variable for event */
int     event_defer_errno        = 0;
cuschar *event_name         = NULL;	/* event name variable */
#endif


gid_t   exim_gid               = EXIM_GID;
cuschar *exim_path              = cUS(BIN_DIRECTORY "/exim"
                        "\0<---------------Space to patch exim_path->");
uid_t   exim_uid               = EXIM_UID;
int     expand_level	       = 0;		/* Nesting depth, indent for debug */
int     expand_forbid          = 0;
int     expand_nlength[EXPAND_MAXN+1];
int     expand_nmax            = -1;
cuschar *expand_nstring[EXPAND_MAXN+1];
cuschar *expand_string_message;
cuschar *extra_local_interfaces = NULL;

int     fake_response          = OK;
cuschar *fake_response_text     = cUS("Your message has been rejected but is "
                                   "being kept for evaluation.\nIf it was a "
                                   "legitimate message, it may still be "
                                   "delivered to the target recipient(s).");
int     filter_n[FILTER_VARIABLE_COUNT];
int     filter_sn[FILTER_VARIABLE_COUNT];
int     filter_test            = FTEST_NONE;
cuschar *filter_test_sfile      = NULL;
cuschar *filter_test_ufile      = NULL;
cuschar *filter_thisaddress     = NULL;
int     finduser_retries       = 0;
uid_t   fixed_never_users[]    = { FIXED_NEVER_USERS };
cuschar *freeze_tell            = NULL;
cuschar *freeze_tell_config     = NULL;
cuschar *fudged_queue_times     = cUS("");

cuschar *gecos_name             = NULL;
cuschar *gecos_pattern          = NULL;
rewrite_rule  *global_rewrite_rules = NULL;

volatile sig_atomic_t had_command_timeout = 0;
volatile sig_atomic_t had_command_sigterm = 0;
volatile sig_atomic_t had_data_timeout    = 0;
volatile sig_atomic_t had_data_sigint     = 0;
cuschar *headers_charset  = cUS(HEADERS_CHARSET);
int     header_insert_maxlen   = 64 * 1024;
header_line  *header_last      = NULL;
header_line  *header_list      = NULL;
int     header_maxsize         = HEADER_MAXSIZE;
int     header_line_maxsize    = 0;

header_name header_names[] = {
  /* name		len	allow_resent	htype */
  { cUS("bcc"),            3,	TRUE,		htype_bcc },
  { cUS("cc"),             2,	TRUE,		htype_cc },
  { cUS("date"),           4,	TRUE,		htype_date },
  { cUS("delivery-date"), 13,	FALSE,		htype_delivery_date },
  { cUS("envelope-to"),   11,	FALSE,		htype_envelope_to },
  { cUS("from"),           4,	TRUE,		htype_from },
  { cUS("message-id"),    10,	TRUE,		htype_id },
  { cUS("received"),       8,	FALSE,		htype_received },
  { cUS("reply-to"),       8,	FALSE,		htype_reply_to },
  { cUS("return-path"),   11,	FALSE,		htype_return_path },
  { cUS("sender"),         6,	TRUE,		htype_sender },
  { cUS("subject"),        7,	FALSE,		htype_subject },
  { cUS("to"),             2,	TRUE,		htype_to }
};

int header_names_size          = nelem(header_names);

cuschar *helo_accept_junk_hosts = NULL;
cuschar *helo_allow_chars       = cUS("");
cuschar *helo_lookup_domains    = cUS("@ : @[]");
cuschar *helo_try_verify_hosts  = NULL;
cuschar *helo_verify_hosts      = NULL;
cuschar *hex_digits             = cUS("0123456789abcdef");
cuschar *hold_domains           = NULL;
cuschar *host_data              = NULL;
cuschar *host_lookup            = NULL;
cuschar *host_lookup_order      = cUS("bydns:byaddr");
cuschar *host_lookup_msg        = cUS("");
int     host_number                  = 0;
cuschar *host_number_string     = NULL;
cuschar *host_reject_connection = NULL;
tree_node *hostlist_anchor           = NULL;
int     hostlist_count               = 0;
cuschar *hosts_treat_as_local   = NULL;
cuschar *hosts_require_helo     = cUS("*");
cuschar *hosts_connection_nolog = NULL;

int     ignore_bounce_errors_after = 10*7*24*60*60;  /* 10 weeks */
cuschar *ignore_fromline_hosts  = NULL;
int     inetd_wait_timeout           = -1;
cuschar *initial_cwd            = NULL;
cuschar *interface_address      = NULL;
int     interface_port         = -1;
cuschar *iterate_item           = NULL;

int     journal_fd                   = -1;

cuschar *keep_environment       = NULL;

int     keep_malformed               = 4*24*60*60;    /* 4 days */

cuschar *eldap_dn               = NULL;
cuschar *letter_digit_hyphen_dot =
    cUS("abcdefghijklmnopqrstuvwxyz"
      ".-0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
#ifdef EXPERIMENTAL_ESMTP_LIMITS
cuschar *limits_advertise_hosts = cUS("*");
#endif
int     load_average           = -2;
cuschar *local_from_prefix      = NULL;
cuschar *local_from_suffix      = NULL;

#if HAVE_IPV6
cuschar *local_interfaces       = cUS("<; ::0 ; 0.0.0.0");
#else
cuschar *local_interfaces       = cUS("0.0.0.0");
#endif

#ifdef HAVE_LOCAL_SCAN
cuschar *local_scan_data        = NULL;
int     local_scan_timeout     = 5*60;
#endif
gid_t   local_user_gid         = (gid_t)(-1);
uid_t   local_user_uid         = (uid_t)(-1);

tree_node *localpartlist_anchor= NULL;
int     localpartlist_count    = 0;
cuschar *log_buffer             = NULL;

int     log_default[]          = { /* for initializing log_selector */
  Li_acl_warn_skipped,
  Li_connection_reject,
  Li_delay_delivery,
  Li_dkim,
  Li_dnslist_defer,
  Li_etrn,
  Li_host_lookup_failed,
  Li_lost_incoming_connection,
  Li_outgoing_interface, /* see d_log_interface in deliver.c */
  Li_msg_id,
  Li_queue_run,
  Li_queue_time_exclusive,
  Li_rejected_header,
  Li_retry_defer,
  Li_sender_verify_fail,
  Li_size_reject,
  Li_skip_delivery,
  Li_smtp_confirmation,
  Li_tls_certificate_verified,
  Li_tls_cipher,
  -1
};

cuschar *log_file_path          = cUS(LOG_FILE_PATH
                           "\0<--------------Space to patch log_file_path->");

int     log_notall[]           = {
  -1
};
bit_table log_options[]        = { /* must be in alphabetical order,
				with definitions from enum logbit. */
  BIT_TABLE(L, 8bitmime),
  BIT_TABLE(L, acl_warn_skipped),
  BIT_TABLE(L, address_rewrite),
  BIT_TABLE(L, all),
  BIT_TABLE(L, all_parents),
  BIT_TABLE(L, arguments),
  BIT_TABLE(L, connection_reject),
  BIT_TABLE(L, delay_delivery),
  BIT_TABLE(L, deliver_time),
  BIT_TABLE(L, delivery_size),
#ifndef DISABLE_DKIM
  BIT_TABLE(L, dkim),
  BIT_TABLE(L, dkim_verbose),
#endif
  BIT_TABLE(L, dnslist_defer),
  BIT_TABLE(L, dnssec),
  BIT_TABLE(L, etrn),
  BIT_TABLE(L, host_lookup_failed),
  BIT_TABLE(L, ident_timeout),
  BIT_TABLE(L, incoming_interface),
  BIT_TABLE(L, incoming_port),
  BIT_TABLE(L, lost_incoming_connection),
  BIT_TABLE(L, millisec),
  BIT_TABLE(L, msg_id),
  BIT_TABLE(L, msg_id_created),
  BIT_TABLE(L, outgoing_interface),
  BIT_TABLE(L, outgoing_port),
  BIT_TABLE(L, pid),
  BIT_TABLE(L, pipelining),
  BIT_TABLE(L, protocol_detail),
#if defined(SUPPORT_PROXY) || defined(SUPPORT_SOCKS)
  BIT_TABLE(L, proxy),
#endif
  BIT_TABLE(L, queue_run),
  BIT_TABLE(L, queue_time),
  BIT_TABLE(L, queue_time_exclusive),
  BIT_TABLE(L, queue_time_overall),
  BIT_TABLE(L, receive_time),
  BIT_TABLE(L, received_recipients),
  BIT_TABLE(L, received_sender),
  BIT_TABLE(L, rejected_header),
  { cUS("rejected_headers"), Li_rejected_header },
  BIT_TABLE(L, retry_defer),
  BIT_TABLE(L, return_path_on_delivery),
  BIT_TABLE(L, sender_on_delivery),
  BIT_TABLE(L, sender_verify_fail),
  BIT_TABLE(L, size_reject),
  BIT_TABLE(L, skip_delivery),
  BIT_TABLE(L, smtp_confirmation),
  BIT_TABLE(L, smtp_connection),
  BIT_TABLE(L, smtp_incomplete_transaction),
  BIT_TABLE(L, smtp_mailauth),
  BIT_TABLE(L, smtp_no_mail),
  BIT_TABLE(L, smtp_protocol_error),
  BIT_TABLE(L, smtp_syntax_error),
  BIT_TABLE(L, subject),
  BIT_TABLE(L, tls_certificate_verified),
  BIT_TABLE(L, tls_cipher),
  BIT_TABLE(L, tls_peerdn),
  BIT_TABLE(L, tls_resumption),
  BIT_TABLE(L, tls_sni),
  BIT_TABLE(L, unknown_in_list),
};
int     log_options_count            = nelem(log_options);

int     log_reject_target            = 0;
unsigned int log_selector[log_selector_size]; /* initialized in main() */
cuschar *log_selector_string    = NULL;
FILE   *log_stderr                   = NULL;
cuschar *login_sender_address   = NULL;
cuschar *lookup_dnssec_authenticated = NULL;
int     lookup_open_max              = 25;
cuschar *lookup_value           = NULL;

macro_item *macros_user              = NULL;
cuschar *mailstore_basename     = NULL;
#ifdef WITH_CONTENT_SCAN
cuschar *malware_name           = NULL;  /* Virus Name */
#endif
int     max_received_linelength      = 0;
int     max_username_length          = 0;
int     message_age                  = 0;
cuschar *message_body           = NULL;
cuschar *message_body_end       = NULL;
int     message_body_size            = 0;
int     message_body_visible         = 500;
int     message_ended                = END_NOTSTARTED;
cuschar *message_headers        = NULL;
cuschar *message_id;
cuschar *message_id_domain      = NULL;
cuschar *message_id_text        = NULL;
uschar message_id_option[MESSAGE_ID_LENGTH + 3];
cuschar *message_id_external;
int     message_linecount            = 0;
int     message_size                 = 0;
cuschar *message_size_limit     = cUS("50M");
#ifdef SUPPORT_I18N
int     message_utf8_downconvert = 0;	/* -1 ifneeded; 0 never; 1 always */
#endif
uschar message_subdir[2]      = { 0, 0 };
cuschar *message_reference      = NULL;

/* MIME ACL expandables */
#ifdef WITH_CONTENT_SCAN
int     mime_anomaly_level           = 0;
cuschar *mime_anomaly_text      = NULL;
cuschar *mime_boundary          = NULL;
cuschar *mime_charset           = NULL;
cuschar *mime_content_description = NULL;
cuschar *mime_content_disposition = NULL;
cuschar *mime_content_id        = NULL;
unsigned int mime_content_size       = 0;
cuschar *mime_content_transfer_encoding = NULL;
cuschar *mime_content_type      = NULL;
cuschar *mime_decoded_filename  = NULL;
cuschar *mime_filename          = NULL;
int     mime_is_multipart            = 0;
int     mime_is_coverletter          = 0;
int     mime_is_rfc822               = 0;
int     mime_part_count              = -1;
#endif

uid_t  *never_users                  = NULL;
cuschar *notifier_socket        = cUS("$spool_directory/" NOTIFIER_SOCKET_NAME) ;

const int on                         = 1;	/* for setsockopt */
const int off                        = 0;

uid_t   original_euid;
gid_t   originator_gid;
cuschar *originator_login       = NULL;
cuschar *originator_name        = NULL;
uid_t   originator_uid;
cuschar *override_local_interfaces = NULL;
cuschar *override_pid_file_path = NULL;

BOOL    panic_coredump	             = FALSE;
pcre2_general_context * pcre_gen_ctx = NULL;
pcre2_compile_context * pcre_gen_cmp_ctx = NULL;
pcre2_match_context * pcre_gen_mtc_ctx = NULL;
pcre2_general_context * pcre_mlc_ctx = NULL;
pcre2_compile_context * pcre_mlc_cmp_ctx = NULL;

cuschar *percent_hack_domains   = NULL;
cuschar *pid_file_path          = cUS(PID_FILE_PATH
                                           "\0<--------------Space to patch pid_file_path->");
#ifndef DISABLE_PIPE_CONNECT
cuschar *pipe_connect_advertise_hosts = cUS("*");
#endif
cuschar *pipelining_advertise_hosts = cUS("*");
cuschar *primary_hostname       = NULL;
cuschar *process_info;
int     process_info_len             = 0;
cuschar *process_log_path       = NULL;
cuschar *process_purpose        = cUS("fresh-exec");

#if defined(SUPPORT_PROXY) || defined(SUPPORT_SOCKS)
cuschar *hosts_proxy            = NULL;
cuschar *proxy_external_address = NULL;
int     proxy_external_port          = 0;
cuschar *proxy_local_address    = NULL;
int     proxy_local_port             = 0;
int     proxy_protocol_timeout       = 3;
#endif

cuschar *prvscheck_address      = NULL;
cuschar *prvscheck_keynum       = NULL;
cuschar *prvscheck_result       = NULL;


cuschar *qualify_domain_recipient = NULL;
cuschar *qualify_domain_sender  = NULL;
cuschar *queue_domains          = NULL;
int     queue_interval               = -1;
cuschar *queue_name             = cUS("");
cuschar *queue_name_dest        = NULL;
cuschar *queue_only_file        = NULL;
int     queue_only_load              = -1;
cuschar *queue_run_max          = cUS("5");
pid_t   queue_run_pid                = (pid_t)0;
int     queue_run_pipe               = -1;
unsigned queue_size                  = 0;
time_t  queue_size_next              = 0;
cuschar *queue_smtp_domains     = NULL;

uint32_t random_seed	             = 0;
tree_node *ratelimiters_cmd          = NULL;
tree_node *ratelimiters_conn         = NULL;
tree_node *ratelimiters_mail         = NULL;
cuschar *raw_active_hostname    = NULL;
cuschar *raw_sender             = NULL;
cuschar **raw_recipients        = NULL;
int     raw_recipients_count         = 0;

int     rcpt_count                   = 0;
int     rcpt_fail_count              = 0;
int     rcpt_defer_count             = 0;
gid_t   real_gid;
uid_t   real_uid;
int     receive_linecount            = 0;
int     receive_messagecount         = 0;
int     receive_timeout              = 0;
int     received_count               = 0;
cuschar *received_for           = NULL;

/*  This is the default text for Received headers generated by Exim. The
date  will be automatically added on the end. */

cuschar *received_header_text   = cUS(
     "Received: "
     "${if def:sender_rcvhost {from $sender_rcvhost\n\t}"
       "{${if def:sender_ident {from ${quote_local_part:$sender_ident} }}"
         "${if def:sender_helo_name {(helo=$sender_helo_name)\n\t}}}}"
     "by $primary_hostname "
     "${if def:received_protocol {with $received_protocol }}"
#ifndef DISABLE_TLS
     "${if def:tls_in_ver        { ($tls_in_ver)}}"
     "${if def:tls_in_cipher_std { tls $tls_in_cipher_std\n\t}}"
#endif
     "(Exim $version_number)\n\t"
     "${if def:sender_address {(envelope-from <$sender_address>)\n\t}}"
     "id $message_exim_id"
     "${if def:received_for {\n\tfor $received_for}}"
     "\0<---------------Space to patch received_header_text->");

int     received_headers_max         = 30;
cuschar *received_protocol      = NULL;
struct timeval received_time         = { 0, 0 };
struct timeval received_time_complete = { 0, 0 };
cuschar *recipient_data         = NULL;
cuschar *recipient_unqualified_hosts = NULL;
cuschar *recipient_verify_failure = NULL;
int     recipients_count             = 0;
recipient_item  *recipients_list = NULL;
int     recipients_list_max          = 0;
int     recipients_max               = 50000;
const pcre2_code *regex_AUTH         = NULL;
const pcre2_code *regex_check_dns_names = NULL;
const pcre2_code *regex_From         = NULL;
const pcre2_code *regex_IGNOREQUOTA  = NULL;
const pcre2_code *regex_PIPELINING   = NULL;
const pcre2_code *regex_SIZE         = NULL;
#ifndef DISABLE_PIPE_CONNECT
const pcre2_code *regex_EARLY_PIPE   = NULL;
#endif
int    regex_cachesize		     = 0;
const pcre2_code *regex_ismsgid      = NULL;
const pcre2_code *regex_smtp_code    = NULL;
cuschar *regex_vars[REGEX_VARS];
#ifdef WHITELIST_D_MACROS
const pcre2_code *regex_whitelisted_macro = NULL;
#endif
#ifdef WITH_CONTENT_SCAN
cuschar *regex_match_string     = NULL;
#endif
int     remote_delivery_count        = 0;
int     remote_max_parallel          = 4;
cuschar *remote_sort_domains    = NULL;
int     retry_data_expire            = 7*24*60*60;
int     retry_interval_max           = 24*60*60;
int     retry_maximum_timeout        = 0;        /* set from retry config */
retry_config  *retries               = NULL;
cuschar *return_path            = NULL;
int     rewrite_existflags           = 0;
cuschar *rfc1413_hosts          = cUS("@[]");
int     rfc1413_query_timeout        = 0;
uid_t   root_gid                     = ROOT_GID;
uid_t   root_uid                     = ROOT_UID;

router_instance  *routers  = NULL;
router_instance  router_defaults = {
    .next =			NULL,
    .name =			NULL,
    .info =			NULL,
    .options_block =		NULL,
    .driver_name =		NULL,

    .address_data =		NULL,
#ifdef EXPERIMENTAL_BRIGHTMAIL
    .bmi_rule =			NULL,
#endif
    .cannot_route_message =	NULL,
    .condition =		NULL,
    .current_directory =	NULL,
    .debug_string =		NULL,
    .domains =			NULL,
    .errors_to =		NULL,
    .expand_gid =		NULL,
    .expand_uid =		NULL,
    .expand_more =		NULL,
    .expand_unseen =		NULL,
    .extra_headers =		NULL,
    .fallback_hosts =		NULL,
    .home_directory =		NULL,
    .ignore_target_hosts =	NULL,
    .local_parts =		NULL,
    .pass_router_name =		NULL,
    .prefix =			NULL,
    .redirect_router_name =	NULL,
    .remove_headers =		NULL,
    .require_files =		NULL,
    .router_home_directory =	NULL,
    .self =			cUS("freeze"),
    .senders =			NULL,
    .suffix =			NULL,
    .translate_ip_address =	NULL,
    .transport_name =		NULL,

    .address_test =		TRUE,
#ifdef EXPERIMENTAL_BRIGHTMAIL
    .bmi_deliver_alternate =	FALSE,
    .bmi_deliver_default =	FALSE,
    .bmi_dont_deliver =		FALSE,
#endif
    .expn =			TRUE,
    .caseful_local_part =	FALSE,
    .check_local_user =		FALSE,
    .disable_logging =		FALSE,
    .fail_verify_recipient =	FALSE,
    .fail_verify_sender =	FALSE,
    .gid_set =			FALSE,
    .initgroups =		FALSE,
    .log_as_local =		TRUE_UNSET,
    .more =			TRUE,
    .pass_on_timeout =		FALSE,
    .prefix_optional =		FALSE,
    .repeat_use =		TRUE,
    .retry_use_local_part =	TRUE_UNSET,
    .same_domain_copy_routing =	FALSE,
    .self_rewrite =		FALSE,
    .set =			NULL,
    .suffix_optional =		FALSE,
    .verify_only =		FALSE,
    .verify_recipient =		TRUE,
    .verify_sender =		TRUE,
    .uid_set =			FALSE,
    .unseen =			FALSE,
    .dsn_lasthop =		FALSE,

    .self_code =		self_freeze,
    .uid =			(uid_t)(-1),
    .gid =			(gid_t)(-1),

    .fallback_hostlist =	NULL,
    .transport =		NULL,
    .pass_router =		NULL,
    .redirect_router =		NULL,

    .dnssec =                   { .request= cUS("*"), .require=NULL },
};

cuschar *router_name            = NULL;
tree_node *router_var	             = NULL;

ip_address_item *running_interfaces = NULL;

/* This is a weird one. The following string gets patched in the binary by the
script that sets up a copy of Exim for running in the test harness. It seems
that compilers are now clever, and share constant strings if they can.
Elsewhere in Exim the string "<" is used. The compiler optimization seems to
make use of the end of this string in order to save space. So the patching then
wrecks this. We defeat this optimization by adding some additional characters
onto the end of the string. */

cuschar *running_status         = cUS(">>>running<<<" "\0EXTRA");

int     runrc                        = 0;

cuschar *search_error_message   = NULL;
cuschar *self_hostname          = NULL;
cuschar *sender_address         = NULL;
unsigned int sender_address_cache[(MAX_NAMED_LIST * 2)/32];
cuschar *sender_address_data    = NULL;
cuschar *sender_address_unrewritten = NULL;
cuschar *sender_data            = NULL;
unsigned int sender_domain_cache[(MAX_NAMED_LIST * 2)/32];
cuschar *sender_fullhost        = NULL;
cuschar *sender_helo_name       = NULL;
cuschar **sender_host_aliases   = &no_aliases;
cuschar *sender_host_address    = NULL;
cuschar *sender_host_authenticated = NULL;
cuschar *sender_host_auth_pubname  = NULL;
unsigned int sender_host_cache[(MAX_NAMED_LIST * 2)/32];
cuschar *sender_host_name       = NULL;
int     sender_host_port             = 0;
cuschar *sender_ident           = NULL;
cuschar *sender_rate            = NULL;
cuschar *sender_rate_limit      = NULL;
cuschar *sender_rate_period     = NULL;
cuschar *sender_rcvhost         = NULL;
cuschar *sender_unqualified_hosts = NULL;
cuschar *sender_verify_failure = NULL;
address_item *sender_verified_list  = NULL;
address_item *sender_verified_failed = NULL;
int     sender_verified_rc           = -1;
cuschar *sending_ip_address     = NULL;
int     sending_port                 = -1;
SIGNAL_BOOL sigalrm_seen             = FALSE;
cuschar *sigalarm_setter        = NULL;
cuschar **sighup_argv           = NULL;
int     slow_lookup_log        = 0;	/* millisecs, zero disables */
int     smtp_accept_count      = 0;
int     smtp_accept_max        = 20;
int     smtp_accept_max_nonmail= 10;
cuschar *smtp_accept_max_nonmail_hosts = cUS("*");
cuschar *smtp_accept_max_per_connection = cUS("1000");
cuschar *smtp_accept_max_per_host = NULL;
int     smtp_accept_queue      = 0;
int     smtp_accept_queue_per_connection = 10;
int     smtp_accept_reserve    = 0;
cuschar *smtp_active_hostname   = NULL;
int	smtp_backlog_monitor   = 0;
cuschar *smtp_banner            = cUS("$smtp_active_hostname ESMTP "
                             "Exim $version_number $tod_full"
                             "\0<---------------Space to patch smtp_banner->");
int     smtp_ch_index          = 0;
cuschar *smtp_cmd_argument      = NULL;
cuschar *smtp_cmd_buffer        = NULL;
struct timeval smtp_connection_start  = {0,0};
uschar smtp_connection_had[SMTP_HBUFF_SIZE];
int     smtp_connect_backlog   = 20;
double  smtp_delay_mail        = 0.0;
double  smtp_delay_rcpt        = 0.0;
FILE   *smtp_in                = NULL;
int     smtp_listen_backlog    = 0;
int     smtp_load_reserve      = -1;
int     smtp_mailcmd_count     = 0;
int     smtp_mailcmd_max       = -1;
FILE   *smtp_out               = NULL;
cuschar *smtp_etrn_command      = NULL;
int     smtp_max_synprot_errors= 3;
int     smtp_max_unknown_commands = 3;
cuschar *smtp_notquit_reason    = NULL;
unsigned smtp_peer_options     = 0;
unsigned smtp_peer_options_wrap= 0;
cuschar *smtp_ratelimit_hosts   = NULL;
cuschar *smtp_ratelimit_mail    = NULL;
cuschar *smtp_ratelimit_rcpt    = NULL;
cuschar *smtp_read_error        = cUS("");
int     smtp_receive_timeout   = 5*60;
cuschar *smtp_receive_timeout_s = NULL;
cuschar *smtp_reserve_hosts     = NULL;
int     smtp_rlm_base          = 0;
double  smtp_rlm_factor        = 0.0;
int     smtp_rlm_limit         = 0;
int     smtp_rlm_threshold     = INT_MAX;
int     smtp_rlr_base          = 0;
double  smtp_rlr_factor        = 0.0;
int     smtp_rlr_limit         = 0;
int     smtp_rlr_threshold     = INT_MAX;
#ifdef SUPPORT_I18N
cuschar *smtputf8_advertise_hosts = cUS("*");	/* overridden under test-harness */
#endif

#ifdef WITH_CONTENT_SCAN
cuschar *spamd_address          = cUS("127.0.0.1 783");
cuschar *spam_bar               = NULL;
cuschar *spam_report            = NULL;
cuschar *spam_action            = NULL;
cuschar *spam_score             = NULL;
cuschar *spam_score_int         = NULL;
#endif
#ifdef SUPPORT_SPF
cuschar *spf_guess              = cUS("v=spf1 a/24 mx/24 ptr ?all");
cuschar *spf_header_comment     = NULL;
cuschar *spf_received           = NULL;
cuschar *spf_result             = NULL;
cuschar *spf_smtp_comment       = NULL;
cuschar *spf_smtp_comment_template = cUS("Please%_see%_http://www.open-spf.org/Why");
                    /* Used to be: "Please%_see%_http://www.open-spf.org/Why?id=%{S}&ip=%{C}&receiver=%{R}" */

#endif

FILE   *spool_data_file	       = NULL;
cuschar *spool_directory        = cUS(SPOOL_DIRECTORY
                           "\0<--------------Space to patch spool_directory->");
#ifdef SUPPORT_SRS
cuschar *srs_recipient          = NULL;
#endif
int     string_datestamp_offset= -1;
int     string_datestamp_length= 0;
int     string_datestamp_type  = -1;
cuschar *submission_domain = NULL;
cuschar *submission_name  = NULL;
int     syslog_facility        = LOG_MAIL;
cuschar *syslog_processname     = cUS("exim");
cuschar *system_filter          = NULL;

cuschar *system_filter_directory_transport = NULL;
cuschar *system_filter_file_transport = NULL;
cuschar *system_filter_pipe_transport = NULL;
cuschar *system_filter_reply_transport = NULL;

gid_t   system_filter_gid      = 0;
uid_t   system_filter_uid      = (uid_t)-1;

blob	tcp_fastopen_nodata    = { .data = NULL, .len = 0 };
tfo_state_t tcp_out_fastopen   = TFO_NOT_USED;
#ifdef USE_TCP_WRAPPERS
cuschar *tcp_wrappers_daemon_name = cUS(TCP_WRAPPERS_DAEMON_NAME);
#endif
int     test_harness_load_avg  = 0;
int     thismessage_size_limit = 0;
int     timeout_frozen_after   = 0;
#ifdef MEASURE_TIMING
struct timeval timestamp_startup;
#endif

transport_instance  *transports = NULL;

transport_instance  transport_defaults = {
    /* All non-mentioned elements zero/NULL/FALSE */
    .batch_max =		1,
    .multi_domain =		TRUE,
    .max_addresses =		100,
    .connection_max_messages =	500,
    .uid =			(uid_t)(-1),
    .gid =			(gid_t)(-1),
    .filter_timeout =		300,
    .retry_use_local_part =	TRUE_UNSET,	/* retry_use_local_part: BOOL, but set neither
						 1 nor 0 so can detect unset */
};

int     transport_count;
cuschar *transport_name          = NULL;
int     transport_newlines;
cuschar **transport_filter_argv  = NULL;
int     transport_filter_timeout;
int     transport_write_timeout= 0;

tree_node  *tree_dns_fails     = NULL;
tree_node  *tree_duplicates    = NULL;
tree_node  *tree_nonrecipients = NULL;
tree_node  *tree_unusable      = NULL;

gid_t  *trusted_groups         = NULL;
uid_t  *trusted_users          = NULL;
cuschar *timezone_string        = cUS(TIMEZONE_DEFAULT);

cuschar *unknown_login          = NULL;
cuschar *unknown_username       = NULL;
cuschar *untrusted_set_sender   = NULL;

/*  A regex for matching a "From_" line in an incoming message, in the form

    From ph10 Fri Jan  5 12:35 GMT 1996

which  the "mail" commands send to the MTA (undocumented, of course), or in
the  form

    From ph10 Fri, 7 Jan 97 14:00:00 GMT

which  is apparently used by some UUCPs, despite it not being in RFC 976.
Because  of variations in time formats, just match up to the minutes. That
should  be sufficient. Examples have been seen of time fields like 12:1:03,
so  just require one digit for hours and minutes. The weekday is also absent
in  some forms. */

cuschar *uucp_from_pattern      = cUS(
   "^From\\s+(\\S+)\\s+(?:[a-zA-Z]{3},?\\s+)?"    /* Common start */
   "(?:"                                          /* Non-extracting bracket */
   "[a-zA-Z]{3}\\s+\\d?\\d|"                      /* First form */
   "\\d?\\d\\s+[a-zA-Z]{3}\\s+\\d\\d(?:\\d\\d)?"  /* Second form */
   ")"                                            /* End alternation */
   "\\s+\\d\\d?:\\d\\d?");                        /* Start of time */

cuschar *uucp_from_sender       = cUS("$1");

cuschar *verify_mode	       = NULL;
cuschar *version_copyright      =
 cUS("Copyright (c) University of Cambridge, 1995 - 2018\n"
     "(c) The Exim Maintainers and contributors in ACKNOWLEDGMENTS file, 2007 - 2022");
cuschar *version_date           = cUS("?");
cuschar *version_cnumber        = cUS("????");
cuschar *version_string         = cUS("?");

cuschar *warn_message_file      = NULL;
int     warning_count          = 0;
cuschar *warnmsg_delay          = NULL;
cuschar *warnmsg_recipients     = NULL;


/*  End of globals.c */
