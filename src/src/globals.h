/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2022 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Almost all the global variables are defined together in this one header, so
that they are easy to find. However, those that are visible during the
compilation of the local_scan() function are defined separately in the
local_scan.h header file. */

/* First put any specials that are required for some operating systems. */

#ifdef NEED_H_ERRNO
extern int h_errno;
#endif

/* We need to be careful about width of int and atomicity in signal handlers,
especially with the rise of 64-bit systems breaking older assumptions.  But
sig_atomic_t comes from signal.h so can't go into mytypes.h without including
signal support in local_scan, which seems precipitous. */
typedef volatile sig_atomic_t SIGNAL_BOOL;

/* Now things that are present only when configured. */

#ifdef EXIM_PERL
extern cuschar *opt_perl_startup;       /* Startup code for Perl interpreter */
extern BOOL    opt_perl_at_start;       /* Start Perl interpreter at start */
extern BOOL    opt_perl_started;        /* Set once interpreter started */
extern BOOL    opt_perl_taintmode;      /* Enable taint mode in Perl */
#endif

#ifdef EXPAND_DLFUNC
extern tree_node *dlobj_anchor;         /* Tree of dynamically-loaded objects */
#endif

#ifdef LOOKUP_IBASE
extern cuschar *ibase_servers;
#endif

#ifdef LOOKUP_LDAP
extern cuschar *eldap_ca_cert_dir;      /* Directory with CA certificates */
extern cuschar *eldap_ca_cert_file;     /* CA certificate file */
extern cuschar *eldap_cert_file;        /* Certificate file */
extern cuschar *eldap_cert_key;         /* Certificate key file */
extern cuschar *eldap_cipher_suite;     /* Allowed cipher suite */
extern cuschar *eldap_default_servers;  /* List of default servers */
extern cuschar *eldap_require_cert;     /* Peer certificate checking strategy */
extern BOOL    eldap_start_tls;         /* Use STARTTLS */
extern int     eldap_version;           /* LDAP version */
#endif

#ifdef LOOKUP_MYSQL
extern cuschar *mysql_servers;          /* List of servers and connect info */
#endif

#ifdef LOOKUP_ORACLE
extern cuschar *oracle_servers;         /* List of servers and connect info */
#endif

#ifdef LOOKUP_PGSQL
extern cuschar *pgsql_servers;          /* List of servers and connect info */
#endif

#ifdef LOOKUP_REDIS
extern cuschar *redis_servers;          /* List of servers and connect info */
#endif

#ifdef LOOKUP_SQLITE
extern cuschar *sqlite_dbfile;          /* Filname for database */
extern int     sqlite_lock_timeout;     /* Internal lock waiting timeout */
#endif

#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
extern BOOL    move_frozen_messages;    /* Get them out of the normal directory */
#endif

/* These variables are outside the #ifdef because it keeps the code less
cluttered in several places (e.g. during logging) if we can always refer to
them. Also, the tls_ variables are now always visible. */

typedef struct {
  client_conn_ctx active;               /* fd/socket when in a TLS session, and ptr to TLS context */
  int     bits;                         /* bits used in TLS session */
  BOOL    certificate_verified;         /* Client certificate verified */
#ifdef SUPPORT_DANE
  BOOL    dane_verified;                /* ... via DANE */
  int     tlsa_usage;                   /* TLSA record(s) usage */
#endif
  cuschar *cipher;                      /* Cipher used */
  cuschar *cipher_stdname;              /* Cipher used, RFC version */
  cuschar *ver;                         /* TLS version */

  BOOL    on_connect;                   /* For older MTAs that don't STARTTLS */
  uschar *on_connect_ports;             /* Ports always tls-on-connect */
  void   *ourcert;                      /* Certificate we presented, binary */
  void   *peercert;                     /* Certificate of peer, binary */
  cuschar *peerdn;                      /* DN from peer */
  cuschar *sni;                         /* Server Name Indication */
  cuschar *channelbinding;              /* b64'd data identifying channel, for authenticators */
  enum {
    OCSP_NOT_REQ=0,                     /* not requested */
    OCSP_NOT_RESP,                      /* no response to request */
    OCSP_VFY_NOT_TRIED,                 /* response not verified */
    OCSP_FAILED,                        /* verify failed */
    OCSP_VFIED                          /* verified */
    }     ocsp;                         /* Stapled OCSP status */
#ifndef DISABLE_TLS_RESUME
  hctx    resume_hctx;                  /* session lookup key accumulation */
  cuschar * resume_index;               /* session lookup key */

  unsigned resumption;                  /* Session resumption */
  BOOL    host_resumable:1;
  BOOL    ticket_received:1;
#endif
  BOOL    verify_override:1;            /* certificate_verified only due to tls_try_verify_hosts */
  BOOL    ext_master_secret:1;          /* extended-master-secret was used */
  BOOL    channelbind_exporter:1;       /* channelbinding is EXPORTER not UNIQUE */
} tls_support;
extern tls_support tls_in;
extern tls_support tls_out;

#ifndef DISABLE_TLS
extern BOOL    gnutls_compat_mode;      /* Less security, more compatibility */
extern BOOL    gnutls_allow_auto_pkcs11; /* Let GnuTLS autoload PKCS11 modules */
extern cuschar *hosts_require_alpn;     /* Mandatory ALPN successful nogitiation */
extern cuschar *openssl_options;        /* OpenSSL compatibility options */
extern const pcre2_code *regex_STARTTLS; /* For recognizing STARTTLS settings */
extern cuschar *tls_alpn;               /* ALPN names acceptable */
extern cuschar *tls_certificate;        /* Certificate file */
extern cuschar *tls_crl;                /* CRL File */
extern int     tls_dh_max_bits;         /* don't accept higher lib suggestions */
extern cuschar *tls_dhparam;            /* DH param file */
extern cuschar *tls_eccurve;            /* EC curve */
# ifndef DISABLE_OCSP
extern cuschar *tls_ocsp_file;          /* OCSP stapling proof file */
# endif
extern cuschar *tls_privatekey;         /* Private key file */
extern BOOL    tls_remember_esmtp;      /* For YAEB */
extern cuschar *tls_require_ciphers;    /* So some can be avoided */
# ifndef DISABLE_TLS_RESUME
extern cuschar *tls_resumption_hosts;   /* TLS session resumption */
# endif
extern cuschar *tls_try_verify_hosts;   /* Optional client verification */
extern cuschar *tls_verify_certificates; /* Path for certificates to check */
extern cuschar *tls_verify_hosts;       /* Mandatory client verification */
extern int     tls_watch_fd;            /* for inotify of creds files */
extern time_t  tls_watch_trigger_time;  /* non-0: triggered */
#endif
extern cuschar *tls_advertise_hosts;    /* host for which TLS is advertised */

extern cuschar  *dsn_envid;             /* DSN envid string */
extern int      dsn_ret;                /* DSN ret type*/
extern const pcre2_code *regex_DSN;     /* For recognizing DSN settings */
extern cuschar  *dsn_advertise_hosts;   /* host for which TLS is advertised */

/* Input-reading functions for messages, so we can use special ones for
incoming TCP/IP. */

extern int   (*lwr_receive_getc)(unsigned);
extern uschar *(*lwr_receive_getbuf)(unsigned *);
extern BOOL  (*lwr_receive_hasc)(void);
extern int   (*lwr_receive_ungetc)(int);

extern int (*receive_getc)(unsigned);
extern uschar * (*receive_getbuf)(unsigned *);
extern BOOL  (*receive_hasc)(void);
extern void  (*receive_get_cache)(unsigned);
extern int   (*receive_ungetc)(int);
extern int   (*receive_feof)(void);
extern int   (*receive_ferror)(void);


/* For clearing, saving, restoring address expansion variables. We have to have
the size of this vector set explicitly, because it is referenced from more than
one module. */

extern cuschar **address_expansions[ADDRESS_EXPANSIONS_COUNT];

/* Flags for which we don't need an address ever so can use a bitfield */

extern struct global_flags {
 BOOL   acl_temp_details                :1; /* TRUE to give details for 4xx error */
 BOOL   active_local_from_check         :1; /* For adding Sender: (switchable) */
 BOOL   active_local_sender_retain      :1; /* For keeping Sender: (switchable) */
 BOOL   address_test_mode               :1; /* True for -bt */
 BOOL   admin_user                      :1; /* True if caller can do admin */
 BOOL   allow_auth_unadvertised         :1; /* As it says */
 BOOL   allow_unqualified_recipient     :1; /* For local messages */ /* As it says */
 BOOL   allow_unqualified_sender        :1; /* Reset for SMTP */ /* Ditto */
 BOOL   authentication_local            :1; /* TRUE if non-smtp (implicit authentication) */

 BOOL   background_daemon               :1; /* Set FALSE to keep in foreground */
 BOOL   bdat_readers_wanted             :1; /* BDAT-handling to be pushed on readfunc stack */

 BOOL   chunking_offered                :1;
 BOOL   config_changed                  :1; /* True if -C used */
 BOOL   continue_more                   :1; /* Flag more addresses waiting */

 BOOL   daemon_listen                   :1; /* True if listening required */
 BOOL   daemon_scion                    :1; /* Ancestor proc is daemon, and not re-exec'd */
 BOOL   debug_daemon                    :1; /* Debug the daemon process only */
 BOOL   deliver_firsttime               :1; /* True for first delivery attempt */
 BOOL   deliver_force                   :1; /* TRUE if delivery was forced */
 BOOL   deliver_freeze                  :1; /* TRUE if delivery is frozen */
 BOOL   deliver_force_thaw              :1; /* TRUE to force thaw in queue run */
 BOOL   deliver_manual_thaw             :1; /* TRUE if manually thawed */
 BOOL   deliver_selectstring_regex      :1; /* String is regex */
 BOOL   deliver_selectstring_sender_regex :1; /* String is regex */
 BOOL   disable_callout_flush           :1; /* Don't flush before callouts */
 BOOL   disable_delay_flush             :1; /* Don't flush before "delay" in ACL */
 BOOL   disable_logging                 :1; /* Disables log writing when TRUE */
#ifndef DISABLE_DKIM
 BOOL   dkim_disable_verify             :1; /* Set via ACL control statement. When set, DKIM verification is disabled for the current message */
 BOOL   dkim_init_done                  :1; /* lazy-init status */
#endif
#ifdef SUPPORT_DMARC
 BOOL   dmarc_has_been_checked          :1; /* Global variable to check if test has been called yet */
 BOOL   dmarc_disable_verify            :1; /* Set via ACL control statement. When set, DMARC verification is disabled for the current message */
 BOOL   dmarc_enable_forensic           :1; /* Set via ACL control statement. When set, DMARC forensic reports are enabled for the current message */
#endif
 BOOL   dont_deliver                    :1; /* TRUE for -N option */
 BOOL   dot_ends                        :1; /* TRUE if "." ends non-SMTP input */

 BOOL   enable_dollar_recipients        :1; /* Make $recipients available */
 BOOL   expand_string_forcedfail        :1; /* TRUE if failure was "expected" */

 BOOL   filter_running                  :1; /* TRUE while running a filter */

 BOOL   header_rewritten                :1; /* TRUE if header changed by router */
 BOOL   helo_verified                   :1; /* True if HELO verified */
 BOOL   helo_verify_failed              :1; /* True if attempt failed */
 BOOL   host_checking_callout           :1; /* TRUE if real callout wanted */
 BOOL   host_find_failed_syntax         :1; /* DNS syntax check failure */

 BOOL   inetd_wait_mode                 :1; /* Whether running in inetd wait mode */
 BOOL   is_inetd                        :1; /* True for inetd calls */

 BOOL   local_error_message             :1; /* True if handling one of these */
 BOOL   log_testing_mode                :1; /* TRUE in various testing modes */

#ifdef WITH_CONTENT_SCAN
 BOOL   no_mbox_unspool                 :1; /* don't unlink files in /scan directory */
#endif
 BOOL   no_multiline_responses          :1; /* For broken clients */

 BOOL   parse_allow_group               :1; /* Allow group syntax */
 BOOL   parse_found_group               :1; /* In the middle of a group */
 BOOL   pipelining_enable               :1; /* As it says */
#if defined(SUPPORT_PROXY) || defined(SUPPORT_SOCKS)
 BOOL   proxy_session_failed            :1; /* TRUE if required proxy negotiation failed */
#endif

 BOOL   queue_2stage                    :1; /* Run queue in 2-stage manner */
 BOOL   queue_only_policy               :1; /* ACL or local_scan wants queue_only */
 BOOL   queue_run_first_delivery        :1; /* If TRUE, first deliveries only */
 BOOL   queue_run_force                 :1; /* TRUE to force during queue run */
 BOOL   queue_run_local                 :1; /* Local deliveries only in queue run */
 BOOL   queue_running                   :1; /* TRUE for queue running process and */
 BOOL   queue_smtp                      :1; /* Disable all immediate SMTP (-odqs)*/

 BOOL   really_exim                     :1; /* FALSE in utilities */
 BOOL   receive_call_bombout            :1; /* Flag for crashing log */
 BOOL   recipients_discarded            :1; /* By an ACL */
 BOOL   running_in_test_harness         :1; /*TRUE when running_status is patched */

 BOOL   search_find_defer               :1; /* Set TRUE if lookup deferred */
 BOOL   sender_address_forced           :1; /* Set by -f */
 BOOL   sender_host_notsocket           :1; /* Set for -bs and -bS */
 BOOL   sender_host_unknown             :1; /* TRUE for -bs and -bS except inetd */
 BOOL   sender_local                    :1; /* TRUE for local senders */
 BOOL   sender_name_forced              :1; /* Set by -F */
 BOOL   sender_set_untrusted            :1; /* Sender set by untrusted caller */
 BOOL   smtp_authenticated              :1; /* Sending client has authenticated */
#ifndef DISABLE_PIPE_CONNECT
 BOOL   smtp_in_early_pipe_advertised   :1; /* server advertised PIPECONNECT */
 BOOL   smtp_in_early_pipe_no_auth      :1; /* too many authenticator names */
 BOOL   smtp_in_early_pipe_used         :1; /* client did send early data */
#endif
 BOOL   smtp_in_pipelining_advertised   :1; /* server advertised PIPELINING */
 BOOL   smtp_in_pipelining_used         :1; /* server noted client using PIPELINING */
 BOOL   smtp_in_quit                    :1; /* server noted QUIT command */
 BOOL   spool_file_wireformat           :1; /* current -D file has CRLF rather than NL */
 BOOL   submission_mode                 :1; /* Can be forced from ACL */
 BOOL   suppress_local_fixups           :1; /* Can be forced from ACL */
 BOOL   suppress_local_fixups_default   :1; /* former is reset to this; override with -G */
 BOOL   synchronous_delivery            :1; /* TRUE if -odi is set */
 BOOL   system_filtering                :1; /* TRUE when running system filter */

 BOOL   taint_check_slow                :1; /* malloc/mmap are not returning distinct ranges */
 BOOL   testsuite_delays                :1; /* interprocess sequencing delays, under testsuite */
 BOOL   tcp_fastopen_ok                 :1; /* appears to be supported by kernel */
 BOOL   tcp_in_fastopen                 :1; /* conn usefully used fastopen */
 BOOL   tcp_in_fastopen_data            :1; /* fastopen carried data */
 BOOL   tcp_in_fastopen_logged          :1; /* one-time logging */
 BOOL   tcp_out_fastopen_logged         :1; /* one-time logging */
 BOOL   timestamps_utc                  :1; /* Use UTC for all times */
 BOOL   transport_filter_timed_out      :1; /* True if it did */
 BOOL   trusted_caller                  :1; /* Caller is trusted */
 BOOL   trusted_config                  :1; /* Configuration file is trusted */
} f;


/* General global variables */

extern BOOL     accept_8bitmime;        /* Allow *BITMIME incoming */
extern cuschar *add_environment;        /* List of environment variables to add */
extern header_line *acl_added_headers;  /* Headers added by an ACL */
extern tree_node *acl_anchor;           /* Tree of named ACLs */
extern cuschar *acl_arg[9];             /* Argument to ACL call */
extern int      acl_narg;               /* Number of arguments to ACL call */
extern int      acl_level;              /* Nesting depth and debug indent */
extern cuschar *acl_not_smtp;           /* ACL run for non-SMTP messages */
#ifdef WITH_CONTENT_SCAN
extern cuschar *acl_not_smtp_mime;      /* For MIME parts of ditto */
#endif
extern cuschar *acl_not_smtp_start;     /* ACL run at the beginning of a non-SMTP session */
extern cuschar *acl_removed_headers;    /* Headers deleted by an ACL */
extern cuschar *acl_smtp_auth;          /* ACL run for AUTH */
extern cuschar *acl_smtp_connect;       /* ACL run on SMTP connection */
extern cuschar *acl_smtp_data;          /* ACL run after DATA received */
#ifndef DISABLE_PRDR
extern cuschar *acl_smtp_data_prdr;     /* ACL run after DATA received if in PRDR mode*/
const extern pcre2_code *regex_PRDR;    /* For recognizing PRDR settings */
#endif
#ifndef DISABLE_DKIM
extern cuschar *acl_smtp_dkim;          /* ACL run for DKIM signatures / domains */
#endif
extern cuschar *acl_smtp_etrn;          /* ACL run for ETRN */
extern cuschar *acl_smtp_expn;          /* ACL run for EXPN */
extern cuschar *acl_smtp_helo;          /* ACL run for HELO/EHLO */
extern cuschar *acl_smtp_mail;          /* ACL run for MAIL */
extern cuschar *acl_smtp_mailauth;      /* ACL run for MAIL AUTH */
#ifdef WITH_CONTENT_SCAN
extern cuschar *acl_smtp_mime;          /* ACL run after DATA, before acl_smtp_data, for each MIME part */
#endif
extern cuschar *acl_smtp_notquit;       /* ACL run for disconnects */
extern cuschar *acl_smtp_predata;       /* ACL run for DATA command */
extern cuschar *acl_smtp_quit;          /* ACL run for QUIT */
extern cuschar *acl_smtp_rcpt;          /* ACL run for RCPT */
extern cuschar *acl_smtp_starttls;      /* ACL run for STARTTLS */
extern cuschar *acl_smtp_vrfy;          /* ACL run for VRFY */
extern tree_node *acl_var_c;            /* ACL connection variables */
extern tree_node *acl_var_m;            /* ACL message variables */
extern cuschar *acl_verify_message;     /* User message for verify failure */
extern string_item *acl_warn_logged;    /* Logged lines */
extern cuschar *acl_wherecodes[];       /* Response codes for ACL fails */
extern cuschar *acl_wherenames[];       /* Names for messages */
extern address_item *addr_duplicate;    /* Duplicate address list */
extern address_item address_defaults;   /* Default data for address item */
extern cuschar *address_file;           /* Name of file when delivering to one */
extern cuschar *address_pipe;           /* Pipe command when delivering to one */
extern tree_node *addresslist_anchor;   /* Tree of defined address lists */
extern int      addresslist_count;      /* Number defined */
extern gid_t  *admin_groups;            /* List of admin groups */
extern BOOL    allow_domain_literals;   /* As it says */
extern BOOL    allow_mx_to_ip;          /* Allow MX records to -> ip address */
#ifdef EXPERIMENTAL_ARC
extern struct arc_set *arc_received;    /* highest ARC instance evaluation struct */
extern int     arc_received_instance;   /* highest ARC instance number in headers */
extern int     arc_oldest_pass;         /* lowest passing instance number in headers */
extern cuschar *arc_state;              /* verification state */
extern cuschar *arc_state_reason;
#endif
extern BOOL    allow_utf8_domains;      /* For experimenting */
extern cuschar *authenticated_fail_id;  /* ID that failed authentication */
extern cuschar *authenticated_id;       /* ID that was authenticated */
extern cuschar *authenticated_sender;   /* From AUTH on MAIL */
extern BOOL    authentication_failed;   /* TRUE if AUTH was tried and failed */
extern cuschar *authenticator_name;     /* for debug and error messages */
extern cuschar *auth_advertise_hosts;   /* Only advertise to these */
extern auth_info auths_available[];     /* Vector of available auth mechanisms */
extern auth_instance *auths;            /* Chain of instantiated auths */
extern auth_instance auth_defaults;     /* Default values */
extern cuschar *auth_defer_msg;         /* Error message for log */
extern cuschar *auth_defer_user_msg;    /* Error message for user */
extern cuschar *auth_vars[];            /* $authn variables */
extern int     auto_thaw;               /* Auto-thaw interval */
#ifdef WITH_CONTENT_SCAN
extern int     av_failed;               /* TRUE if the AV process failed */
extern cuschar *av_scanner;             /* AntiVirus scanner to use for the malware condition */
#endif

extern cuschar *base62_chars;           /* Table of base-62 characters */
extern cuschar *bi_command;             /* Command for -bi option */
extern uschar  *big_buffer;             /* Used for various temp things */
extern int     big_buffer_size;         /* Current size (can expand) */
#ifdef EXPERIMENTAL_BRIGHTMAIL
extern cuschar *bmi_alt_location;       /* expansion variable that contains the alternate location for the rcpt (available during routing) */
extern cuschar *bmi_base64_tracker_verdict; /* expansion variable with base-64 encoded OLD verdict string (available during routing) */
extern cuschar *bmi_base64_verdict;     /* expansion variable with base-64 encoded verdict string (available during routing) */
extern cuschar *bmi_config_file;        /* Brightmail config file */
extern int     bmi_deliver;             /* Flag that determines if the message should be delivered to the rcpt (available during routing) */
extern int     bmi_run;                 /* Flag that determines if message should be run through Brightmail server */
extern cuschar *bmi_verdicts;           /* BASE64-encoded verdicts with recipient lists */
#endif
extern int     bsmtp_transaction_linecount; /* Start of last transaction */
extern int     body_8bitmime;           /* sender declared BODY= ; 7=7BIT, 8=8BITMIME */
extern cuschar *bounce_message_file;    /* Template file */
extern cuschar *bounce_message_text;    /* One-liner */
extern cuschar *bounce_recipient;       /* When writing an errmsg */
extern BOOL    bounce_return_body;      /* Include body in returned message */
extern int     bounce_return_linesize_limit; /* Max line length in return */
extern BOOL    bounce_return_message;   /* Include message in bounce */
extern int     bounce_return_size_limit; /* Max amount to return */
extern cuschar *bounce_sender_authentication; /* AUTH address for bounces */

extern cuschar *callout_address;        /* Address used for a malware/spamd/verify etc. callout */
extern int     callout_cache_domain_positive_expire; /* Time for positive domain callout cache records to expire */
extern int     callout_cache_domain_negative_expire; /* Time for negative domain callout cache records to expire */
extern int     callout_cache_positive_expire; /* Time for positive callout cache records to expire */
extern int     callout_cache_negative_expire; /* Time for negative callout cache records to expire */
extern cuschar *callout_random_local_part; /* Local part to be used to check if server called will accept any local part */
extern cuschar *check_dns_names_pattern;/* Regex for syntax check */
extern int     check_log_inodes;        /* Minimum for message acceptance */
extern int_eximarith_t check_log_space; /* Minimum for message acceptance */
extern BOOL    check_rfc2047_length;    /* Check RFC 2047 encoded string length */
extern int     check_spool_inodes;      /* Minimum for message acceptance */
extern int_eximarith_t check_spool_space; /* Minimum for message acceptance */
extern cuschar *chunking_advertise_hosts; /* RFC 3030 CHUNKING */
extern unsigned chunking_datasize;
extern unsigned chunking_data_left;
extern chunking_state_t chunking_state;
extern cuschar *client_authenticator;   /* Authenticator name used for smtp delivery */
extern cuschar *client_authenticated_id; /* "login" name used for SMTP AUTH */
extern cuschar *client_authenticated_sender; /* AUTH option to SMTP MAIL FROM (not yet used) */
#ifndef DISABLE_CLIENT_CMD_LOG
extern gstring *client_cmd_log;         /* debug log of client cmds & responses */
#endif
extern int     clmacro_count;           /* Number of command line macros */
extern cuschar *clmacros[];             /* Copy of them, for re-exec */
extern BOOL    commandline_checks_require_admin; /* belt and braces for insecure setups */
extern int     connection_max_messages; /* Max down one SMTP connection */
extern FILE   *config_file;             /* Configuration file */
extern cuschar *config_filename;        /* Configuration file name */
extern gid_t   config_gid;              /* Additional group owner */
extern int     config_lineno;           /* Line number */
extern cuschar *config_main_filelist;   /* List of possible config files */
extern cuschar *config_main_filename;   /* File name actually used */
extern cuschar *config_main_directory;  /* Directory where the main config file was found */
extern uid_t   config_uid;              /* Additional owner */
extern cuschar *continue_proxy_cipher;  /* TLS cipher for proxied continued delivery */
extern BOOL    continue_proxy_dane;     /* proxied conn is DANE */
extern cuschar *continue_proxy_sni;     /* proxied conn SNI */
extern cuschar *continue_hostname;      /* Host for continued delivery */
extern cuschar *continue_host_address;  /* IP address for ditto */
extern int     continue_sequence;       /* Sequence num for continued delivery */
extern cuschar *continue_transport;     /* Transport for continued delivery */
#ifdef EXPERIMENTAL_ESMTP_LIMITS
extern unsigned continue_limit_mail;    /* Peer advertised limit */
extern unsigned continue_limit_rcpt;
extern unsigned continue_limit_rcptdom;
#endif


extern cuschar *csa_status;             /* Client SMTP Authorization result */

typedef struct {
  unsigned     callout_hold_only:1;     /* Conn is only for verify callout */
  unsigned     delivery:1;              /* When to attempt */
  unsigned     defer_pass:1;            /* Pass 4xx to caller rather than spooling */
  unsigned     is_tls:1;                /* Conn has TLS active */
  client_conn_ctx cctx;                 /* Open connection */
  int          nrcpt;                   /* Count of addresses */
  uschar *     transport;               /* Name of transport */
  uschar *     interface;               /* (address of) */
  uschar *     snd_ip;                  /* sending_ip_address */
  int          snd_port;                /* sending_port */
  unsigned     peer_options;            /* smtp_peer_options */
  host_item    host;                    /* Host used */
  address_item addr;                    /* (Chain of) addresses */
} cut_t;
extern cut_t cutthrough;                /* Deliver-concurrently */

extern int     daemon_notifier_fd;      /* Unix socket for notifications */
extern cuschar *daemon_smtp_port;       /* Can be a list of ports */
extern int     daemon_startup_retries;  /* Number of times to retry */
extern int     daemon_startup_sleep;    /* Sleep between retries */

#ifdef EXPERIMENTAL_DCC
extern BOOL     dcc_direct_add_header;  /* directly add header */
extern cuschar *dcc_header;             /* dcc header */
extern cuschar *dcc_result;             /* dcc result */
extern cuschar *dccifd_address;         /* address of the dccifd daemon */
extern cuschar *dccifd_options;         /* options for the dccifd daemon */
#endif

extern int      debug_fd;               /* The fd for debug_file */
extern FILE    *debug_file;             /* Where to write debugging info */
extern int      debug_notall[];         /* Debug options excluded from +all */
extern const    bit_table debug_options[]; /* Table of debug options */
extern int     debug_options_count;     /* Size of table */
extern unsigned debug_pretrigger_bsize;
extern uschar *debug_pretrigger_buf;    /* circular buffer for precapture */
extern BOOL    debug_store;             /* Do extra checks on store_reset */
extern uschar  debuglog_name[LOG_NAME_SIZE]; /* ACL-init debug */

extern int     delay_warning[];         /* Times between warnings */
extern cuschar *delay_warning_condition; /* Condition string for warnings */
extern BOOL    delivery_date_remove;    /* Remove delivery-date headers */

extern cuschar *deliver_address_data;   /* Arbitrary data for an address */
extern int     deliver_datafile;        /* FD for data part of message */
extern cuschar *deliver_domain;         /* The local domain for delivery */
extern cuschar *deliver_domain_data;    /* From domain lookup */
extern cuschar *deliver_domain_orig;    /* The original local domain for delivery */
extern cuschar *deliver_domain_parent;  /* The parent domain for delivery */
extern BOOL    deliver_drop_privilege;  /* TRUE for unprivileged delivery */
extern time_t  deliver_frozen_at;       /* Time of freezing */
extern cuschar *deliver_home;           /* Home directory for pipes */
extern cuschar *deliver_host;           /* (First) host for routed local deliveries */
                                        /* Remote host for filter */
extern cuschar *deliver_host_address;   /* Address for remote delivery filter */
extern int     deliver_host_port;       /* Address for remote delivery filter */
extern cuschar *deliver_in_buffer;      /* Buffer for copying file */
extern ino_t   deliver_inode;           /* Inode for appendfile */
extern cuschar *deliver_localpart;      /* The local part for delivery */
extern cuschar *deliver_localpart_data; /* From local part lookup (de-tainted) */
extern cuschar *deliver_localpart_orig; /* The original local part for delivery */
extern cuschar *deliver_localpart_parent; /* The parent local part for delivery */
extern cuschar *deliver_localpart_prefix; /* The stripped prefix, if any */
extern cuschar *deliver_localpart_prefix_v; /* The stripped-prefix variable portion, if any */
extern cuschar *deliver_localpart_suffix; /* The stripped suffix, if any */
extern cuschar *deliver_localpart_suffix_v; /* The stripped-suffix variable portion, if any */
extern cuschar *deliver_out_buffer;     /* Buffer for copying file */
extern int     deliver_queue_load_max;  /* Different value for queue running */
extern address_item *deliver_recipients; /* Current set of addresses */
extern cuschar *deliver_selectstring;   /* For selecting by recipient */
extern cuschar *deliver_selectstring_sender; /* For selecting by sender */
#ifdef ENABLE_DISABLE_FSYNC
extern BOOL    disable_fsync;           /* Not for normal use */
#endif
extern BOOL    disable_ipv6;            /* Don't do any IPv6 things */

#ifndef DISABLE_DKIM
extern unsigned dkim_collect_input;     /* Runtime count of dkim signtures; tracks whether SMTP input is fed to DKIM validation */
extern cuschar *dkim_cur_signer;        /* Expansion variable, holds the current "signer" domain or identity during a acl_smtp_dkim run */
extern int     dkim_key_length;         /* Expansion variable, length of signing key in bits */
extern void   *dkim_signatures;         /* Actually a (pdkim_signature *) but most files do not need to know */
extern cuschar *dkim_signers;           /* Expansion variable, holds colon-separated list of domains and identities that have signed a message */
extern cuschar *dkim_signing_domain;    /* Expansion variable, domain used for signing a message. */
extern cuschar *dkim_signing_selector;  /* Expansion variable, selector used for signing a message. */
extern cuschar *dkim_verify_hashes;     /* Preference order for signatures */
extern cuschar *dkim_verify_keytypes;   /* Preference order for signatures */
extern cuschar *dkim_verify_min_keysizes; /* list of minimum key sizes, keyed by algo */
extern BOOL    dkim_verify_minimal;     /* Shortcircuit signture verification */
extern cuschar *dkim_verify_overall;    /* First successful domain verified, or null */
extern cuschar *dkim_verify_signers;    /* Colon-separated list of domains for each of which we call the DKIM ACL */
extern cuschar *dkim_verify_status;     /* result for this signature */
extern cuschar *dkim_verify_reason;     /* result for this signature */
#endif
#ifdef SUPPORT_DMARC
extern cuschar *dmarc_domain_policy;    /* Expansion for declared policy of used domain */
extern cuschar *dmarc_forensic_sender;  /* Set sender address for forensic reports */
extern cuschar *dmarc_history_file;     /* Expansion variable, file to store dmarc results */
extern cuschar *dmarc_status;           /* Expansion variable, one word value */
extern cuschar *dmarc_status_text;      /* Expansion variable, human readable value */
extern cuschar *dmarc_tld_file;         /* Mozilla TLDs text file */
extern cuschar *dmarc_used_domain;      /* Expansion variable, domain libopendmarc chose for DMARC policy lookup */
#endif

extern cuschar *dns_again_means_nonexist; /* Domains that are badly set up */
extern int     dns_csa_search_limit;    /* How deep to search for CSA SRV records */
extern BOOL    dns_csa_use_reverse;     /* Check CSA in reverse DNS? (non-standard) */
extern int     dns_cname_loops;         /* Follow CNAMEs returned by resolver to this depth */
extern cuschar *dns_ipv4_lookup;        /* For these domains, don't look for AAAA (or A6) */
#ifdef SUPPORT_DANE
extern int     dns_dane_ok;             /* Ok to use DANE when checking TLS authenticity */
#endif
extern int     dns_retrans;             /* Retransmission time setting */
extern int     dns_retry;               /* Number of retries */
extern int     dns_dnssec_ok;           /* When constructing DNS query, set DO flag */
extern cuschar * dns_rc_names[];        /* Mostly for debug output */
extern cuschar *dns_trust_aa;           /* DNSSEC trust AA as AD */
extern int     dns_use_edns0;           /* Coerce EDNS0 support on/off in resolver. */
extern cuschar *dnslist_domain;         /* DNS (black) list domain */
extern cuschar *dnslist_matched;        /* DNS (black) list matched key */
extern cuschar *dnslist_text;           /* DNS (black) list text message */
extern cuschar *dnslist_value;          /* DNS (black) list IP address */
extern tree_node *domainlist_anchor;    /* Tree of defined domain lists */
extern int     domainlist_count;        /* Number defined */

/* This option is now a no-opt, retained for compatibility */
extern BOOL    drop_cr;                 /* For broken local MUAs */
extern cuschar *driver_srcfile;         /* For debug & errors */
extern int     driver_srcline;          /* For debug & errors */

extern unsigned int dtrigger_selector;  /* when to start debug */

extern cuschar *dsn_from;               /* From: string for DSNs */

extern BOOL    envelope_to_remove;      /* Remove envelope_to_headers */
extern int     errno_quota;             /* Quota errno in this OS */
extern int     error_handling;          /* Error handling style */
extern cuschar *errors_copy;            /* For taking copies of errors */
extern cuschar *errors_reply_to;        /* Reply-to for error messages */
extern int     errors_sender_rc;        /* Return after message to sender*/

#ifndef DISABLE_EVENT
extern cuschar *event_action;           /* expansion for delivery events */
extern cuschar *event_data;             /* event data */
extern int     event_defer_errno;       /* error number set when a remote delivery is deferred with a host error */
extern cuschar *event_name;             /* event classification */
#endif

extern gid_t   exim_gid;                /* To be used with exim_uid */
extern BOOL    exim_gid_set;            /* TRUE if exim_gid set */
extern cuschar *exim_path;              /* Path to exec exim */
extern cuschar *exim_sieve_extension_list[]; /* list of sieve extensions */
extern uid_t   exim_uid;                /* Non-root uid for exim */
extern BOOL    exim_uid_set;            /* TRUE if exim_uid set */
extern int     expand_level;            /* Nesting depth; indent for debug */
extern int     expand_forbid;           /* RDO flags for forbidding things */
extern int     expand_nlength[];        /* Lengths of numbered strings */
extern int     expand_nmax;             /* Max numerical value */
extern cuschar *expand_nstring[];       /* Numbered strings */
extern BOOL    extract_addresses_remove_arguments; /* Controls -t behaviour */
extern cuschar *extra_local_interfaces; /* Local, non-listen interfaces */

extern int     fake_response;           /* Fake FAIL or DEFER response to data */
extern cuschar *fake_response_text;     /* User defined message for the above. Default is in globals.c. */
extern int     filter_n[FILTER_VARIABLE_COUNT]; /* filter variables */
extern int     filter_sn[FILTER_VARIABLE_COUNT]; /* variables set by system filter */
extern int     filter_test;             /* Filter test type */
extern cuschar *filter_test_sfile;      /* System filter test file */
extern cuschar *filter_test_ufile;      /* User filter test file */
extern cuschar *filter_thisaddress;     /* For address looping */
extern int     finduser_retries;        /* Retry count for getpwnam() */
extern uid_t   fixed_never_users[];     /* Can't be overridden */
extern cuschar *freeze_tell;            /* Message on (some) freezings */
extern cuschar *freeze_tell_config;     /* The configured setting */
extern cuschar *fudged_queue_times;     /* For use in test harness */

extern cuschar *gecos_name;             /* To be expanded when pattern matches */
extern cuschar *gecos_pattern;          /* Pattern to match */
extern rewrite_rule *global_rewrite_rules; /* Chain of rewriting rules */

extern volatile sig_atomic_t had_command_timeout; /* Alarm sighandler called */
extern volatile sig_atomic_t had_command_sigterm; /* TERM  sighandler called */
extern volatile sig_atomic_t had_data_timeout; /* Alarm sighandler called */
extern volatile sig_atomic_t had_data_sigint; /* TERM/INT  sighandler called */
extern int     header_insert_maxlen;    /* Max for inserting headers */
extern int     header_maxsize;          /* Max total length for header */
extern int     header_line_maxsize;     /* Max for an individual line */
extern header_name header_names[];      /* Table of header names */
extern int     header_names_size;       /* Number of entries */
extern cuschar *helo_accept_junk_hosts; /* Allowed to use junk arg */
extern cuschar *helo_allow_chars;       /* Rogue chars to allow in HELO/EHLO */
extern cuschar *helo_lookup_domains;    /* If these given, lookup host name */
extern cuschar *helo_try_verify_hosts;  /* Soft check HELO argument for these */
extern cuschar *helo_verify_hosts;      /* Hard check HELO argument for these */
extern cuschar *hex_digits;             /* Used in several places */
extern cuschar *hold_domains;           /* Hold up deliveries to these */
extern cuschar *host_data;              /* Obtained from lookup in ACL */
extern cuschar *host_lookup;            /* For which IP addresses are always looked up */
extern BOOL    host_lookup_deferred;    /* TRUE if lookup deferred */
extern BOOL    host_lookup_failed;      /* TRUE if lookup failed */
extern cuschar *host_lookup_order;      /* Order of host lookup types */
extern cuschar *host_lookup_msg;        /* Text for why it failed */
extern int     host_number;             /* For sharing spools */
extern cuschar *host_number_string;     /* For expanding */
extern cuschar *hosts_require_helo;     /* check for HELO/EHLO before MAIL */
extern cuschar *host_reject_connection; /* Reject these hosts */
extern tree_node *hostlist_anchor;      /* Tree of defined host lists */
extern int     hostlist_count;          /* Number defined */
extern cuschar *hosts_connection_nolog; /* Limits the logging option */
extern cuschar *hosts_treat_as_local;   /* For routing */

extern int     ignore_bounce_errors_after; /* Keep them for this time. */
extern BOOL    ignore_fromline_local;   /* Local SMTP ignore fromline */
extern cuschar *ignore_fromline_hosts;  /* Hosts permitted to send "From " */
extern int     inetd_wait_timeout;      /* Timeout for inetd wait mode */
extern cuschar *initial_cwd;            /* The directory we where in at startup */
extern cuschar *iterate_item;           /* Item from iterate list */

extern int     journal_fd;              /* Fd for journal file */

extern cuschar *keep_environment;       /* Whitelist for environment variables */
extern int     keep_malformed;          /* Time to keep malformed messages */

extern cuschar *eldap_dn;               /* Where LDAP DNs are left */
extern cuschar *letter_digit_hyphen_dot; /* Legitimate DNS host name chars */
#ifdef EXPERIMENTAL_ESMTP_LIMITS
extern cuschar *limits_advertise_hosts; /* for banner/EHLO pipelining */
#endif
extern int     load_average;            /* Most recently read load average */
extern BOOL    local_from_check;        /* For adding Sender: (global value) */
extern cuschar *local_from_prefix;      /* Permitted prefixes */
extern cuschar *local_from_suffix;      /* Permitted suffixes */
extern cuschar *local_interfaces;       /* For forcing specific interfaces */
#ifdef HAVE_LOCAL_SCAN
extern cuschar *local_scan_data;        /* Text returned by local_scan() */
extern optionlist local_scan_options[]; /* Option list for local_scan() */
extern int     local_scan_options_count; /* Size of the list */
extern int     local_scan_timeout;      /* Timeout for local_scan() */
#endif
extern BOOL    local_sender_retain;     /* Retain Sender: (with no From: check) */
extern gid_t   local_user_gid;          /* As it says; may be set in routers */
extern uid_t   local_user_uid;          /* As it says; may be set in routers */
extern tree_node *localpartlist_anchor; /* Tree of defined localpart lists */
extern int     localpartlist_count;     /* Number defined */
extern cuschar *log_buffer;             /* For constructing log entries */
extern int     log_default[];           /* Initialization list for log_selector */
extern cuschar *log_file_path;          /* If unset, use default */
extern int     log_notall[];            /* Log options excluded from +all */
extern bit_table log_options[];         /* Table of options */
extern int     log_options_count;       /* Size of table */
extern int     log_reject_target;       /* Target log for ACL rejections */
extern unsigned int log_selector[];     /* Bit map of logging options */
extern cuschar *log_selector_string;    /* As supplied in the config */
extern FILE   *log_stderr;              /* Copy of stderr for log use, or NULL */
extern BOOL    log_timezone;            /* TRUE to include the timezone in log lines */
extern cuschar *login_sender_address;   /* The actual sender address */
extern lookup_info **lookup_list;       /* Array of pointers to available lookups */
extern int     lookup_list_count;       /* Number of entries in the list */
extern cuschar *lookup_dnssec_authenticated; /* AD status of dns lookup */
extern int     lookup_open_max;         /* Max lookup files to cache */
extern cuschar *lookup_value;           /* Value looked up from file */

extern macro_item *macros;              /* Configuration macros */
extern macro_item *macros_user;         /* Non-builtin configuration macros */
extern macro_item *mlast;               /* Last item in macro list */
extern cuschar *mailstore_basename;     /* For mailstore deliveries */
#ifdef WITH_CONTENT_SCAN
extern cuschar *malware_name;           /* Name of virus or malware ("W32/Klez-H") */
#endif
extern int     max_received_linelength; /* What it says */
extern int     max_username_length;     /* For systems with broken getpwnam() */
extern int     message_age;             /* In seconds */
extern cuschar *message_body;           /* Start of message body for filter */
extern cuschar *message_body_end;       /* End of message body for filter */
extern BOOL    message_body_newlines;   /* FALSE => remove newlines */
extern int     message_body_size;       /* Sic */
extern int     message_body_visible;    /* Amount visible in message_body */
extern int     message_ended;           /* State of message reading and how ended */
extern cuschar *message_headers;        /* When built */
extern uschar  message_id_option[];     /* -E<message-id> for use as option */
extern cuschar *message_id_external;    /* External form of following */
extern cuschar *message_id_domain;      /* Expanded to form domain-part of message_id */
extern cuschar *message_id_text;        /* Expanded to form message_id */
extern int     message_linecount;       /* As it says */
extern BOOL    message_logs;            /* TRUE to write message logs */
extern int     message_size;            /* Size of message */
extern cuschar *message_size_limit;     /* As it says */
#ifdef SUPPORT_I18N
extern BOOL    message_smtputf8;        /* Internationalized mail handling */
extern int     message_utf8_downconvert; /* convert from utf8 */
const extern pcre2_code *regex_UTF8;    /* For recognizing SMTPUTF8 settings */
#endif
extern uschar  message_subdir[];        /* Subdirectory for messages */
extern cuschar *message_reference;      /* Reference for error messages */

/* MIME ACL expandables */
#ifdef WITH_CONTENT_SCAN
extern int     mime_anomaly_level;
extern cuschar *mime_anomaly_text;
extern cuschar *mime_boundary;
extern cuschar *mime_charset;
extern cuschar *mime_content_description;
extern cuschar *mime_content_disposition;
extern cuschar *mime_content_id;
extern unsigned int mime_content_size;
extern cuschar *mime_content_transfer_encoding;
extern cuschar *mime_content_type;
extern cuschar *mime_decoded_filename;
extern cuschar *mime_filename;
extern int     mime_is_multipart;
extern int     mime_is_coverletter;
extern int     mime_is_rfc822;
extern int     mime_part_count;
#endif

extern BOOL    mua_wrapper;             /* TRUE when Exim is wrapping an MUA */

extern uid_t  *never_users;             /* List of uids never to be used */
extern cuschar *notifier_socket;        /* Name for daemon notifier unix-socket */

extern const int on;                    /* For setsockopt */
extern const int off;

extern optionlist optionlist_auths[];   /* These option lists are made */
extern int     optionlist_auths_size;   /* global so that readconf can */
extern optionlist optionlist_routers[]; /* see them for printing out   */
extern int     optionlist_routers_size; /* the options.                */
extern optionlist optionlist_transports[];
extern int     optionlist_transports_size;

extern uid_t   original_euid;           /* Original effective uid */
extern gid_t   originator_gid;          /* Gid of whoever wrote spool file */
extern cuschar *originator_login;       /* Login of same */
extern cuschar *originator_name;        /* Full name of same */
extern uid_t   originator_uid;          /* Uid of ditto */
extern cuschar *override_local_interfaces; /* Value of -oX argument */
extern cuschar *override_pid_file_path; /* Value of -oP argument */

extern BOOL    panic_coredump;          /* SEGV rather than exit, on LOG_PANIC_DIE */
extern pcre2_general_context * pcre_gen_ctx; /* pcre memory management */
extern pcre2_compile_context * pcre_gen_cmp_ctx;
extern pcre2_match_context *   pcre_gen_mtc_ctx;
extern pcre2_general_context * pcre_mlc_ctx;
extern pcre2_compile_context * pcre_mlc_cmp_ctx;

extern cuschar *percent_hack_domains;   /* Local domains for which '% operates */
extern cuschar *pid_file_path;          /* For writing daemon pids */
#ifndef DISABLE_PIPE_CONNECT
extern cuschar *pipe_connect_advertise_hosts; /* for banner/EHLO pipelining */
#endif
extern cuschar *pipelining_advertise_hosts; /* As it says */
#ifndef DISABLE_PRDR
extern BOOL    prdr_enable;             /* As it says */
extern BOOL    prdr_requested;          /* Connecting mail server wants PRDR */
#endif
extern BOOL    preserve_message_logs;   /* Save msglog files */
extern cuschar *primary_hostname;       /* Primary name of this computer */
extern BOOL    print_topbitchars;       /* Topbit chars are printing chars */
extern cuschar *process_info;           /* For SIGUSR1 output */
extern int     process_info_len;
extern cuschar *process_log_path;       /* Alternate path */
extern cuschar *process_purpose;        /* for debug output */
extern BOOL    prod_requires_admin;     /* TRUE if prodding requires admin */

#if defined(SUPPORT_PROXY) || defined(SUPPORT_SOCKS)
extern cuschar *hosts_proxy;            /* Hostlist which (require) use proxy protocol */
extern cuschar *proxy_external_address; /* IP of remote interface of proxy */
extern int     proxy_external_port;     /* Port on remote interface of proxy */
extern cuschar *proxy_local_address;    /* IP of local interface of proxy */
extern int     proxy_local_port;        /* Port on local interface of proxy */
extern int     proxy_protocol_timeout;  /* Timeout for proxy negotiation */
extern BOOL    proxy_session;           /* TRUE if receiving mail from valid proxy  */
#endif

extern cuschar *prvscheck_address;      /* Set during prvscheck expansion item */
extern cuschar *prvscheck_keynum;       /* Set during prvscheck expansion item */
extern cuschar *prvscheck_result;       /* Set during prvscheck expansion item */

extern cuschar *qualify_domain_recipient; /* Domain to qualify recipients with */
extern cuschar *qualify_domain_sender;  /* Domain to qualify senders with */
extern cuschar *queue_domains;          /* Queue these domains */
#ifndef DISABLE_QUEUE_RAMP
extern BOOL    queue_fast_ramp;         /* 2-phase queue-run overlap */
#endif
extern BOOL    queue_list_requires_admin; /* TRUE if -bp requires admin */
                                        /*   immediate children */
extern pid_t   queue_run_pid;           /* PID of the queue running process or 0 */
extern int     queue_run_pipe;          /* Pipe for synchronizing */
extern int     queue_interval;          /* Queue running interval */
extern cuschar *queue_name;             /* Name of queue, if nondefault spooling */
extern cuschar *queue_name_dest;        /* Destination queue, for moving messages */
extern BOOL    queue_only;              /* TRUE to disable immediate delivery */
extern int     queue_only_load;         /* Max load before auto-queue */
extern BOOL    queue_only_load_latch;   /* Latch queue_only_load TRUE */
extern cuschar *queue_only_file;        /* Queue if file exists/not-exists */
extern BOOL    queue_only_override;     /* Allow override from command line */
extern BOOL    queue_run_in_order;      /* As opposed to random */
extern cuschar *queue_run_max;          /* Max queue runners */
extern unsigned queue_size;             /* items in queue */
extern time_t  queue_size_next;         /* next time to evaluate queue_size */
extern cuschar *queue_smtp_domains;     /* Ditto, for these domains */

extern unsigned int random_seed;        /* Seed for random numbers */
extern tree_node *ratelimiters_cmd;     /* Results of command ratelimit checks */
extern tree_node *ratelimiters_conn;    /* Results of connection ratelimit checks */
extern tree_node *ratelimiters_mail;    /* Results of per-mail ratelimit checks */
extern cuschar *raw_active_hostname;    /* Pre-expansion */
extern cuschar *raw_sender;             /* Before rewriting */
extern cuschar **raw_recipients;        /* Before rewriting */
extern int     raw_recipients_count;
extern cuschar * rc_names[];            /* Mostly for debug output */
extern int     rcpt_count;              /* Count of RCPT commands in a message */
extern int     rcpt_fail_count;         /* Those that got 5xx */
extern int     rcpt_defer_count;        /* Those that got 4xx */
extern gid_t   real_gid;                /* Real gid */
extern uid_t   real_uid;                /* Real user running program */
extern int     receive_linecount;       /* Mainly for BSMTP errors */
extern int     receive_messagecount;    /* Mainly for BSMTP errors */
extern int     receive_timeout;         /* For non-SMTP acceptance */
extern int     received_count;          /* Count of Received: headers */
extern cuschar *received_for;           /* For "for" field */
extern cuschar *received_header_text;   /* Definition of Received: header */
extern int     received_headers_max;    /* Max count of Received: headers */
extern struct timeval received_time;    /* Time the message started to be received */
extern struct timeval received_time_complete; /* Time the message completed reception */
extern cuschar *recipient_data;         /* lookup data for recipients */
extern cuschar *recipient_unqualified_hosts; /* Permitted unqualified recipients */
extern cuschar *recipient_verify_failure; /* What went wrong */
extern int     recipients_list_max;     /* Maximum number fitting in list */
extern int     recipients_max;          /* Max permitted */
extern BOOL    recipients_max_reject;   /* If TRUE, reject whole message */
extern const pcre2_code *regex_AUTH;    /* For recognizing AUTH settings */
extern const pcre2_code  *regex_check_dns_names; /* For DNS name checking */
extern const pcre2_code  *regex_From;   /* For recognizing "From_" lines */
extern const pcre2_code  *regex_CHUNKING; /* For recognizing CHUNKING (RFC 3030) */
extern const pcre2_code  *regex_IGNOREQUOTA; /* For recognizing IGNOREQUOTA (LMTP) */
#ifdef EXPERIMENTAL_ESMTP_LIMITS
extern const pcre2_code  *regex_LIMITS; /* For recognizing LIMITS */
#endif
extern const pcre2_code  *regex_PIPELINING; /* For recognizing PIPELINING */
extern const pcre2_code  *regex_SIZE;   /* For recognizing SIZE settings */
#ifndef DISABLE_PIPE_CONNECT
extern const pcre2_code  *regex_EARLY_PIPE; /* For recognizing PIPE_CONNCT */
#endif
extern int     regex_cachesize;         /* number of entries */
extern const pcre2_code  *regex_ismsgid; /* Compiled r.e. for message ID */
extern const pcre2_code  *regex_smtp_code; /* For recognizing SMTP codes */
extern cuschar *regex_vars[];           /* $regexN variables */
#ifdef WHITELIST_D_MACROS
extern const pcre2_code  *regex_whitelisted_macro; /* For -D macro values */
#endif
#ifdef WITH_CONTENT_SCAN
extern cuschar *regex_match_string;     /* regex that matched a line (regex ACL condition) */
#endif
extern int     remote_delivery_count;   /* Number of remote addresses */
extern int     remote_max_parallel;     /* Maximum parallel delivery */
extern cuschar *remote_sort_domains;    /* Remote domain sorting order */
extern retry_config *retries;           /* Chain of retry config information */
extern int     retry_data_expire;       /* When to expire retry data */
extern int     retry_interval_max;      /* Absolute maximum */
extern int     retry_maximum_timeout;   /* The maximum timeout */
extern cuschar *return_path;            /* Return path for a message */
extern BOOL    return_path_remove;      /* Remove return-path headers */
extern int     rewrite_existflags;      /* Indicate which headers have rewrites */
extern cuschar *rfc1413_hosts;          /* RFC hosts */
extern int     rfc1413_query_timeout;   /* Timeout on RFC 1413 calls */
/* extern BOOL    rfc821_domains;  */   /* If set, syntax is 821, not 822 => being abolished */
extern uid_t   root_gid;                /* The gid for root */
extern uid_t   root_uid;                /* The uid for root */
extern router_info routers_available[]; /* Vector of available routers */
extern router_instance *routers;        /* Chain of instantiated routers */
extern router_instance router_defaults; /* Default values */
extern cuschar *router_name;            /* Name of router last started */
extern tree_node *router_var;           /* Variables set by router */
extern ip_address_item *running_interfaces; /* Host's running interfaces */
extern cuschar *running_status;         /* Flag string for testing */
extern int     runrc;                   /* rc from ${run} */

extern cuschar *search_error_message;   /* Details of lookup problem */
extern cuschar *self_hostname;          /* Self host after routing->directors */
extern unsigned int sender_address_cache[(MAX_NAMED_LIST * 2)/32]; /* Cache bits for sender */
extern cuschar *sender_address_data;    /* address_data from sender verify */
extern cuschar *sender_address_unrewritten; /* Set if rewritten by verify */
extern cuschar *sender_data;            /* lookup result for senders */
extern unsigned int sender_domain_cache[(MAX_NAMED_LIST * 2)/32]; /* Cache bits for sender domain */
extern cuschar *sender_fullhost;        /* Sender host name + address */
extern BOOL    sender_helo_dnssec;      /* True if HELO verify used DNS and was DNSSEC */
extern cuschar *sender_helo_name;       /* Host name from HELO/EHLO */
extern cuschar **sender_host_aliases;   /* Points to list of alias names */
extern cuschar *sender_host_auth_pubname; /* Public-name of authentication method */
extern unsigned int sender_host_cache[(MAX_NAMED_LIST * 2)/32]; /* Cache bits for incoming host */
extern BOOL    sender_host_dnssec;      /* true if sender_host_name verified in DNSSEC */
extern cuschar *sender_ident;           /* Sender identity via RFC 1413 */
extern cuschar *sender_rate;            /* Sender rate computed by ACL */
extern cuschar *sender_rate_limit;      /* Configured rate limit */
extern cuschar *sender_rate_period;     /* Configured smoothing period */
extern cuschar *sender_rcvhost;         /* Host data for Received: */
extern cuschar *sender_unqualified_hosts; /* Permitted unqualified senders */
extern cuschar *sender_verify_failure;  /* What went wrong */
extern address_item *sender_verified_list; /* Saved chain of sender verifies */
extern address_item *sender_verified_failed; /* The one that caused denial */
extern cuschar *sending_ip_address;     /* Address of outgoing (SMTP) interface */
extern int     sending_port;            /* Port of outgoing interface */
extern SIGNAL_BOOL sigalrm_seen;        /* Flag for sigalrm_handler */
extern cuschar *sigalarm_setter;        /* For debug, set to callpoint of alarm() */
extern cuschar **sighup_argv;           /* Args for re-execing after SIGHUP */
extern int     slow_lookup_log;         /* Log DNS lookups taking longer than N millisecs */
extern int     smtp_accept_count;       /* Count of connections */
extern BOOL    smtp_accept_keepalive;   /* Set keepalive on incoming */
extern int     smtp_accept_max;         /* Max SMTP connections */
extern int     smtp_accept_max_nonmail; /* Max non-mail commands in one con */
extern cuschar *smtp_accept_max_nonmail_hosts; /* Limit non-mail cmds from these hosts */
extern cuschar *smtp_accept_max_per_connection; /* Max msgs per connection */
extern cuschar *smtp_accept_max_per_host; /* Max SMTP cons from one IP addr */
extern int     smtp_accept_queue;       /* Queue after so many connections */
extern int     smtp_accept_queue_per_connection; /* Queue after so many msgs */
extern int     smtp_accept_reserve;     /* Reserve these SMTP connections */
extern cuschar *smtp_active_hostname;   /* Hostname for this message */
extern int     smtp_backlog_monitor;    /* listen backlog level to log */
extern cuschar *smtp_banner;            /* Banner string (to be expanded) */
extern BOOL    smtp_check_spool_space;  /* TRUE to check SMTP SIZE value */
extern int     smtp_ch_index;           /* Index in smtp_connection_had */
extern cuschar *smtp_cmd_argument;      /* For all SMTP commands */
extern cuschar *smtp_cmd_buffer;        /* SMTP command buffer */
extern struct timeval smtp_connection_start; /* Start time of SMTP connection */
extern uschar  smtp_connection_had[];   /* Recent SMTP commands */
extern int     smtp_connect_backlog;    /* Max backlog permitted */
extern double  smtp_delay_mail;         /* Current MAIL delay */
extern double  smtp_delay_rcpt;         /* Current RCPT delay */
extern BOOL    smtp_enforce_sync;       /* Enforce sync rules */
extern cuschar *smtp_etrn_command;      /* Command to run */
extern BOOL    smtp_etrn_serialize;     /* Only one at once */
extern FILE   *smtp_in;                 /* Incoming SMTP input file */
extern int     smtp_listen_backlog;     /* Current listener socket backlog, if monitored */
extern int     smtp_load_reserve;       /* Only from reserved if load > this */
extern int     smtp_mailcmd_count;      /* Count of MAIL commands */
extern int     smtp_mailcmd_max;        /* Limit for MAIL commands */
extern int     smtp_max_synprot_errors; /* Max syntax/protocol errors */
extern int     smtp_max_unknown_commands; /* As it says */
extern cuschar *smtp_names[];           /* decode for command codes */
extern cuschar *smtp_notquit_reason;    /* Global for disconnect reason */
extern FILE   *smtp_out;                /* Incoming SMTP output file */
extern cuschar *smtp_ratelimit_hosts;   /* Rate limit these hosts */
extern cuschar *smtp_ratelimit_mail;    /* Parameters for MAIL limiting */
extern cuschar *smtp_ratelimit_rcpt;    /* Parameters for RCPT limiting */
extern cuschar *smtp_read_error;        /* Message for SMTP input error */
extern int     smtp_receive_timeout;    /* Applies to each received line */
extern cuschar *smtp_receive_timeout_s; /* ... expandable version */
extern cuschar *smtp_reserve_hosts;     /* Hosts for reserved slots */
extern BOOL    smtp_return_error_details; /* TRUE to return full info */
extern int     smtp_rlm_base;           /* Base interval for MAIL rate limit */
extern double  smtp_rlm_factor;         /* Factor for MAIL rate limit */
extern int     smtp_rlm_limit;          /* Max delay */
extern int     smtp_rlm_threshold;      /* Threshold for RCPT rate limit */
extern int     smtp_rlr_base;           /* Base interval for RCPT rate limit */
extern double  smtp_rlr_factor;         /* Factor for RCPT rate limit */
extern int     smtp_rlr_limit;          /* Max delay */
extern int     smtp_rlr_threshold;      /* Threshold for RCPT rate limit */
extern unsigned smtp_peer_options;      /* Global flags for passed connections */
extern unsigned smtp_peer_options_wrap; /* stacked version hidden by TLS */
#ifdef SUPPORT_I18N
extern cuschar *smtputf8_advertise_hosts; /* ingress control */
#endif

#ifdef WITH_CONTENT_SCAN
extern cuschar *spamd_address;          /* address for the spamassassin daemon */
extern cuschar *spam_bar;               /* the spam "bar" (textual representation of spam_score) */
extern cuschar *spam_report;            /* the spamd report (multiline) */
extern cuschar *spam_action;            /* the spamd recommended-action */
extern cuschar *spam_score;             /* the spam score (float) */
extern cuschar *spam_score_int;         /* spam_score * 10 (int) */
#endif
#ifdef SUPPORT_SPF
extern cuschar *spf_guess;              /* spf best-guess record */
extern cuschar *spf_header_comment;     /* spf header comment */
extern cuschar *spf_received;           /* Received-SPF: header */
extern cuschar *spf_result;             /* spf result in string form */
extern BOOL    spf_result_guessed;      /* spf result is of best-guess operation */
extern cuschar *spf_smtp_comment;       /* spf comment to include in SMTP reply */
extern cuschar *spf_smtp_comment_template;
                                        /* template to construct the spf comment by libspf2 */
#endif
extern BOOL    split_spool_directory;   /* TRUE to use multiple subdirs */
extern FILE   *spool_data_file;         /* handle for -D file */
extern cuschar *spool_directory;        /* Name of spool directory */
extern BOOL    spool_wireformat;        /* can write wireformat -D files */
#ifdef SUPPORT_SRS
extern cuschar *srs_recipient;          /* SRS recipient */
#endif
extern BOOL    strict_acl_vars;         /* ACL variables have to be set before being used */
extern int     string_datestamp_offset; /* After insertion by string_format */
extern int     string_datestamp_length; /* After insertion by string_format */
extern int     string_datestamp_type;   /* After insertion by string_format */
extern BOOL    strip_excess_angle_brackets; /* Surrounding route-addrs */
extern BOOL    strip_trailing_dot;      /* Remove dots at ends of domains */
extern cuschar *submission_domain;      /* Domain for submission mode */
extern cuschar *submission_name;        /* User name set from ACL */
extern BOOL    syslog_duplication;      /* FALSE => no duplicate logging */
extern int     syslog_facility;         /* As defined by Syslog.h */
extern BOOL    syslog_pid;              /* TRUE if PID on syslogs */
extern cuschar *syslog_processname;     /* 'ident' param to openlog() */
extern BOOL    syslog_timestamp;        /* TRUE if time on syslogs */
extern cuschar *system_filter;          /* Name of system filter file */

extern cuschar *system_filter_directory_transport; /* Transports for the */
extern cuschar *system_filter_file_transport; /* system filter */
extern cuschar *system_filter_pipe_transport;
extern cuschar *system_filter_reply_transport;

extern gid_t   system_filter_gid;       /* Gid for running system filter */
extern BOOL    system_filter_gid_set;   /* TRUE if gid set */
extern uid_t   system_filter_uid;       /* Uid for running system filter */
extern BOOL    system_filter_uid_set;   /* TRUE if uid set */

extern blob    tcp_fastopen_nodata;     /* for zero-data TFO connect requests */
extern BOOL    tcp_nodelay;             /* Controls TCP_NODELAY on daemon */
extern tfo_state_t tcp_out_fastopen;    /* TCP fast open */
#ifdef USE_TCP_WRAPPERS
extern cuschar *tcp_wrappers_daemon_name; /* tcpwrappers daemon lookup name */
#endif
extern int     test_harness_load_avg;   /* For use when testing */
extern int     thismessage_size_limit;  /* Limit for this message */
extern int     timeout_frozen_after;    /* Max time to keep frozen messages */
#ifdef MEASURE_TIMING
extern struct timeval timestamp_startup; /* For development measurements */
#endif

extern cuschar *transport_name;         /* Name of transport last started */
extern int     transport_count;         /* Count of bytes transported */
extern int     transport_newlines;      /* Accurate count of number of newline chars transported */
extern cuschar **transport_filter_argv; /* For on-the-fly filtering */
extern int     transport_filter_timeout; /* Timeout for same */

extern transport_info transports_available[]; /* Vector of available transports */
extern transport_instance *transports;  /* Chain of instantiated transports */
extern transport_instance transport_defaults; /* Default values */

extern int     transport_write_timeout; /* Set to time out individual writes */

extern tree_node *tree_dns_fails;       /* Tree of DNS lookup failures */
extern tree_node *tree_duplicates;      /* Tree of duplicate addresses */
extern tree_node *tree_nonrecipients;   /* Tree of nonrecipient addresses */
extern tree_node *tree_unusable;        /* Tree of unusable addresses */

extern gid_t  *trusted_groups;          /* List of trusted groups */
extern uid_t  *trusted_users;           /* List of trusted users */
extern cuschar *timezone_string;        /* Required timezone setting */

extern cuschar *unknown_login;          /* To use when login id unknown */
extern cuschar *unknown_username;       /* Ditto */
extern cuschar *untrusted_set_sender;   /* Let untrusted users set these senders */
extern cuschar *uucp_from_pattern;      /* For recognizing "From " lines */
extern cuschar *uucp_from_sender;       /* For building the sender */

extern cuschar *warn_message_file;      /* Template for warning messages */
extern cuschar *warnmsg_delay;          /* String form of delay time */
extern cuschar *warnmsg_recipients;     /* Recipients of warning message */
extern BOOL    write_rejectlog;         /* Control of reject logging */

extern cuschar *verify_mode;            /* Running a router in verify mode */
extern cuschar *version_copyright;      /* Copyright notice */
extern cuschar *version_date;           /* Date of compilation */
extern cuschar *version_cnumber;        /* Compile number */
extern cuschar *version_string;         /* Version string */

extern int     warning_count;           /* Delay warnings sent for this msg */

/* End of globals.h */
