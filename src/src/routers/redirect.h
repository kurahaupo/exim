/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright © The Exim Maintainers 2021 - 2026 */
/* Copyright © University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Header for the redirect router */

/* Private structure for the private options. */

typedef struct {
  transport_instance *directory_transport;
  transport_instance *file_transport;
  transport_instance *pipe_transport;
  transport_instance *reply_transport;

  uschar *data;
  uschar *directory_transport_name;

  uschar *expand_allow_filter;
  uschar *expand_forbid_blackhole;
  uschar *expand_forbid_exim_filter;
  uschar *expand_forbid_filter_dlfunc;
  uschar *expand_forbid_filter_existstest;
  uschar *expand_forbid_file;
  uschar *expand_forbid_filter_logwrite;
  uschar *expand_forbid_filter_lookup;
  uschar *expand_forbid_filter_perl;
  uschar *expand_forbid_filter_readfile;
  uschar *expand_forbid_filter_readsocket;
  uschar *expand_forbid_filter_reply;
  uschar *expand_forbid_filter_run;
  uschar *expand_forbid_include;
  uschar *expand_forbid_pipe;
  uschar *expand_forbid_sieve_filter;
  uschar *expand_forbid_smtp_code;
  uschar *file;
  uschar *file_dir;
  uschar *file_transport_name;
  uschar *include_directory;
  uschar *pipe_transport_name;
  uschar *reply_transport_name;

  uschar *sieve_enotify_mailto_owner;
  uschar *sieve_inbox;
  uschar *sieve_subaddress;
  uschar *sieve_useraddress;
  uschar *sieve_vacation_directory;

  uschar *syntax_errors_text;
  uschar *syntax_errors_to;
  uschar *qualify_domain;

  uid_t  *owners;
  gid_t  *owngroups;

  int   modemask;
  int   bit_options;

  BOOL  hide_child_in_errmsg;
  BOOL  one_time;
  BOOL  qualify_preserve_domain;
  BOOL  skip_syntax_errors;

  BOOL  check_ancestor;
  BOOL  check_group;
  BOOL  check_owner;
  BOOL	allow_filter;
  BOOL	forbid_blackhole;
  BOOL	forbid_exim_filter;
  BOOL	forbid_file;
  BOOL	forbid_filter_dlfunc;
  BOOL	forbid_filter_existstest;
  BOOL	forbid_filter_logwrite;
  BOOL	forbid_filter_lookup;
  BOOL	forbid_filter_perl;
  BOOL	forbid_filter_readfile;
  BOOL	forbid_filter_readsocket;
  BOOL	forbid_filter_reply;
  BOOL	forbid_filter_run;
  BOOL	forbid_include;
  BOOL	forbid_pipe;
  BOOL	forbid_sieve_filter;
  BOOL	forbid_smtp_code;

} redirect_router_options_block;

/* End of routers/redirect.h */
