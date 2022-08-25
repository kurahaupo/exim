/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the functions that are shared by the lookups */

extern int     lf_check_file(int, cuschar *, int, int, uid_t *, gid_t *,
                 const char *, uschar **);
extern gstring *lf_quote(uschar *, uschar *, int, gstring *);
extern int     lf_sqlperform(cuschar *, cuschar *, cuschar *,
		 cuschar *, uschar **,
                 uschar **, uint *, cuschar *,
		 int(*)(cuschar *, uschar *, uschar **,
                 uschar **, BOOL *, uint *, cuschar *));

/* End of lf_functions.h */
