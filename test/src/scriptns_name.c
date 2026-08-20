/*************************************************
*       scriptns - A Fake Nameserver Program     *
*************************************************/

/*
Copyright (c) The Exim Maintainers 2026
SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char uschar;

#define CS   (char *)
#define CCS  (const char *)
#define Ustrlen(s)         (int)strlen(CCS(s))



const uschar *
scriptns_sock_name(const uschar * testdir)
{
static uschar buf[PATH_MAX];

snprintf(CS buf, sizeof(buf), "%s/aux-var/scriptns", testdir);
buf[PATH_MAX-1] = '\0';
return buf;
}

/* vi: aw ai sw=2 sts=2 ts=8 et
*/
/* End of scriptns_name.c */
