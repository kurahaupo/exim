/*************************************************
*       scriptns - A Fake Nameserver Program     *
*************************************************/

/* This program exists to support the testing of DNS handling code in Exim.
it takes script input from the testcase runner and supplies it to Exim as
DNS responses.

It takes two commandline arguments:
- The testsuite toplevel directory path
- A pathname for pidfile creation

Copyright (c) The Exim Maintainers 2026
SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
# include <sys/un.h>
#endif

typedef unsigned char uschar;

#define CS   (char *)
#define CCS  (const char *)
#define US   (unsigned char *)

#define Ustrlen(s)         (int)strlen(CCS(s))
#define Ustrcmp(s,t)       strcmp(CCS(s),CCS(t))
#define Ustrncpy(s,t,n)    strncpy(CS(s),CCS(t),n)

typedef struct line {
  struct line * next;
  unsigned len;
  uschar line[1];
} line;

int debug = 0;

extern const uschar * scriptns_sock_name(const uschar *);

/******************************************************************************/

/* Setup Unix-dom socket for comms from fakens */

static int
make_unix_socket(const uschar * name)
{
int fd;
struct sockaddr_un sa_un = {.sun_family = AF_UNIX};
const uschar * where = US"socket";

if ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) goto bad;
where = US"fcntl";

Ustrncpy(sa_un.sun_path, name, sizeof(sa_un.sun_path));
sa_un.sun_path[sizeof(sa_un.sun_path)-1] = '\0';

where = US"bind";
if (bind(fd, (const struct sockaddr *)&sa_un, (socklen_t)sizeof(sa_un)) < 0)
  goto bad;
if (debug) fprintf(stderr, "scriptns: socket '%s' bind ok\n", name);

where = US"chmod";
if (chmod(CCS name, 0777) != 0)
  {
  unlink(CCS name);
  goto bad;
  }

return fd;

bad:
  fprintf(stderr, "scriptns: %s: %s\n", where, strerror(errno));
  return -1;
}


/* Dump the packet content. Some time in future it might be nice to
decode the query packets (but not the responses, as they will commonly be
deliberately malformed */

static void
print_packet(FILE * f, const uschar * prefix, const uschar * buf, int len)
{
fprintf(f, "%s", prefix);
for(const uschar * s = buf; s < buf+len; s++)
  {
  uschar c = *s;
  if (isprint(c)) fputc(c, f); else fprintf(f, "\\x%02x", c);
  }
fputc('\n', f);
}

/*************************************************
*           Entry point and main program         *
*************************************************/

int
main(int argc, char ** argv)
{
FILE * f;
line * script = NULL;
const uschar * sockname;
uschar buffer[10240], * p;
int fakens_fd, rc = EXIT_FAILURE;

if (argc != 3)
  {
  fprintf(stderr, "scriptns: expected 2 arguments, received %d\n", argc-1);
  return EXIT_FAILURE;
  }

/* Create the comms socket first, while our caller is waiting on our pidfile */

sockname = scriptns_sock_name(argv[1]);
if ((fakens_fd = make_unix_socket(sockname)) < 0)
  return EXIT_FAILURE;

/* Write a pidfile, to interlock startup with our caller */

if (!(f = fopen(argv[2], "w")))
  {
  fprintf(stderr, "scriptns: pidfile create: %s\n", strerror(errno));
  return EXIT_FAILURE;
  }
fprintf(f, "scriptns: %ld\n", (long)getpid());
fclose(f);
f = NULL;


/* Read in the controlling script, interpreting \xNN coded bytes, comments
and continuation lines */

if (debug) fprintf(stderr, "scriptns: reading script\n");

/* Loop reading each physical line, appending in buffer */

p = buffer;
for (line * next, * last = NULL;
     fgets(CS p, sizeof(buffer) - (p - buffer), stdin); )
  {
  unsigned plen;
  int continuation = 0, comment = 0;
  uschar * s, * t, c;

  plen = Ustrlen(p);
  if (p[plen-1] == '\n') p[--plen] = '\0';		/* trim NL */

  if (strcmp(CS p, "++++") == 0) break;

  for (s = p; isblank(*s); ) s++;
  if (s > p)
    {
    plen -= s - p;
    memmove(p, s, plen+1);				/* drop leading WS */
    }

  for (s = p, t = s - 1; c = *s; s++)			/* find last nonWS */
    if (!isspace(c))
      if (c == '#') comment = 1;			/* start of comment */
      else if (c != '\\') { if (!comment) t = s; }	/* plain ch */
      else if (!*++s) { continuation = 1; break; }	/* continuation */
      else if (!comment) t = s;				/* escaped ch */
  *++t = '\0';					/* drop trailing WS & comment */

  if (continuation)
    { p = t; continue; }			/* next physical line */

  /* Allocate & link new script "line" struct */

  next = malloc(sizeof(line) + (t - buffer));	/* res len always <= src */
  if (last)
    last->next = next;
  else
    script = next;
  next->next = NULL;

  /* Copy the logical line to the "line" struct, handling hexcoded bytes */

  for (s = buffer, t = next->line; *s; s++, t++)
    {
    uschar cl = *s, ch;
    if (cl == '\\' && (cl = *++s) == 'x')		/* hex coded */
      {
      if ((ch = *++s - '0') > 9 && (ch -= 'A'-'9'-1) > 15) ch -= 'a'-'A';
      if ((cl = *++s - '0') > 9 && (cl -= 'A'-'9'-1) > 15) cl -= 'a'-'A';
      cl |= ch << 4;
      }
    *t = cl;
    }
  next->len = t - next->line;

  /* Set up for next logical line */

  p = buffer;
  last = next;
  }

fclose(stdin);

/* fakens does a one-time dns cmd/resp, on a new exec with cmdline.
We need to run as a daemon.  So: set up a Unix-dom socket for comms to
fakens; it looks for that and gets a response from it rather than it's
zone files.  We send the response into the socket, from our script line.
We may as well also have fakens send us the query too, then we can output
it for observability of what the SUT exim asked.
*/

/* Walk the script lines, waiting for a request for each line then
responding with the line data. */

if (debug) fprintf(stderr, "scriptns: running script\n");
for (; script; script = script->next)
  {
  struct sockaddr_un sa_un;
  socklen_t slen = sizeof(sa_un);
  uschar packet[2048 * 32 + 32];

  if (debug) fprintf(stderr, "scriptns: wait for req\n");
  int reqlen = recvfrom(fakens_fd, packet, sizeof(packet), 0, (void *)&sa_un, &slen);
  if (reqlen < 0)
    {
    fprintf(stderr, "scriptns: pipe read: %s\n", strerror(errno));
    goto done;
    }

  if (debug) fprintf(stderr, "scriptns: req '%.*s'\n", reqlen, packet);
  if (debug) fprintf(stderr, "scriptns: res '%.*s'\n", script->len, script->line);
  /* Log the query and our response */

  if (debug) print_packet(stderr, US"<<< ", packet, reqlen);
  print_packet(stdout, US"<<< ", packet, reqlen);

  if (debug) print_packet(stderr, US">>> ", script->line, script->len);
  print_packet(stdout, US">>> ", script->line, script->len);

  if (sendto(fakens_fd, script->line, (size_t)script->len, 0, (void *)&sa_un, slen)
      != script->len)
    {
    fprintf(stderr, "scriptns: pipe write: %s\n", strerror(errno));
    goto done;
    }
  }
rc = EXIT_SUCCESS;
if (debug) fprintf(stderr, "scriptns: exit good\n");

done:
  close(fakens_fd);
  unlink(CCS sockname);
  unlink(CCS argv[2]);
  return rc;
}

/* vi: aw ai sw=2 ts=8
*/
/* End of scriptns.c */
