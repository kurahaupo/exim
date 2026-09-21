/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright © The Exim Maintainers 2020 - 2026 */
/* Copyright © University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */


/* This header file contains type definitions and macros that I use as
"standard" in the code of Exim and its utilities. Make it idempotent because
local_scan.h includes it and exim.h includes them both (to get this earlier). */

#ifndef MYTYPES_H
#define MYTYPES_H

# include <string.h>

#ifndef FALSE
# define FALSE         0
#endif

#ifndef TRUE
# define TRUE          1
#endif

#ifndef TRUE_UNSET
# define TRUE_UNSET    2
#endif


/* DEPRECATED - warn when marked functions and objects are referenced */

#if __STDC_VERSION__ >= 202300L
# define DEPRECATED  [[deprecated]]
#else
# if defined(__GNUC__) || defined(__clang__)
#  define DEPRECATED  __attribute__((__deprecated__))
# else
#  define DEPRECATED
# endif
#endif

#define DEPRECATE_UCHAR_MACROS 3

/* We gave up on trying to get compilers to check on printf-like functions
because they are both whiney about value sizes where they cannot do decent
static analysis, and incapable of handling extensions to printf formats.
The annotation on functions is still in place but does nothing. */

#if defined(__GNUC__) || defined(__clang__)
/* #  define PRINTF_FUNCTION(A,B)	__attribute__((format(printf,A,B))) */
# define ARG_UNUSED		__attribute__((__unused__))
# define FUNC_MAYBE_UNUSED	__attribute__((__unused__))
# define WARN_UNUSED_RESULT	__attribute__((__warn_unused_result__))
# define ALLOC			__attribute__((malloc))
# define NORETURN		__attribute__((noreturn))
# define UNREACHABLE		__builtin_unreachable()
# ifndef __clang__
#  define ALLOC_SIZE(A)		__attribute__((alloc_size(A)))
# else
#  define ALLOC_SIZE(A)		/**/
# endif
#else
# define ARG_UNUSED		/**/
# define FUNC_MAYBE_UNUSED	/**/
# define WARN_UNUSED_RESULT	/**/
# define ALLOC			/**/
# define ALLOC_SIZE(A)		/**/
# define NORETURN		/**/
# define UNREACHABLE		/**/
#endif

#ifndef PRINTF_FUNCTION
# define PRINTF_FUNCTION(A,B)	/**/
#endif

#ifdef WANT_DEEPER_PRINTF_CHECKS
# define ALMOST_PRINTF(A, B) PRINTF_FUNCTION(A, B)
#else
# define ALMOST_PRINTF(A, B)	/**/
#endif


/* Some operating systems (naughtily, imo) include a definition for "uchar" in
the standard header files, so we use "uschar". Solaris has u_char in
sys/types.h. This is just a typing convenience, of course. */

typedef unsigned char uschar;
typedef unsigned char BOOL;
/* We also have SIGNAL_BOOL, which requires signal.h be included, so is defined
elsewhere */


/* These macros save typing for the casting that is needed to cope with the
mess that is "char" in ISO/ANSI C. Having now been bitten enough times by
systems where "char" is actually signed, I've converted Exim to use entirely
unsigned chars, except in a few special places such as arguments that are
almost always literal strings. */

#define BadType(X) (*(struct BadRef_##X *)(NULL))

#if CHAR_MIN < 0 || FORCE_CHAR_CASTS
/* convert char to uschar but keep all other type info */
# define C(X) _Generic(X, \
		uschar       *         : (char       *)(X), \
		uschar const *         : (char const *)(X), \
                \
		uschar       *       * : (char       **)(X), \
		uschar const *       * : (char const **)(X), \
                \
		default                : &BadType(C))
/* convert uschar to char but keep all other type info */
# define U(X) _Generic(X, \
		  char       *         : (uschar       *)(X), \
		  char const *         : (uschar const *)(X), \
                  \
		  char       *       * : (uschar       **)(X), \
		  char const *       * : (uschar const **)(X), \
                \
		default                : &BadType(U))
/* Only use opt_* macros in type-covariant macro definitions */
#define opt_C(X) _Generic(X, \
		  char       *         :                  (X), \
		  char const *         :                  (X), \
		uschar       *         : (char       * )  (X), \
		uschar const *         : (char const * )  (X), \
		\
		  char       *       * :                  (X), \
		  char const *       * :                  (X), \
		uschar       *       * : (char       **)  (X), \
		uschar const *       * : (char const **)  (X), \
		\
		default                : &BadType(opt_C))

#define opt_U(X) _Generic(X, \
		  char       *         : (uschar      * ) (X), \
		  char const *         : (uschar const* ) (X), \
		uschar       *         :                  (X), \
		uschar const *         :                  (X), \
		\
		  char       *       * : (uschar      **) (X), \
		  char const *       * : (uschar const**) (X), \
		uschar       *       * :                  (X), \
		uschar const *       * :                  (X), \
		\
		default                : &BadType(opt_U))


#else

# define C(X) (X)
# define U(X) (X)
# define opt_C(X) (X)
# define opt_U(X) (X)
#endif

/* Apply constancy ([R]eadonly) to the target but keep all other type info */
#define R(X) _Generic(X, \
		  char       *         : (char   const *)(X), \
		  void       *         : (void   const *)(X), \
		uschar       *         : (uschar const *)(X), \
                \
		  char       *       * : (char   const **)(X), \
		  void       *       * : (void   const **)(X), \
		uschar       *       * : (uschar const **)(X), \
                \
		default                : &BadType(R))

/* Deeply apply constancy ([R]ecursive [R]eadonly) to the target but keep all other type info */
#define RR(X) _Generic(X, \
		  char       *         : (char   const *)(X), \
		  void       *         : (void   const *)(X), \
		uschar       *         : (uschar const *)(X), \
                \
		  char       *       * : (char   const * const *)(X), \
		  char       * const * : (char   const * const *)(X), \
		  char const *       * : (char   const * const *)(X), \
		  void       *       * : (void   const * const *)(X), \
		uschar       *       * : (uschar const * const *)(X), \
		uschar       * const * : (uschar const * const *)(X), \
		uschar const *       * : (uschar const * const *)(X), \
                \
		default                : &BadType(RR))

/* Remove constancy ([W]ritable) to the target but keep all other type info */
#define W(X) _Generic(X, \
		  char const *         : (char   * ) (X), \
		  void const *         : (void   * ) (X), \
		uschar const *         : (uschar * ) (X), \
                \
		  char       * const * : (char   **) (X), \
		  char const *       * : (char   **) (X), \
		  char const * const * : (char   **) (X), \
		  void       * const * : (void   **) (X), \
		  void const *       * : (void   **) (X), \
		  void const * const * : (void   **) (X), \
		uschar       * const * : (uschar **) (X), \
		uschar const *       * : (uschar **) (X), \
		uschar const * const * : (uschar **) (X), \
                \
		default                : &BadType(W))

/* convert char to uschar and apply constancy but keep all other type info */
#define RC(X) R(C(X))
/* convert uschar to char and apply constancy but keep all other type info */
#define RU(X) R(U(X))

/* cause these to error if used not as functions */
#if ! DEPRECATE_UCHAR_MACROS

# define CS   (char *)
# define CCS  (const char *)
# define CSS  (char **)
# define US   (unsigned char *)
# define CUS  (const unsigned char *)
# define USS  (unsigned char **)
# define CUSS (const unsigned char **)
# define CCSS (const char **)

#else

# if CHAR_MIN < 0 || FORCE_CHAR_CASTS
#  define US      (uschar*)""	/* must be used like US"quoted string" */
# else
#  define US               ""	/* must be used like US"quoted string" */
# endif

# if DEPRECATE_UCHAR_MACROS < 1

static inline          char       DEPRECATED *   CS (unsigned char       *  X) { return C(X); }
static inline          char const DEPRECATED *  CCS (unsigned char const *  X) { return C(X); }
static inline          char       DEPRECATED **  CSS(unsigned char       ** X) { return C(X); }
static inline          char const DEPRECATED ** CCSS(unsigned char const ** X) { return C(X); }

#  ifndef US
static inline unsigned char       DEPRECATED *   US (         char       *  X) { return U(X); }
#  endif
static inline unsigned char const DEPRECATED *  CUS (         char const *  X) { return U(X); }
static inline unsigned char       DEPRECATED **  USS(         char       ** X) { return U(X); }
static inline unsigned char const DEPRECATED ** CUSS(         char const ** X) { return U(X); }

# elif DEPRECATE_UCHAR_MACROS < 2

void (*(*CS)())(), (*(*CCS)())(), (*(*CSS)())(), (*(*CCSS)())(), (*(*CUS)())(), (*(*USS)())(), (*(*CUSS)())();

# endif
#endif

/* Only use opt_* macros in type-covariant macro definitions */
#define opt_R(X) _Generic(X, \
		  char       *         :   (char const* ) (X), \
		  char const *         :                  (X), \
		uschar       *         : (uschar const* ) (X), \
		uschar const *         :                  (X), \
		\
		  char       *       * :   (char const**) (X), \
		  char       * const * :   (char const**) (X), \
		  char const *       * :                  (X), \
		  char const * const * :   (char const**) (X), \
		uschar       *       * : (uschar const**) (X), \
		uschar       * const * : (uschar const**) (X), \
		uschar const *       * :                  (X), \
		uschar const * const * : (uschar const**) (X), \
		\
		default                : &BadType(opt_R))

#define opt_RR(X) _Generic(X, \
		  char       *       * :   (char const* const*) (X), \
		  char       * const * :   (char const* const*) (X), \
		  char const *       * :   (char const* const*) (X), \
		  char const * const * :                        (X), \
		uschar       *       * : (uschar const* const*) (X), \
		uschar       * const * : (uschar const* const*) (X), \
		uschar const *       * : (uschar const* const*) (X), \
		uschar const * const * :                  (X), \
		default                : &BadType(opt_RR))

#define opt_W(X) _Generic(X, \
		  char       *         :                  (X), \
		  char const *         :   (char*)        (X), \
		uschar       *         :                  (X), \
		uschar const *         : (uschar*)        (X), \
                \
		  char       **        :                  (X), \
		  char const **        :   (char**)       (X), \
		uschar       *       * :                  (X), \
		uschar       * const * :                  (X), \
		uschar const *       * : (uschar**)       (X), \
		uschar const * const * : (uschar**)       (X), \
                \
		default                : &BadType(opt_W))

/* The C library string functions expect "char *" arguments. Use macros to
avoid having to write a cast each time. We do this for string and file
functions that are called quite often; for other calls to external libraries
(which are on the whole special-purpose) we just use individual casts. */

#define Uatoi(s)           atoi(C(s))
#define Uatol(s)           atol(C(s))
#define Uchdir(s)          chdir(C(s))
#define Uchmod(s,n)        chmod(C(s),n)
#define Ufgets(b,n,f)      fgets(C(b),n,f)
#define Ufopen(s,t)        exim_fopen(C(s),opt_C(t))
#define Ulink(s,t)         link(C(s),C(t))
#define Ulstat(s,t)        lstat(C(s),t)

#ifdef O_BINARY							/* This is for Cygwin,  */
# define Uopen(s,n,m)       exim_open(C(s),(n)|O_BINARY,m)	/* where all files must */
# define Uopen2(s,n)        exim_open2(C(s),(n)|O_BINARY)
#else								/* be opened as binary  */
# define Uopen(s,n,m)       exim_open(C(s),n,m)			/* to avoid problems    */
# define Uopen2(s,n)        exim_open2(C(s),n)
#endif								/* with CRLF endings.   */
#define Uread(f,b,l)       read(f,C(b),l)
#define Urename(s,t)       rename(C(s),C(t))
#define Ustat(s,t)         stat(C(s),t)
#define Ustrchr(s,n)       ((typeof(*(s))*) strchr(C(s),n))
#define Ustrchrnul(s,n)    ((typeof(*(s))*) strchrnul(C(s),n))
#define CUstrerror(n)      U(strerror(n))
#define Ustrcmp(s,t)       strcmp(C(s),opt_C(t))
#define Ustrcpy_nt(s,t)    ((typeof(*(s))*) strcpy(C(s), opt_C(t)))			/* no taint check */
#define Ustrcspn(s,t)      strcspn(C(s),opt_C(t))
#define Ustrftime(s,m,f,t) strftime(C(s),m,f,t)
#define Ustrlen(s)         (int)strlen(C(s))
#define Ustrncmp(s,t,n)    strncmp(C(s),opt_C(t),n)
#define Ustrncpy_nt(s,t,n) strncpy(C(s), opt_C(t), n)		/* no taint check */
#define Ustrpbrk(s,t)      ((typeof(*(s))*) strpbrk(C(s),opt_C(t)))
#define Ustrrchr(s,n)      ((typeof(*(s))*) strrchr(C(s),n))
#define CUstrrchr(s,n)     ((const typeof(*(s))*) strrchr(C(s),n))
#define Ustrspn(s,t)       strspn(C(s),opt_C(t))
#define Ustrstr(s,t)       ((typeof(*(s))*) strstr(C(s),opt_C(t)))
#define CUstrstr(s,t)      ((const typeof(*(s))*) strstr(C(s),opt_C(t)))
#define Ustrtod(s,t)       _Generic(t, typeof(*(s))** : strtod(C(s), (char **)(t)), \
                                     /*typeof(NULL)   : strtod(C(s),t),*/ \
                                       default        : BadType(Ustrtod_args_1_and_2_mismatch))
#define Ustrtol(s,t,b)     _Generic(t, typeof(*(s))** : strtol(C(s), (char **)(t),b), \
                                     /*typeof(NULL)   : strtol(C(s),t,b),*/ \
                                       default        : BadType(Ustrtol_args_1_and_2_mismatch))
#define Ustrtoul(s,t,b)    _Generic(t, typeof(*(s))** : strtoul(C(s), (char **)(t),b), \
                                     /*typeof(NULL)   : strtoul(C(s),t,b),*/ \
                                       default        : BadType(Ustrtoul_args_1_and_2_mismatch))
#define Uunlink(s)         unlink(C(s))

#if defined(EM_VERSION_C) || defined(LOCAL_SCAN) || defined(DLFUNC_IMPL)
# define Ustrcat(s,t)       ((typeof(*(s))*) strcat(C(s), opt_C(t)))
# define Ustrcpy(s,t)       ((typeof(*(s))*) strcpy(C(s), opt_C(t)))
# define Ustrncat(s,t,n)    ((typeof(*(s))*) strncat(C(s), opt_C(t), n))
# define Ustrncpy(s,t,n)    ((typeof(*(s))*) strncpy(C(s), opt_C(t), n))
# define Ustpcpy(s,t)       ((typeof(*(s))*) stpcpy(C(s), opt_C(t)))
#else
# define Ustrcat(s,t)       ((typeof(*(s))*) __Ustrcat(s, opt_U(t), __FUNCTION__, __LINE__))
# define Ustrcpy(s,t)       ((typeof(*(s))*) __Ustrcpy(s, opt_U(t), __FUNCTION__, __LINE__))
# define Ustrncat(s,t,n)    ((typeof(*(s))*) __Ustrncat(s, opt_U(t), n, __FUNCTION__, __LINE__))
# define Ustrncpy(s,t,n)    ((typeof(*(s))*) __Ustrncpy(s, opt_U(t), n, __FUNCTION__, __LINE__))
# define Ustpcpy(s,t)       ((typeof(*(s))*) __Ustpcpy(s, opt_U(t), __FUNCTION__, __LINE__))
#endif

#endif
/* End of mytypes.h */
