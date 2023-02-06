#ifndef __NAGIOS_H_
#define __NAGIOS_H_

#include <sys/time.h>

#define WINR_DEF_PORT   5985

#define UNKNOWN_VALUE            0x7FFFFFFF  /* Signed int highest value */
#define UNKNOWN_PERCENTAGE_USAGE 200         /* 200% */

enum {
   STATE_OK,
   STATE_WARNING,
   STATE_CRITICAL,
   STATE_UNKNOWN,
   STATE_DEPENDENT
};
enum {
   OK = 0,
   ERROR = -1
};

#ifndef FALSE
enum {
   FALSE,
   TRUE
};
#endif

# define no_argument            0
# define required_argument      1

#define UT_CREDENTIALS _("\
 -u, --username=STRING:<domain name/username>\n\
    Username and Domain name to access data from the windows server\n\
 -P, --password=STRING\n\
    Domain password\n")

#define UT_SUPPORT_SMN _("\n\
Send email to info@samanagroup.com if you have questions regarding use\n\
of this software. To submit patches or suggest improvements, send email to\n\
info@samanagroup.com\n\n")

#define FREE_NULL(x) do { \
   if((x) != NULL) free(x); \
   x = NULL; \
} while(0);

int process_arguments (int, char **);
int validate_arguments (void);
void print_help (void);
void print_usage (void);
int get_threshold(char *arg, int *th);
char *smn_perfdata (const char *label, long int val, const char *uom,
    int warnp, long int warn, int critp, long int crit, int minp,
    long int minv, int maxp, long int maxv);

/* Following functions were pulled from nagios-plugins header files. */
extern unsigned int timeout_interval;
void timeout_alarm_handler (int signo);
#define np_extra_opts(acptr,av,pr) av
void usage4(const char *) __attribute__((noreturn));
#define _(String) gettext (String)
long deltime (struct timeval tv);
int xasprintf (char **strp, const char *fmt, ...);
int is_integer (char *);
int is_intpos (char *);
int is_intneg (char *);
int is_intnonneg (char *);
int is_intpercent (char *);

int is_numeric (char *);
int is_positive (char *);
int is_negative (char *);
int is_nonnegative (char *);
int is_percentage (char *);

int is_option (char *);
void usage (const char *) __attribute__((noreturn));
void usage2(const char *, const char *) __attribute__((noreturn));
void usage3(const char *, int) __attribute__((noreturn));
void usage4(const char *) __attribute__((noreturn));
void usage5(void) __attribute__((noreturn));
void usage_va(const char *fmt, ...) __attribute__((noreturn));
int parse_timeout_string (char *timeout_str);
int is_host (const char *);
int is_addr (const char *);

void print_revision (const char *, const char *);
#define UT_HLP_VRS _("\
       %s (-h | --help) for detailed help\n\
       %s (-V | --version) for version information\n")
#ifdef NP_EXTRA_OPTS
#define UT_EXTRA_OPTS _("\
 --extra-opts=[section][@file]\n\
    Read options from an ini file. See\n\
    https://www.nagios-plugins.org/doc/extra-opts.html\n\
    for usage and examples.\n")
#else
#define UT_EXTRA_OPTS " \b"
#endif
#define UT_HOST_PORT _("\
 -H, --hostname=ADDRESS\n\
    Host name, IP Address, or unix socket (must be an absolute path)\n\
 -%c, --port=INTEGER\n\
    Port number (default: %s)\n")

#define UT_WARN_CRIT _("\
 -w, --warning=DOUBLE\n\
    Response time to result in warning status (seconds)\n\
 -c, --critical=DOUBLE\n\
    Response time to result in critical status (seconds)\n")

#define UT_CONN_TIMEOUT _("\
 -t, --timeout=INTEGER:<timeout state>\n\
    Seconds before connection times out (default: %d)\n\
    Optional \":<timeout state>\" can be a state integer (0,1,2,3) or a state STRING\n")
 
#define UT_VERBOSE _("\
 -v, --verbose\n\
    Show details for command-line debugging (Nagios may truncate output)\n")

#define UT_HELP_VRSN _("\
\nOptions:\n\
 -h, --help\n\
    Print detailed help screen\n\
 -V, --version\n\
    Print version information\n")

#define STD_LONG_OPTS \
{"version",no_argument,0,'V'},\
{"verbose",no_argument,0,'v'},\
{"help",no_argument,0,'h'},\
{"timeout",required_argument,0,'t'},\
{"critical",required_argument,0,'c'},\
{"warning",required_argument,0,'w'},\
{"hostname",required_argument,0,'H'}

enum {
   DEFAULT_SOCKET_TIMEOUT = 10,   /* timeout after 10 seconds */
   MAX_INPUT_BUFFER = 8192,        /* max size of most buffers we use */
   MAX_HOST_ADDRESS_LENGTH = 256  /* max size of a host address */
};

#endif