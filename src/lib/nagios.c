#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <unistd.h>
#include <getopt.h>
#include "nagios.h"

extern const char *progname;
extern const char *copyright;
extern const char *email;
extern int port;
extern char *server_name;
extern int verbose;
extern char *username;
extern char *password;
extern char *url;
extern int warn;
extern int crit;


char *smn_perfdata (const char *label,
 long int val,
 const char *uom,
 int warnp,
 long int warn,
 int critp,
 long int crit,
 int minp,
 long int minv,
 int maxp,
 long int maxv)
{
    char *data, *temp;

    if (strpbrk (label, "'= "))
        xasprintf (&data, "'%s'=%ld%s;", label, val, uom);
    else
        xasprintf (&data, "%s=%ld%s;", label, val, uom);

    if (warnp)
        xasprintf (&temp, "%s%ld;", data, warn);
    else
        xasprintf (&temp, "%s;", data);
    free(data);
    data=temp;

    if (critp)
        xasprintf (&temp, "%s%ld;", data, crit);
    else
        xasprintf (&temp, "%s;", data);
    free(data);
    data=temp;

    if (minp){
        xasprintf (&temp, "%s%ld", data, minv);
        free(data);
        data=temp;
    }

    if (maxp){
        xasprintf (&temp, "%s;%ld", data, maxv);
        free(data);
        data=temp;
    }

    return data;
}

int
get_threshold(char *arg, int *th)
{
    if (is_intnonneg (arg) && sscanf (arg, "%d", th) == 1)
        return OK;

    return ERROR;
}

void
print_help (void)
{
    char *myport;
    xasprintf (&myport, "%d", WINR_DEF_PORT);

    print_revision (progname, NP_VERSION);

    printf ("Copyright (c) 2022 Fabian Baena <info@samanagroup.com>\n");

    printf ("%s\n", _("Gets CPU usage from a Windows server using WinRM"));

    printf ("\n\n");

    print_usage ();

    printf (UT_HELP_VRSN);
    printf (UT_EXTRA_OPTS);

    printf (UT_HOST_PORT, 'p', myport);

    printf (UT_CREDENTIALS);

    printf (UT_WARN_CRIT);

    printf (UT_CONN_TIMEOUT, DEFAULT_SOCKET_TIMEOUT);

    printf (UT_VERBOSE);

    printf (UT_SUPPORT_SMN);
}



void
print_usage (void)
{
    printf ("%s\n", _("Usage:"));
    printf ("%s  -H <host> -u <username> -P <password> [ -w <warning percentage> ]"
        " [ -c <critical percentage> ] [-p <port>] [-t <timeout>]\n", progname);
}

/* process command-line arguments */
int
process_arguments (int argc, char **argv)
{
    int c;

    int option = 0;
    static struct option longopts[] = {
        STD_LONG_OPTS,
        {"port", required_argument, 0, 'p'},
        {"username", required_argument, 0, 'u'},
        {"password", required_argument, 0, 'P'},
        {0, 0, 0, 0}
    };

    if (argc < 2)
        return ERROR;

    for (c = 1; c < argc; c++)
        if (strcmp ("-to", argv[c]) == 0)
            strcpy (argv[c], "-t");

    while (1) {
        c = getopt_long (argc, argv, "+Vhvt:H:p:u:P:c:w:", longopts, &option);

        if (c == -1 || c == EOF)
            break;

        switch (c) {
        case '?':                                   /* help */
            usage5 ();
        case 'V':                                   /* version */
            print_revision (progname, NP_VERSION);
            exit (STATE_OK);
        case 'h':                                   /* help */
            print_help ();
            exit (STATE_OK);
        case 'v':                                   /* verbose */
            verbose = TRUE;
            break;
        case 't':                                   /* timeout period */
            timeout_interval = parse_timeout_string (optarg);
            break;
        case 'H':                                   /* host */
            if (is_host (optarg) == FALSE)
                usage2 (_("Invalid hostname/address"), optarg);
            server_name = optarg;
            break;
        case 'p':                                   /* port */
            if (is_intpos (optarg)) {
                port = atoi (optarg);
            }
            else {
                usage2 (_("Port number must be a positive integer"), optarg);
            }
            break;
        case 'c':
            if (get_threshold (optarg, &crit) == ERROR) 
                usage2 (_("Critical threshold must be integer or percentage!"), optarg);
            break;
        case 'w':
            if (get_threshold (optarg, &warn) == ERROR)
                usage2 (_("Warning threshold must be integer or percentage!"), optarg);
            break;
        }
    }

    return validate_arguments ();
}

int
validate_arguments (void)
{
    if(username == NULL) {
        username = getenv("WR_USERNAME");
        if(username == NULL) {
        return ERROR;
        }
    }
    if(password == NULL) {
        password = getenv("WR_PASSWORD");
        if(password == NULL) {
        return ERROR;
        }
    }

    if (server_name == NULL)
        return ERROR;
    if (port == -1)                             /* funky, but allows -p to override stray integer in args */
        port = WINR_DEF_PORT;

    xasprintf(&url, "http://%s:%d/wsman", server_name, port);
    if (url == NULL)
        return ERROR;

    return OK;
}
