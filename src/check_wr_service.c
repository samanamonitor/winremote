/*****************************************************************************
* 
* Nagios check_wr_service plugin
* 
* License: TBD
* Copyright (c) 2023-2037 Samana Group LLC
* 
* Description:
* 
* This file contains the check_wr_service plugin
* 
* Connects to a Windows machine with Windows Remote Protocol and pulls
* Services data from WMI
* 
* 
* 
* 
*****************************************************************************/

const char *progname = "check_wr_service";
const char *copyright = "2023-2037";
const char *email = "info@samanagroup.com";

#include "config.h"
#include <locale.h>
#include <libintl.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include "protocol.h"
#include "transport.h"
#include "nagios.h"
#include "xml.h"
#include <regex.h>

#define NAMESPACE "root/cimv2"
#define CHECK_CLASS_NAME "Win32_Service"
#define NS_URL "http://schemas.microsoft.com/wbem/wsman/1/wmi/" NAMESPACE "/" CHECK_CLASS_NAME
#define WQL_QUERY "SELECT * FROM " CHECK_CLASS_NAME ""
#define MAX_EVENTS_PRINT 10
#define EXCEPTION_SEPARATOR ';'
#define EXC_VALUE_SEPARATOR ','

int legacy = 0;
int port = -1;
char *server_name = NULL;
int verbose = FALSE;
char *username = NULL;
char *password = NULL;
char *url = NULL;
char *exclude = NULL, *include = NULL;
regex_t r_exclude, r_include;
int running = 0, stopped = 0;
int warn = UNKNOWN_VALUE;
int crit = UNKNOWN_VALUE;

int check_service (char *url);
int validate_arguments_service (void);
int process_arguments_service (int argc, char **argv);
uint32_t is_excluded(char *service_name);
uint32_t is_included(char *service_name);
void print_help_service (void);

int
main (int argc, char **argv)
{
	int result = STATE_UNKNOWN;

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);

	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);

	if (process_arguments_service (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/* initialize alarm signal handling */
	signal (SIGALRM, timeout_alarm_handler);

	alarm (timeout_interval);

	/* ssh_connect exits if error is found */
	result = check_service (url);

	alarm (0);

	return (result);
}

int
check_service (char *url)
{
	int result = STATE_OK;
	void *proto=NULL, *wql_ctx=NULL;
	struct timeval tv;
	char *namespace=NAMESPACE;
	char *wql = WQL_QUERY;
	long elapsed_time;
	char *perfdata_str;
	xmlDocPtr response=NULL, schema=NULL;
	xmlNodeSetPtr nodes = NULL;
	char *xPathExpr;
	char *addl = NULL, *addltemp = NULL;

	gettimeofday(&tv, NULL);

	proto = wrprotocol_ctx_new();
	if(proto == NULL) {
		printf(_("UNKNOWN - Unable to create protocol context.\n"));
		result = STATE_UNKNOWN;
		goto end;
	}
	if(!wrprotocol_ctx_init(proto, username, password, url, WR_MECH_NTLM)) {
		printf(_("UNKNOWN - Unable to initialize protocol context.\n"));
		result = STATE_UNKNOWN;
		goto end;
	}

	wql_ctx = wr_wql_new(proto, namespace, wql);
	if(wql_ctx == NULL) {
		result = STATE_UNKNOWN;
		goto end;
	}

	if(!wr_wql_run(wql_ctx)) {
		printf(_("UNKNOWN - Run WQL command.\n"));
		printf(_("%s\n"), WQL_QUERY);
		result = STATE_UNKNOWN;
		goto end;
	}

	response = wr_wql_response_toxml(wql_ctx);
	if(response == NULL) {
		result = STATE_UNKNOWN;
		printf(_("UNKNOWN - Response from server was empty"));
		goto end;
	}

	schema = wr_wql_schema_toxml(wql_ctx);
	if(schema == NULL) {
		result = STATE_UNKNOWN;
		printf(_("UNKNOWN - Schema from server was empty"));
		goto end;
	}

	xPathExpr = "//p:" CHECK_CLASS_NAME;
	xml_find_all(&nodes, response, xPathExpr, "p", NS_URL);

	result = STATE_OK;
	for(int i = 0; i < nodes->nodeNr; i++) {
		char *svc_name;
		char *svc_displayname;
		char *svc_state;

		if(!xml_class_get_prop_string(&svc_name,
				nodes->nodeTab[i], "Name", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(!xml_class_get_prop_string(&svc_displayname,
				nodes->nodeTab[i], "DisplayName", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(!xml_class_get_prop_string(&svc_state,
				nodes->nodeTab[i], "State", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(is_included(svc_name) || is_included(svc_displayname)) {
			if(!is_excluded(svc_name) && !is_excluded(svc_displayname)) {
				if(!strcmp(svc_state, "Running")) {
					running ++;
				} else {
					xasprintf(&addltemp, "%s** %s - %s(%s)\n", addl == NULL? "" : addl,
						svc_state, svc_displayname, svc_name);
					if(addl) free(addl);
					addl = addltemp;
					stopped ++;
				}
			}
		}
		free(svc_name);
		free(svc_displayname);
		free(svc_state);
	}

	if(stopped > crit) {
		result = STATE_CRITICAL;
		printf(_("CRITICAL"));
	} else if (stopped > warn) {
		result = STATE_WARNING;
		printf(_("WARNING"));
	} else {
		result = STATE_OK;
		printf(_("OK"));
	}

	printf(_(" - Services running=%d stopped=%d"), running, stopped);

	printf(_(" |"));

	perfdata_str = smn_perfdata("stopped", stopped, "",
		(warn != UNKNOWN_VALUE), warn,
		(crit != UNKNOWN_VALUE), crit,
		0, 0, 0, 0);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	perfdata_str = smn_perfdata("running", running, "",
		(warn != UNKNOWN_VALUE), warn,
		(crit != UNKNOWN_VALUE), crit,
		0, 0, 0, 0);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	printf(_("\n"));

	printf("%s", addl == NULL ? "" : addl);

	end:
	if(addl) free(addl);
	if(nodes) xmlXPathFreeNodeSet(nodes);
	wr_wql_free(&wql_ctx);
	wrprotocol_ctx_free(proto);
	elapsed_time = (double)deltime(tv) / 1.0e6;
	return result;
}

uint32_t is_excluded(char *service_name)
{
	regmatch_t pmatch[1];
	if(exclude == NULL || regexec(&r_exclude, service_name, 1, pmatch, 0) == REG_NOMATCH) {
		return 0;
	}
	return 1;
}

uint32_t is_included(char *service_name)
{
	regmatch_t pmatch[1];
	if(include == NULL) return 1;
	if(regexec(&r_include, service_name, 1, pmatch, 0) == REG_NOMATCH) {
		return 0;
	}
	return 1;
}

/* process command-line arguments */
int
process_arguments_service (int argc, char **argv)
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
		c = getopt_long (argc, argv, "+Vhvt:H:p:u:P:c:w:e:i:", longopts, &option);

		if (c == -1 || c == EOF)
			break;

		switch (c) {
		case '?':                                   /* help */
			usage5 ();
		case 'V':                                   /* version */
			print_revision (progname, VERSION);
			exit (STATE_OK);
		case 'h':                                   /* help */
			print_help_service ();
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
		case 'u':
			username = optarg;
			break;
		case 'P':
			password = optarg;
			break;
		case 'e':
			exclude  = optarg;
			break;
		case 'i':
			include = optarg;
			break;
		}
	}

	return validate_arguments_service ();
}

int
validate_arguments_service (void)
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

	if(exclude != NULL) {
		if(regcomp(&r_exclude, exclude, REG_ICASE | REG_EXTENDED) != 0) {
			return ERROR;
		}
	}

	if(include != NULL) {
		if(regcomp(&r_include, include, REG_ICASE | REG_EXTENDED) != 0) {
			return ERROR;
		}
	}

	return OK;
}

void
print_help_service (void)
{
    char *myport;
    xasprintf (&myport, "%d", WINR_DEF_PORT);

    print_revision (progname, VERSION);

    printf ("Copyright (c) 2022 Fabian Baena <info@samanagroup.com>\n");

    printf ("%s\n", _("Gets Service status from a Windows server using WinRM"));

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
