/*****************************************************************************
* 
* Nagios check_wr_log plugin
* 
* License: TBD
* Copyright (c) 2023-2037 Samana Group LLC
* 
* Description:
* 
* This file contains the check_wr_log plugin
* 
* Connects to a Windows machine with Windows Remote Protocol and pulls
* Logs data from WMI
* 
* 
* 
* 
*****************************************************************************/

const char *progname = "check_wr_log";
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
#define CHECK_CLASS_NAME "Win32_NTLogEvent"
#define NS_URL "http://schemas.microsoft.com/wbem/wsman/1/wmi/" NAMESPACE "/" CHECK_CLASS_NAME
#define WQL_QUERY "SELECT * FROM " CHECK_CLASS_NAME " WHERE TimeGenerated > '%s' and EventType <= %d and Logfile = '%s'"
#define MAX_EVENTS_PRINT 10
#define EXCEPTION_SEPARATOR '|'
#define EXC_VALUE_SEPARATOR ','

typedef struct _log_exception_set *log_exception_set_t;
typedef struct _wmi_log *wmi_log_t;

int legacy = 0;
int port = -1;
char *server_name = NULL;
int verbose = FALSE;
char *username = NULL;
char *password = NULL;
char *url = NULL;
char *logname = NULL;
int warn = UNKNOWN_VALUE;
int crit = UNKNOWN_VALUE;
int log_minutes = 5;
struct _log_exception_set le;

int check_log (char *url);
int validate_arguments_log (void);
int process_arguments_log (int argc, char **argv);
int is_host (const char *);
uint32_t process_exceptions(log_exception_set_t l, const char *e);
uint32_t is_exception(wmi_log_t event, log_exception_set_t le);
void print_help_log (void);

typedef struct _log_exception {
	int32_t EventCode;
	char *r_Message;
	char *r_SourceName;
	regex_t rx_SourceName;
	regex_t rx_Message;
} *log_exception_t;

typedef struct _log_exception_set {
	uint32_t exceptionNr;
	uint32_t exceptionMax;
	log_exception_t exceptionTab;
} *log_exception_set_t;

typedef struct _wmi_log {
	xmlNodePtr node;
	uint64_t EventCode;
	char *Message;
	char *SourceName;
	char *Type;
	uint64_t EventType;
	uint32_t is_exception;
} *wmi_log_t;

struct event_count {
	int Error;
	int Warning;
	int AuditSuccess;
	int AuditFailures;
	int Total;
};

int
main (int argc, char **argv)
{
	int result = STATE_UNKNOWN;

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);

	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);

	if (process_arguments_log (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/* initialize alarm signal handling */
	signal (SIGALRM, timeout_alarm_handler);

	alarm (timeout_interval);

	/* ssh_connect exits if error is found */
	result = check_log (url);

	alarm (0);

	return (result);
}

int
check_log (char *url)
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
	char TimeGenerated[128];
	time_t current_time;
	struct tm current_time_tm;
	wmi_log_t log_data = NULL;
	struct event_count ec = { 0 };

	gettimeofday(&tv, NULL);
	current_time = time(NULL) - log_minutes * 60;
	gmtime_r(&current_time, &current_time_tm);
	strftime(TimeGenerated, 128, "%Y%m%d%H%M%S.000000Z", &current_time_tm);

	proto = wrprotocol_ctx_new();
	if(proto == NULL) {
		result = STATE_UNKNOWN;
		goto end;
	}
	if(!wrprotocol_ctx_init(proto, username, password, url, WR_MECH_NTLM)) {
		result = STATE_UNKNOWN;
		goto end;
	}

	xasprintf(&wql, WQL_QUERY, TimeGenerated, 2, logname);
	wql_ctx = wr_wql_new(proto, namespace, wql);
	free(wql);
	if(wql_ctx == NULL) {
		result = STATE_UNKNOWN;
		goto end;
	}

	if(!wr_wql_run(wql_ctx)) {
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

	log_data = calloc(nodes->nodeNr, sizeof(struct _wmi_log));
	if(log_data == NULL && nodes->nodeNr > 0) {
		result = STATE_UNKNOWN;
		printf(_("UNKNOWN - Could not reserve memory for log data.\n"));
		goto end;
	}

	result = STATE_OK;
	for(int i = 0; i < nodes->nodeNr; i++) {
		log_data[i].node = nodes->nodeTab[i];

		if(!xml_class_get_prop_num(&log_data[i].EventCode, 
				log_data[i].node, "EventCode", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(!xml_class_get_prop_num(&log_data[i].EventType, 
				log_data[i].node, "EventType", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(!xml_class_get_prop_string(&log_data[i].Message, 
				log_data[i].node, "Message", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(!xml_class_get_prop_string(&log_data[i].SourceName, 
				log_data[i].node, "SourceName", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(!xml_class_get_prop_string(&log_data[i].Type, 
				log_data[i].node, "Type", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		log_data[i].is_exception = is_exception(&log_data[i], &le);

		if(!log_data[i].is_exception) {
			ec.Total++;
			switch(log_data[i].EventType) {
			case 1:
				ec.Error++;
				break;
			case 2:
				ec.Warning++;
				break;
			case 4:
				ec.AuditSuccess++;
				break;
			case 5:
				ec.AuditFailures++;
				break;
			}			
		}
	}

	noevents:
	if(ec.Total > crit) {
		result = STATE_CRITICAL;
		printf(_("CRITICAL"));
	} else if (ec.Total > warn) {
		result = STATE_WARNING;
		printf(_("WARNING"));
	} else {
		result = STATE_OK;
		printf(_("OK"));
	}

	printf(_(" - Error or Warning Events=%d"), ec.Total);

	printf(_(" |"));
	perfdata_str = smn_perfdata("error",
		ec.Error, "",
		(warn != UNKNOWN_VALUE), warn,
		(crit != UNKNOWN_VALUE), crit,
		0, 0, 0, 0);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	perfdata_str = smn_perfdata("warning",
		ec.Warning, "",
		(warn != UNKNOWN_VALUE), warn,
		(crit != UNKNOWN_VALUE), crit,
		0, 0, 0, 0);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	perfdata_str = smn_perfdata("audit_success",
		ec.AuditSuccess, "",
		(warn != UNKNOWN_VALUE), warn,
		(crit != UNKNOWN_VALUE), crit,
		0, 0, 0, 0);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	perfdata_str = smn_perfdata("audit_failure",
		ec.AuditFailures, "",
		(warn != UNKNOWN_VALUE), warn,
		(crit != UNKNOWN_VALUE), crit,
		0, 0, 0, 0);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	printf(_("\n"));

	int printed = 0;
	for (int i = 0; i < nodes->nodeNr && printed < MAX_EVENTS_PRINT; i++) {
		if(log_data[i].is_exception) continue;
		printf("   %s - %ld - %.50s - %.80s\n",
			log_data[i].Type,
			log_data[i].EventCode,
			log_data[i].SourceName,
			log_data[i].Message);
		printed++;
	}
	if(printed >= MAX_EVENTS_PRINT) {
		printf("Truncated... (Showing only %d events)\n", printed);
	}

	end:
	if(log_data && nodes) {
		for (int i = 0; i < nodes->nodeNr; i++) {
			if(log_data[i].Message) free(log_data[i].Message);
			if(log_data[i].SourceName) free(log_data[i].SourceName);
			if(log_data[i].Type) free(log_data[i].Type);
		}
		free(log_data);
	}
	if(nodes) xmlXPathFreeNodeSet(nodes);
	wr_wql_free(&wql_ctx);
	wrprotocol_ctx_free(proto);
	elapsed_time = (double)deltime(tv) / 1.0e6;
	return result;
}

uint32_t
is_exception(wmi_log_t event, log_exception_set_t le)
{
	for (int i = 0; i < le->exceptionNr; i++) {
		regex_t r;
		regmatch_t pmatch[1];
		log_exception_t exc_item = &(le->exceptionTab[i]);

		if(le->exceptionTab[i].EventCode == 0 || event->EventCode == le->exceptionTab[i].EventCode) {
			if(exc_item->r_SourceName && 
					regexec(&exc_item->rx_SourceName, 
						event->SourceName, 1, pmatch, 0) == REG_NOMATCH) {
				continue;
			}
			if(exc_item->r_Message &&
					regexec(&exc_item->rx_Message,
						event->Message, 1, pmatch, 0) == REG_NOMATCH) {
				continue;
			}

			return 1;
		}
	}
	return 0;
}

/* process command-line arguments */
int
process_arguments_log (int argc, char **argv)
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
	le.exceptionNr = 0;
	le.exceptionMax = 0;
	le.exceptionTab = NULL;

	if (argc < 2)
		return ERROR;

	for (c = 1; c < argc; c++)
		if (strcmp ("-to", argv[c]) == 0)
			strcpy (argv[c], "-t");

	while (1) {
		c = getopt_long (argc, argv, "+Vhvt:H:p:u:P:c:w:l:e:m:", longopts, &option);

		if (c == -1 || c == EOF)
			break;

		switch (c) {
		case '?':                                   /* help */
			usage5 ();
		case 'V':                                   /* version */
			print_revision (progname, VERSION);
			exit (STATE_OK);
		case 'h':                                   /* help */
			print_help_log ();
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
		case 'l':
			logname = optarg;
			break;
		case 'e':
			process_exceptions(&le, optarg);
			break;
		case 'm':
			if (is_intpos (optarg)) {
				log_minutes = atoi(optarg);
			}
			break;
		}
	}

	return validate_arguments_log ();
}

void
free_exception_set(log_exception_set_t l)
{
	if(l == NULL) return;

	for (int i = 0; i < l->exceptionNr; i++) {
		if(l->exceptionTab[i].r_Message) 
			regfree(&(l->exceptionTab[i].rx_Message));
		if(l->exceptionTab[i].r_SourceName) 
			regfree(&(l->exceptionTab[i].rx_SourceName));
		FREE_NULL(l->exceptionTab[i].r_Message);
		FREE_NULL(l->exceptionTab[i].r_SourceName);
		l->exceptionTab[i].EventCode = 0;
	}
	l->exceptionMax = 0;
	l->exceptionNr = 0;
	if(l->exceptionTab) free(l->exceptionTab);
	l->exceptionTab = NULL;
}

uint32_t
process_exceptions(log_exception_set_t l, const char *e)
	{
	uint16_t EventCode;
	char *p;
	char *msg_start, *msg_end;
	char *src_start, *src_end;

	if(l == NULL || e == NULL) return 0;

	l->exceptionNr = 0;
	l->exceptionMax = 0;
	l->exceptionTab = NULL;

	while(*e) {
		log_exception_t exc_item;
		if(l->exceptionNr == l->exceptionMax) {
			l->exceptionMax += 10;
			void *temp = realloc(l->exceptionTab, 
				l->exceptionMax * sizeof(*(l->exceptionTab)));
			if(temp == NULL) {
				goto error;
			}
			l->exceptionTab = temp;
		}

		exc_item = &(l->exceptionTab[l->exceptionNr]);
		exc_item->EventCode = strtol(e, &src_start, 10);
		if(errno == EINVAL || errno == ERANGE) {
			goto error;
		}

		if(*src_start == EXC_VALUE_SEPARATOR || 
				*src_start == EXCEPTION_SEPARATOR || 
				*src_start == '\0') {
			if(*src_start == EXC_VALUE_SEPARATOR) src_start++;
		} else {
			goto error;
		}

		src_end = src_start;
		while(*src_end != '\0' && 
				*src_end != EXC_VALUE_SEPARATOR && 
				*src_end != EXCEPTION_SEPARATOR) 
			src_end++;
		msg_start = src_end;

		if(*msg_start == EXC_VALUE_SEPARATOR) msg_start++;
		msg_end = msg_start;

		while(*msg_end != '\0' && 
				*msg_end != EXC_VALUE_SEPARATOR && 
				*msg_end != EXCEPTION_SEPARATOR)
			msg_end++;
		if(*msg_end == EXC_VALUE_SEPARATOR) {
			goto error;
		}

		if(src_end > src_start) {
			exc_item->r_SourceName = strndup(src_start, src_end-src_start);
			if(regcomp(&exc_item->rx_SourceName, exc_item->r_SourceName, REG_ICASE) != 0)
				goto error;
		} else {
			exc_item->r_SourceName = NULL;
		}

		if(msg_end > msg_start) {
			exc_item->r_Message = strndup(msg_start, msg_end-msg_start);
			if(regcomp(&exc_item->rx_Message, exc_item->r_Message, REG_ICASE) != 0)
				goto error;
		} else {
			exc_item->r_Message = NULL;
		}

		l->exceptionNr++;

		e = msg_end;
		if(*e == EXCEPTION_SEPARATOR) e++;
	}
	end:
	return 1;

	error:
	fprintf(stderr, "Error\n");
	free_exception_set(l);
	return 0;
}

int
validate_arguments_log (void)
{
	if(username == NULL || strlen(username) == 0) {
		username = getenv("WR_USERNAME");
		if(username == NULL) {
			return ERROR;
		}
	}
	if(password == NULL || strlen(password) == 0) {
		password = getenv("WR_PASSWORD");
		if(password == NULL) {
			return ERROR;
		}
	}

	if (server_name == NULL)
		return ERROR;
	if (port == -1)                             /* funky, but allows -p to override stray integer in args */
		port = WINR_DEF_PORT;

	if (logname == NULL) {
		return ERROR;
	}

	xasprintf(&url, "http://%s:%d/wsman", server_name, port);
	if (url == NULL)
		return ERROR;

	return OK;
}

void
print_help_log (void)
{
    char *myport;
    xasprintf (&myport, "%d", WINR_DEF_PORT);

    print_revision (progname, VERSION);

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
