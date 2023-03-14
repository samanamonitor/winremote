/*****************************************************************************
* 
* Nagios check_wr_uptime plugin
* 
* License: TBD
* Copyright (c) 2023-2037 Samana Group LLC
* 
* Description:
* 
* This file contains the check_wr_uptime plugin
* 
* Connects to a Windows machine with Windows Remote Protocol and pulls
* Uptime data from WMI
* 
* 
* 
* 
*****************************************************************************/

const char *progname = "check_wr_uptime";
const char *copyright = "2023-2037";
const char *email = "info@samanagroup.com";

#include "config.h"
#include <locale.h>
#include <libintl.h>
#include <unistd.h>
#include <signal.h>

#define __USE_XOPEN
#define _GNU_SOURCE
#include <time.h>
#include "protocol.h"
#include "transport.h"
#include "nagios.h"
#include "xml.h"

#define NAMESPACE "root/cimv2"
#define CHECK_CLASS_NAME "Win32_OperatingSystem"
#define NS_URL "http://schemas.microsoft.com/wbem/wsman/1/wmi/" NAMESPACE "/" CHECK_CLASS_NAME
#define WQL_QUERY "select * FROM " CHECK_CLASS_NAME "";

int legacy = 0;
int port = -1;
char *server_name = NULL;
int verbose = FALSE;
char *username = NULL;
char *password = NULL;
char *url = NULL;
int warn = UNKNOWN_VALUE;
int crit = UNKNOWN_VALUE;

int check_uptime (char *url);

int
main (int argc, char **argv)
{
	int result = STATE_UNKNOWN;

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);

	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);

	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/* initialize alarm signal handling */
	signal (SIGALRM, timeout_alarm_handler);

	alarm (timeout_interval);

	/* ssh_connect exits if error is found */
	result = check_uptime (url);

	alarm (0);

	return (result);
}

int
check_uptime (char *url)
{
	int result = STATE_OK;
	void *proto=NULL, *wql_ctx=NULL;
	struct timeval tv;
	char *namespace=NAMESPACE;
	char *wql = WQL_QUERY;
	char *LastBootUpTime = NULL, *xPathExpr = NULL;
	xmlDocPtr response=NULL, schema=NULL;
	xmlNodeSetPtr nodes = NULL;
	long elapsed_time;
	struct tm LastBootUpTime_tm;
	time_t BootUpHours = 0;
	time_t tzh, tzm, LastBootUpTime_time;
	time_t current_time;
	char *perfdata_str;
	char *p;

	gettimeofday(&tv, NULL);

	proto = wrprotocol_ctx_new();
	if(proto == NULL) {
		result = STATE_UNKNOWN;
		goto end;
	}
	if(!wrprotocol_ctx_init(proto, username, password, url, WR_MECH_NTLM)) {
		result = STATE_UNKNOWN;
		goto end;
	}

	wql_ctx = wr_wql_new(proto, namespace, wql);
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
	if(!xml_find_all(&nodes, response, xPathExpr, "p", NS_URL)) {
		result = STATE_UNKNOWN;
		fprintf(stderr, "UNKNOWN - Invalid response from server.\n");
		goto end;
	}
	if(nodes->nodeNr < 1) {
		result = STATE_UNKNOWN;
		fprintf(stderr, "UNKNOWN - Invalid response from server.\n");
		goto end;
	}

	if(!xml_class_get_prop_string(&LastBootUpTime, nodes->nodeTab[0], "LastBootUpTime", schema)) {
		result = STATE_UNKNOWN;
		printf(_("UNKNOWN - Schema from server was empty"));
		goto end;
	}

	current_time = time(NULL);

	p = strptime(LastBootUpTime, "%FT%T", &LastBootUpTime_tm);
	while(*p && *p != '+' && *p != '-') p++;
	sscanf(p, "%ld:%ld", &tzh, &tzm);
	if(tzh < 0) tzm *= -1;
	LastBootUpTime_time = mktime(&LastBootUpTime_tm) - (tzh*60*60 + tzm*60);
	BootUpHours = (current_time - LastBootUpTime_time) / 60 / 60;

	if(BootUpHours > crit) {
		printf(_("CRITICAL"));
		result = STATE_CRITICAL;
	} else if(BootUpHours > warn) {
		printf(_("WARNING"));
		result = STATE_WARNING;
	} else {
		printf(_("OK"));
		result = STATE_OK;
	}
	printf(_(" - Uptime of server is %ld Hours"), BootUpHours);

	printf(" | ");

	perfdata_str = smn_perfdata("uptime", current_time - LastBootUpTime_time, "",
		(warn != UNKNOWN_VALUE), warn,
		(crit != UNKNOWN_VALUE), crit,
		0, 0, 0, 0);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	printf(_("\n"));

	end:
	if(nodes) xmlXPathFreeNodeSet(nodes);
	if(LastBootUpTime) free(LastBootUpTime);
	wr_wql_free(&wql_ctx);
	wrprotocol_ctx_free(proto);
	elapsed_time = (double)deltime(tv) / 1.0e6;
	return result;
}
