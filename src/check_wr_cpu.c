/*****************************************************************************
* 
* Nagios check_wr_cpu plugin
* 
* License: TBD
* Copyright (c) 2023-2037 Samana Group LLC
* 
* Description:
* 
* This file contains the check_wr_cpu plugin
* 
* Connects to a Windows machine with Windows Remote Protocol and pulls
* CPU usage data from WMI
* 
* 
* 
* 
*****************************************************************************/

const char *progname = "check_wr_cpu";
const char *copyright = "2023-2037";
const char *email = "info@samanagroup.com";

#include "config.h"
#include <locale.h>
#include <libintl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include "protocol.h"
#include "transport.h"
#include "nagios.h"
#include "xml.h"

#define NAMESPACE "root/cimv2"
#define CHECK_CLASS_NAME "Win32_PerfFormattedData_Counters_ProcessorInformation"
#define NS_URL "http://schemas.microsoft.com/wbem/wsman/1/wmi/" NAMESPACE "/" CHECK_CLASS_NAME
#define WQL_QUERY "select * FROM " CHECK_CLASS_NAME " WHERE NAME='_total'";

int legacy = 0;
int port = -1;
char *server_name = NULL;
int verbose = FALSE;
char *username = NULL;
char *password = NULL;
char *url = NULL;
int warn = UNKNOWN_PERCENTAGE_USAGE;
int crit = UNKNOWN_PERCENTAGE_USAGE;

int check_cpu (char *url);
char *perfdata (const char *label, long int val, const char *uom, int warnp, long int warn, int critp, long int crit, int minp, long int minv, int maxp, long int maxv);

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
	result = check_cpu (url);

	alarm (0);

	return (result);
}

int
check_cpu (char *url)
{
	int result = STATE_OK;
	void *proto=NULL, *wql_ctx=NULL;
	struct timeval tv;
	char *namespace=NAMESPACE;
	char *wql = WQL_QUERY;
	long PercentProcessorTime, PercentPrivilegedTime;
	long PercentInterruptTime, PercentIdleTime, PercentUserTime;
	xmlDocPtr response=NULL, schema=NULL;
	xmlNodeSetPtr nodes = NULL;
	long elapsed_time;
	char *perfdata_str, *xPathExpr = NULL;;

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

	if(!xml_class_get_prop_num(&PercentProcessorTime, 
			nodes->nodeTab[0], "PercentProcessorTime", schema)) {
		result = STATE_UNKNOWN;
		goto end;
	}

	if(PercentProcessorTime > crit) {
		printf(_("CRITICAL"));
		result = STATE_CRITICAL;
	} else if(PercentProcessorTime > warn) {
		printf(_("WARNING"));
		result = STATE_WARNING;
	} else {
		printf(_("OK"));
	}
	printf(_(" - CPU Usage %ld%%"), PercentProcessorTime);

	printf(_(" |"));

	if(legacy == 1) {
		perfdata_str = perfdata("cpuLoad", PercentProcessorTime, "",
			(warn != UNKNOWN_PERCENTAGE_USAGE), warn,
			(crit != UNKNOWN_PERCENTAGE_USAGE), crit,
			1, 0, 1, 100);
		printf(_(" %s"), perfdata_str);
		free(perfdata_str);
		printf(_("\n"));
		goto end;
	}

	perfdata_str = smn_perfdata("load", PercentProcessorTime, "",
		(warn != UNKNOWN_PERCENTAGE_USAGE), warn,
		(crit != UNKNOWN_PERCENTAGE_USAGE), crit,
		1, 0, 1, 100);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	if(!xml_class_get_prop_num(&PercentIdleTime, 
			nodes->nodeTab[0], "PercentIdleTime", schema)) {
		result = STATE_UNKNOWN;
		goto end;
	}
	perfdata_str = smn_perfdata("idle_time_percent", PercentIdleTime, "",
		0, 0, 0, 0, 1, 0, 1, 100);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	if(!xml_class_get_prop_num(&PercentUserTime, 
			nodes->nodeTab[0], "PercentUserTime", schema)) {
		result = STATE_UNKNOWN;
		goto end;
	}
	perfdata_str = smn_perfdata("user_time_percent", PercentUserTime, "",
		0, 0, 0, 0, 1, 0, 1, 100);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	if(!xml_class_get_prop_num(&PercentPrivilegedTime, 
			nodes->nodeTab[0], "PercentPrivilegedTime", schema)) {
		result = STATE_UNKNOWN;
		goto end;
	}
	perfdata_str = smn_perfdata("privileged_time_percent", PercentPrivilegedTime, "",
		0, 0, 0, 0, 1, 0, 1, 100);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	if(!xml_class_get_prop_num(&PercentInterruptTime, 
			nodes->nodeTab[0], "PercentInterruptTime", schema)) {
		result = STATE_UNKNOWN;
		goto end;
	}
	perfdata_str = smn_perfdata("interrupt_time_percent", PercentInterruptTime, "",
		0, 0, 0, 0, 1, 0, 1, 100);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);

	printf(_("\n"));

	end:
	wr_wql_free(&wql_ctx);
	wrprotocol_ctx_free(proto);
	elapsed_time = (double)deltime(tv) / 1.0e6;
	return result;
}
