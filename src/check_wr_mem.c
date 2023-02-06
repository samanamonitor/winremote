/*****************************************************************************
* 
* Nagios check_wr_mem plugin
* 
* License: TBD
* Copyright (c) 2023-2037 Samana Group LLC
* 
* Description:
* 
* This file contains the check_wr_mem plugin
* 
* Connects to a Windows machine with Windows Remote Protocol and pulls
* RAM usage data from WMI
* 
* 
* 
* 
*****************************************************************************/

const char *progname = "check_wr_mem";
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
#define CHECK_CLASS_NAME "Win32_OperatingSystem"
#define NS_URL "http://schemas.microsoft.com/wbem/wsman/1/wmi/" NAMESPACE "/" CHECK_CLASS_NAME
#define WQL_QUERY "select * FROM " CHECK_CLASS_NAME "";

int port = -1;
char *server_name = NULL;
int verbose = FALSE;
char *username = NULL;
char *password = NULL;
char *url = NULL;
int warn = UNKNOWN_PERCENTAGE_USAGE;
int crit = UNKNOWN_PERCENTAGE_USAGE;

int check_mem (char *url);

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
	result = check_mem (url);

	alarm (0);

	return (result);
}

int
check_mem (char *url)
{
	int result = STATE_OK;
	void *proto=NULL, *wql_ctx=NULL;
	struct timeval tv;
	char *namespace=NAMESPACE;
	char *wql = WQL_QUERY;
	long TotalVisibleMemorySize, FreePhysicalMemory;
	long UsedPhysicalMemory, PercentMemoryUsed, PercentMemoryFree;
	xmlDocPtr response=NULL, schema=NULL;
	xmlNodeSetPtr nodes = NULL;
	long elapsed_time;
	char *perfdata_str, *xPathExpr = NULL;

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

	if(!xml_class_get_prop_num(&TotalVisibleMemorySize, 
			nodes->nodeTab[0], "TotalVisibleMemorySize", schema)) {
		result = STATE_UNKNOWN;
		goto end;
	}

	if(!xml_class_get_prop_num(&FreePhysicalMemory, 
			nodes->nodeTab[0], "FreePhysicalMemory", schema)) {
		result = STATE_UNKNOWN;
		goto end;
	}

	UsedPhysicalMemory = TotalVisibleMemorySize - FreePhysicalMemory;
	PercentMemoryUsed = UsedPhysicalMemory * 100 / TotalVisibleMemorySize;
	PercentMemoryFree = 100 - PercentMemoryUsed;

	if(PercentMemoryUsed > crit) {
		printf(_("CRITICAL"));
	} else if(PercentMemoryUsed > warn) {
		printf(_("WARNING"));
	} else {
		printf(_("OK"));
	}
	printf(_(" - Physical Memory: Total: %ldMB - Used: %ldMB (%ld%%) - Free %ldMB (%ld%%)"), 
	TotalVisibleMemorySize / 1024, 
	UsedPhysicalMemory / 1024, PercentMemoryUsed,
	FreePhysicalMemory / 1024, PercentMemoryFree);

	perfdata_str = smn_perfdata("PercentMemoryUsed", PercentMemoryUsed, "",
		(warn != UNKNOWN_PERCENTAGE_USAGE), warn,
		(crit != UNKNOWN_PERCENTAGE_USAGE), crit,
		1, 0, 1, 100);
	printf(_(" | %s"), perfdata_str);
	free(perfdata_str);
	printf(_("\n"));

  end:
  wr_wql_free(&wql_ctx);
  wrprotocol_ctx_free(proto);
	elapsed_time = (double)deltime(tv) / 1.0e6;
  return result;
}
