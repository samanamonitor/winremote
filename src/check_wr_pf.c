/*****************************************************************************
* 
* Nagios check_wr_pf plugin
* 
* License: TBD
* Copyright (c) 2023-2037 Samana Group LLC
* 
* Description:
* 
* This file contains the check_wr_pf plugin
* 
* Connects to a Windows machine with Windows Remote Protocol and pulls
* PageFile usage data from WMI
* 
* 
* 
* 
*****************************************************************************/

const char *progname = "check_wr_pf";
const char *copyright = "2023-2037";
const char *email = "info@samanagroup.com";

#include "config.h"
#include <locale.h>
#include <libintl.h>
#include <unistd.h>
#include <signal.h>
#include "protocol.h"
#include "transport.h"
#include "nagios.h"
#include "xml.h"

#define NAMESPACE "root/cimv2"
#define CHECK_CLASS_NAME "Win32_PageFileUsage"
#define NS_URL "http://schemas.microsoft.com/wbem/wsman/1/wmi/" NAMESPACE "/" CHECK_CLASS_NAME
#define WQL_QUERY "select * FROM " CHECK_CLASS_NAME ""

int port = -1;
char *server_name = NULL;
int verbose = FALSE;
char *username = NULL;
char *password = NULL;
char *url = NULL;
int warn = UNKNOWN_PERCENTAGE_USAGE;
int crit = UNKNOWN_PERCENTAGE_USAGE;

int check_pf (char *url);

typedef struct _wmi_pf {
	xmlNodePtr node;
	char *Caption;
	long AllocatedBaseSize;
	long CurrentUsage;
	long PeakUsage;
	int PercentCurrentUsage;
	int PercentPeakUsage;
} *wmi_pf_t;

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
	result = check_pf (url);

	alarm (0);

	return (result);
}

int
check_pf (char *url)
{
	int result = STATE_OK;
	void *proto=NULL, *wql_ctx=NULL;
	struct timeval tv;
	char *namespace=NAMESPACE;
	char *wql = WQL_QUERY;
	long TotalAllocatedSize = 0, TotalCurrentUsage = 0;
	long TotalPeakUsage = 0, TotalPercentCurrentUsage = 0;
	long elapsed_time;
	char *perfdata_str;
	xmlDocPtr response=NULL, schema=NULL;
	xmlNodeSetPtr nodes = NULL;
	char *xPathExpr;
	wmi_pf_t pf_data = NULL;

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
		fprintf(stderr, "Error\n");
		goto end;
	}

	pf_data = calloc(nodes->nodeNr, sizeof(struct _wmi_pf));
	if(pf_data == NULL) {
		result = STATE_UNKNOWN;
		printf(_("UNKNOWN - Could not reserve memory for disk data.\n"));
		goto end;
	}

	result = STATE_OK;
	for(int i = 0; i < nodes->nodeNr; i++) {
		pf_data[i].node = nodes->nodeTab[i];

		if(!xml_class_get_prop_num(&pf_data[i].AllocatedBaseSize, 
				pf_data[i].node, "AllocatedBaseSize", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}
		TotalAllocatedSize += pf_data[i].AllocatedBaseSize;

		if(!xml_class_get_prop_num(&pf_data[i].CurrentUsage, 
				pf_data[i].node, "CurrentUsage", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}
		TotalCurrentUsage += pf_data[i].CurrentUsage;

		if(!xml_class_get_prop_num(&pf_data[i].PeakUsage, 
				pf_data[i].node, "PeakUsage", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(pf_data[i].AllocatedBaseSize > 0) {
			pf_data[i].PercentCurrentUsage = pf_data[i].CurrentUsage * 100 / pf_data[i].AllocatedBaseSize;
			pf_data[i].PercentPeakUsage = pf_data[i].PeakUsage * 100 / pf_data[i].AllocatedBaseSize;
		} else {
			pf_data[i].PercentCurrentUsage = 100;
		}

		if(!xml_class_get_prop_string(&pf_data[i].Caption,
				pf_data[i].node, "Caption", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}
	}

	if(TotalAllocatedSize < 1) {
		result = STATE_UNKNOWN;
		printf(_("UNKNOWN - Could not estimate the total allocation size of page file\n"));
		goto end;
	}
	TotalPercentCurrentUsage = TotalCurrentUsage  * 100 / TotalAllocatedSize;

	if(TotalPercentCurrentUsage > crit) {
		printf(_("CRITICAL"));
		result = STATE_CRITICAL;
	} else if(TotalPercentCurrentUsage > warn) {
		printf(_("WARNING"));
		result = STATE_WARNING;
	} else {
		printf(_("OK"));
	}
	printf(_(" - Swap Memory: Total: %ldMB - Used: %ldMB (%ld%%)"),
		TotalAllocatedSize, TotalCurrentUsage, TotalPercentCurrentUsage);

	printf(_(" |"));

	perfdata_str = smn_perfdata("used_percent_total", TotalPercentCurrentUsage, "",
  		(warn != UNKNOWN_PERCENTAGE_USAGE), warn,
  		(crit != UNKNOWN_PERCENTAGE_USAGE), crit,
  		1, 0, 1, 100);
	printf(_(" %s"), perfdata_str);
	free(perfdata_str);
	printf(_("\n"));

	for (int i = 0; i < nodes->nodeNr; i++) {
		printf("PageFile at %s, Total, %ldMB, CurrentUsage: %ldMB (%d%%), PeakUsage: %ldMB (%d%%)\n",
			pf_data[i].Caption,
			pf_data[i].AllocatedBaseSize,
			pf_data[i].CurrentUsage,
			pf_data[i].PercentCurrentUsage,
			pf_data[i].PeakUsage,
			pf_data[i].PercentPeakUsage);
	}


	end:
	if(pf_data && nodes) {
		for (int i = 0; i < nodes->nodeNr; i++) {
			if(pf_data[i].Caption) free(pf_data[i].Caption);
		}
		free(pf_data);
	}
	if(nodes) xmlXPathFreeNodeSet(nodes);
	wr_wql_free(&wql_ctx);
	wrprotocol_ctx_free(proto);
	elapsed_time = (double)deltime(tv) / 1.0e6;
	return result;
}
