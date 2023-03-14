/*****************************************************************************
* 
* Nagios check_wr_disk plugin
* 
* License: TBD
* Copyright (c) 2023-2037 Samana Group LLC
* 
* Description:
* 
* This file contains the check_wr_disk plugin
* 
* Connects to a Windows machine with Windows Remote Protocol and pulls
* Disk usage data from WMI
* 
* 
* 
* 
*****************************************************************************/

const char *progname = "check_wr_disk";
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
#define CHECK_CLASS_NAME "Win32_LogicalDisk"
#define NS_URL "http://schemas.microsoft.com/wbem/wsman/1/wmi/" NAMESPACE "/" CHECK_CLASS_NAME
#define WQL_QUERY "select * FROM " CHECK_CLASS_NAME " WHERE DriveType = 3"

int legacy = 0;
int port = -1;
char *server_name = NULL;
int verbose = FALSE;
char *username = NULL;
char *password = NULL;
char *url = NULL;
int warn = UNKNOWN_PERCENTAGE_USAGE;
int crit = UNKNOWN_PERCENTAGE_USAGE;

int check_disk (char *url);
char *perfdata (const char *label, long int val, const char *uom, int warnp, long int warn, int critp, long int crit, int minp, long int minv, int maxp, long int maxv);

typedef struct _wmi_disk {
	xmlNodePtr node;
	char *Disk_Caption;
	char *Disk_Name;
	long Disk_FreeSpace;
	long Disk_UsedSpace;
	long Disk_Size;
	uint32_t Disk_PercentUsed;
	char *alert;
} *wmi_disk_t;

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
	result = check_disk (url);

	alarm (0);

	return (result);
}

int
check_disk (char *url)
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
	wmi_disk_t disk_data = NULL;

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

	disk_data = calloc(nodes->nodeNr, sizeof(struct _wmi_disk));
	if(disk_data == NULL) {
		result = STATE_UNKNOWN;
		printf(_("UNKNOWN - Could not reserve memory for disk data.\n"));
		goto end;
	}

	result = STATE_OK;
	for(int i = 0; i < nodes->nodeNr; i++) {
		disk_data[i].node = nodes->nodeTab[i];
		disk_data[i].alert = "";

		if(!xml_class_get_prop_num(&disk_data[i].Disk_FreeSpace, 
				disk_data[i].node, "FreeSpace", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}
		disk_data[i].Disk_FreeSpace /= (1024 * 1024);

		if(!xml_class_get_prop_num(&disk_data[i].Disk_Size, 
				disk_data[i].node, "Size", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}
		disk_data[i].Disk_Size /= (1024 * 1024);

		if(!xml_class_get_prop_string(&disk_data[i].Disk_Caption,
				disk_data[i].node, "Caption", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		if(!xml_class_get_prop_string(&disk_data[i].Disk_Name,
				disk_data[i].node, "Name", schema)) {
			result = STATE_UNKNOWN;
			goto end;
		}

		disk_data[i].Disk_UsedSpace = disk_data[i].Disk_Size - disk_data[i].Disk_FreeSpace;

		if(disk_data[i].Disk_Size > 0) {
			disk_data[i].Disk_PercentUsed = disk_data[i].Disk_UsedSpace 
				* 100 / disk_data[i].Disk_Size;
		} else {
			disk_data[i].Disk_PercentUsed = 100;
		}

		if(disk_data[i].Disk_PercentUsed > crit) {
			result = STATE_CRITICAL;
			disk_data[i].alert = "*** ";

		} else if (disk_data[i].Disk_PercentUsed > warn) {
			result = result < STATE_WARNING ? STATE_WARNING : result;
			disk_data[i].alert = "*** ";
		}
	}

	if(result == STATE_CRITICAL) {
		printf(_("CRITICAL"));
	} else if (result == STATE_WARNING) {
		printf(_("WARNING"));
	} else if (result == STATE_OK) {
		printf(_("OK"));
	} else {
		printf(_("UNKNOWN"));
	}

	printf(_(" | "));
	for (int i = 0; i < nodes->nodeNr; i++) {
		char *label;
		if(legacy==1) {
			perfdata_str = perfdata(disk_data[i].Disk_Name,
				disk_data[i].Disk_PercentUsed, "",
				(warn != UNKNOWN_PERCENTAGE_USAGE), warn,
				(crit != UNKNOWN_PERCENTAGE_USAGE), crit,
				1, 0, 1, 100);
			printf(_(" %s"), perfdata_str);
			free(perfdata_str);
		} else {
			xasprintf(&label, "%sused_percent", disk_data[i].Disk_Caption);
			perfdata_str = smn_perfdata(label,
				disk_data[i].Disk_PercentUsed, "",
				(warn != UNKNOWN_PERCENTAGE_USAGE), warn,
				(crit != UNKNOWN_PERCENTAGE_USAGE), crit,
				1, 0, 1, 100);
			printf(_(" %s"), perfdata_str);
			free(label);
			free(perfdata_str);
		}
	}
	printf(_("\n"));

	for (int i = 0; i < nodes->nodeNr; i++) {
		printf("%sDisk %s, Total, %ldMB, Used: %ldMB (%d%%)\n",
			disk_data[i].alert,
			disk_data[i].Disk_Caption,
			disk_data[i].Disk_Size,
			disk_data[i].Disk_UsedSpace,
			disk_data[i].Disk_PercentUsed);
	}

	end:
	if(disk_data && nodes) {
		for (int i = 0; i < nodes->nodeNr; i++) {
			if(disk_data[i].Disk_Caption) free(disk_data[i].Disk_Caption);
		}
		free(disk_data);
	}
	if(nodes) xmlXPathFreeNodeSet(nodes);
	wr_wql_free(&wql_ctx);
	wrprotocol_ctx_free(proto);
	elapsed_time = (double)deltime(tv) / 1.0e6;
	return result;
}
