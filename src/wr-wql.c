#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <libxml/tree.h>
#include "transport.h"
#include "protocol.h"
#include "cimclass.h"

#define MAX_BUFFER_SIZE (1<<22) /* 4MB */

uint32_t
usage(const char *msg, int argc, char * const*argv)
{
    if(msg) {
        fprintf(stderr, "%s\n", msg);
    }
    fprintf(stderr, "Usage: %s -H <host address> -u <username> "
        "-p <password> [ -n <namespace, 'root/cimv2' is default> ] "
        "-q <WMI query in quotes>\n", argv[0]);
    return 3;
}

int main(int argc, char * const*argv)
{
    int result = 0, opt;
    char *username = NULL;
    char *password = NULL;
    char *url = NULL;
    void *proto = NULL;
    const char *namespace = "root/cimv2";
    const char *wql = NULL;
    char buf[MAX_BUFFER_SIZE];
    char *classname = buf;
    size_t buf_len;
    xmlDocPtr xml_schema = NULL;
    cimclass_t cimclass_schema = NULL;
    xmlDocPtr xml_class = NULL;
    cimclass_set_t cimclass_set = NULL;

    while ((opt = getopt(argc, argv, "hu:p:H:n:q:")) != -1) {
        switch(opt) {
        case 'h':
            usage(NULL, argc, argv);
            break;
        case 'u':
            username = optarg;
            break;
        case 'p':
            password = optarg;
            break;
        case 'H':
            asprintf(&url, "http://%s:5985/wsman", optarg);
            break;
        case 'n':
            namespace = optarg;
            break;
        case 'q':
            wql = optarg;
            break;
        default:
            exit(usage(NULL, argc, argv));
            break;
        }
    }
    if(username == NULL) {
        username = getenv("WR_USERNAME");
        if(username == NULL) {
            usage("Username is a mandatory parameter.", argc, argv);
            result = 3;
            goto end;
        }
    }
    if(password == NULL) {
        password = getenv("WR_PASSWORD");
        if(password == NULL) {
            usage("Password is a mandatory parameter.", argc, argv);
            result = 3;
            goto end;
        }
    }
    if(url == NULL) {
        usage("Password is a mandatory parameter.", argc, argv);
        result = 3;
        goto end;
    }
    if(wql == NULL) {
        usage("Query is a mandatory parameter.", argc, argv);
        result = 3;
        goto end;
    }

    proto = wrprotocol_ctx_new();
    if(proto == NULL) {
        result = 1;
        goto end;
    }
    if(!wrprotocol_ctx_init(proto, username, password, url, WR_MECH_NTLM)) {
        result = 1;
        goto end;
    }

    extract_class_name(classname, MAX_BUFFER_SIZE, wql);

    xml_schema = wr_get_cim_schema_xml(proto, namespace, classname);
    if(xml_schema == NULL) {
        result = 1;
        goto end;
    }

    cimclass_schema = cimschema_from_xmlschema(xml_schema);
    if(cimclass_schema == NULL) {
        result = 1;
        goto end;
    }

    if(!wr_wql(proto, namespace, wql)) {
        result = 1;
        goto end;
    }

    xml_class = wr_result_toxml(proto);

    cimclass_set = cimclass_set_from_xml_doc(xml_class, cimclass_schema);

    cimclass_set_print(cimclass_set);

    end:
    xmlFreeDoc(xml_schema);
    xmlFreeDoc(xml_class);
    cimclass_free(&cimclass_schema);
    cimclass_set_free(&cimclass_set);
    if(url) free(url);
    wrprotocol_ctx_free(proto);

    return result;
}