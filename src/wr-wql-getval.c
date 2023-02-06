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
    char *property = NULL;
    char *url = NULL;
    void *proto = NULL, *wql_ctx=NULL;
    const char *namespace = "root/cimv2";
    const char *wql = NULL;
    long data;

    while ((opt = getopt(argc, argv, "hu:p:H:n:q:r:")) != -1) {
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
        case 'r':
            property = optarg;
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
    if(property == NULL) {
        usage("Property is a mandatory parameter.", argc, argv);
        result = 3;
        goto end;
    }

    proto = wrprotocol_ctx_new();
    if(proto == NULL) {
        result = 3;
        goto end;
    }
    if(!wrprotocol_ctx_init(proto, username, password, url, WR_MECH_NTLM)) {
        result = 3;
        goto end;
    }

    wql_ctx = wr_wql_new(proto, namespace, wql);
    if(wql_ctx == NULL) {
        result = 3;
        goto end;
    }

    for(int i = 0; i < 20; i++) {
        if(!wr_wql_run(wql_ctx)) {
            result = 3;
            goto end;
        }

        data = wr_wql_get_integer(wql_ctx, property);

        if(data == -1) {
            fprintf(stderr, "Invalid data from property.\n");
            result = 3;
            goto end;
        }
        printf("Data: %ld\n", data);
        sleep(1);
    }


    end:
    wr_wql_free(&wql_ctx);
    if(url) free(url);
    wrprotocol_ctx_free(proto);

    return result;
}