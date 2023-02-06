#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "transport.h"
#include "protocol.h"

#define MAX_BUFFER_SIZE (1<<22) /* 4MB */

int main(int argc, char const *argv[])
{
    int result = 0;
    char *username;
    char *password;
    char *url;
    const char *classname = "Win32_Service";
    const char *namespace = "root/cimv2";
    char buf[MAX_BUFFER_SIZE];
    char *filter = NULL; /*"Name LIKE 'Citrix%'";*/

    username = getenv("WR_USERNAME");
    password = getenv("WR_PASSWORD");
    url = getenv("WR_URL");

    if(username == NULL || password == NULL || url == NULL) {
        fprintf(stderr, "Cannot continue. Define the environment variables WR_USERNAME, WR_PASSWORD and WR_URL.\n");
        exit(1);
    }

    if(argc > 1)
        classname = argv[1];
    if(argc > 2)
        namespace = argv[2];

    char *resourceuri;
    void *ctx = NULL;

    ctx = wrprotocol_ctx_new();
    if(ctx == NULL) {
        result = 1;
        goto end;
    }
    if(!wrprotocol_ctx_init(ctx, username, password, url, WR_MECH_NTLM)) {
        result = 1;
        goto end;
    }

    size_t buf_len;
    asprintf(&resourceuri, "http://schemas.microsoft.com/wbem/wsman/1/wmi/%s/%s", namespace, classname);
    if(resourceuri == NULL) {
        result = 1;
        goto end;
    }
    for(int i=0; i<1; i++) {
        if(!wr_enumerate(ctx, resourceuri, filter, NULL, NULL)) {
            wr_response_to_buffer(ctx, buf, MAX_BUFFER_SIZE);
            printf("%s\n", buf);
            result = 1;
            goto end;
        }
        wr_response_to_buffer(ctx, buf, MAX_BUFFER_SIZE);
        printf("Server:\n%s\n", buf);
        if(!wr_pull_all(ctx, resourceuri)) {
            result = 1;
            goto end;
        }
        wr_pull_to_buffer(ctx, buf, MAX_BUFFER_SIZE);

        printf("Server:\n%s\n", buf);
        result = 0;
    }

    end:
    if(resourceuri != NULL) free(resourceuri);
    wrprotocol_ctx_free(ctx);
    return result;
}