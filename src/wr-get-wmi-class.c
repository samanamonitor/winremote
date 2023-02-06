#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "transport.h"
#include "protocol.h"

#define LOOP_COUNT 5
#define MAX_BUFFER_SIZE (1<<22) /* 4MB */

int main(int argc, char const *argv[])
{
    int result = 0;
    char *username;
    char *password;
    char *url;
    void *ctx = NULL;
    const char *namespace = "root/cimv2";
    const char *classname = "Win32_ComputerSystem";
    char buf[MAX_BUFFER_SIZE];
    size_t buf_len;

    username = getenv("WR_USERNAME");
    password = getenv("WR_PASSWORD");
    url = getenv("WR_URL");

    if(username == NULL || password == NULL || url == NULL) {
        fprintf(stderr, "Cannot continue. Define the environment variables WR_USERNAME, WR_PASSWORD and WR_URL.\n");
        exit(1);
    }

    if(argc > 1) {
        namespace = argv[1];
    }
    if(argc > 2) {
        classname = argv[2];
    }

    ctx = wrprotocol_ctx_new();
    if(ctx == NULL) {
        result = 1;
        goto end;
    }
    if(!wrprotocol_ctx_init(ctx, username, password, url, WR_MECH_NTLM)) {
        result = 1;
        goto end;
    }
    if(wr_get_cim_schema(ctx, buf, MAX_BUFFER_SIZE, namespace, classname) == -1) {
        result = 1;
        goto end;
    }
    printf("%s\n", buf);
    if(wr_get_wmi_class(ctx, buf, MAX_BUFFER_SIZE, namespace, classname) == -1) {
        result = 1;
        goto end;
    }
    printf("%s\n", buf);
    end:
    wrprotocol_ctx_free(ctx);

    return result;
}