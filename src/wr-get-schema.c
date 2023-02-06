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
    void *ctx = NULL;
    const char *namespace = "root/default";
    const char *classname = "";
    char buf[MAX_BUFFER_SIZE];

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


    for(int i=0; i<1; i++) {
        wr_get_cim_schema(ctx, buf, MAX_BUFFER_SIZE, namespace, classname);
        printf("Server:\n%s\n", buf);
    }

    end:

    wrprotocol_ctx_free(ctx);
    return result;
}