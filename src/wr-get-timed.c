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

    struct timespec tp, tp_start, tp_new, tp_init, tp_schema, tp_class, tp_free, tplast = {0, 0};
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp_start);
    printf("start=%ld\n", (tp_start.tv_nsec - tplast.tv_nsec) / 1000);
    tplast = tp_start;

    for(int i=0; i<LOOP_COUNT; i++) {
        ctx = wrprotocol_ctx_new();
        if(ctx == NULL) {
            result = 1;
            goto end;
        }
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp_new);
        if(!wrprotocol_ctx_init(ctx, username, password, url, WR_MECH_NTLM)) {
            result = 1;
            goto end;
        }
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp_init);
        if(!wr_get_cim_schema(ctx, buf, MAX_BUFFER_SIZE, namespace, classname)) {
            result = 1;
            goto end;
        }
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp_schema);
        printf("%s\n", buf);
        if(!wr_get_wmi_class(ctx, buf, MAX_BUFFER_SIZE, namespace, classname)) {
            result = 1;
            goto end;
        }
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp_class);
        printf("%s\n", buf);
        end:
        wrprotocol_ctx_free(ctx);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp_free);
        if(result) break;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp);
        printf("new=%ld init=%ld schema=%ld class=%ld free=%ld total=%ld\n", 
            (tp_new.tv_nsec - tplast.tv_nsec) / 1000,
            (tp_init.tv_nsec - tp_new.tv_nsec) / 1000,
            (tp_schema.tv_nsec - tp_init.tv_nsec) / 1000,
            (tp_class.tv_nsec - tp_schema.tv_nsec) / 1000,
            (tp_free.tv_nsec - tp_class.tv_nsec) / 1000,
            (tp_free.tv_nsec - tplast.tv_nsec) / 1000);
        tplast = tp;

        read(STDIN_FILENO, buf, 4000000);
    }

    return result;
}