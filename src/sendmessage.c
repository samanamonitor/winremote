#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "transport.h"
#include "protocol.h"

uint32_t
load_from_file(struct ntlm_buffer *message, const uint8_t *filename)
{
    uint32_t result = 1;
    size_t sz;
    uint8_t *src_data=NULL;
    FILE *f=NULL;
    if(message == NULL || filename == NULL) return 0;

    if((f = fopen(filename, "rb")) == NULL) {
        fprintf(stderr, "Unable to open data file.\n");
        result = 0;
        goto end;
    }
    fseek(f, 0L, SEEK_END);
    message->length = ftell(f);
    message->data = calloc(1, message->length);
    if(message->data == NULL) {
        fprintf(stderr, "Unable to reserver memory for source data.\n");
        message->length = 0;
        result = 0;
        goto end;
    }
    fseek(f, 0L, SEEK_SET);
    sz = fread(message->data, message->length, 1, f);
    if(sz != 1) {
        fprintf(stderr, "Invalid number of bytes received.\n");
        message->length = 0;
        free(message->data);
        result = 0;
        goto end;
    }

    end:
    if(f) fclose(f);
    return result;
}

int main(int argc, char const *argv[])
{
    int result = 0;
    char *username;
    char *password;
    char *url;
    void *ctx = NULL;
    struct ntlm_buffer response = { NULL, 0 };
    struct ntlm_buffer message = { NULL, 0 };

    username = getenv("WR_USERNAME");
    password = getenv("WR_PASSWORD");
    url = getenv("WR_URL");

    if(username == NULL || password == NULL || url == NULL) {
        fprintf(stderr, "Cannot continue. Define the environment variables WR_USERNAME, WR_PASSWORD and WR_URL.\n");
        exit(1);
    }

    ctx = wr_context_new();
    if(ctx == NULL) {
        result = 1;
        goto end;
    }
    if(!wr_context_init(ctx, username, password, url, WR_MECH_NTLM)) {
        result = 1;
        goto end;
    }
    if(!wr_login(ctx)) {
        result = 1;
        goto end;
    }

    char buf[2048];
    size_t buf_len;
    /*
    wql(buf, &buf_len, "SELECT * FROM Win32_OperatingSystem");
    */
    for(int i=0; i<1; i++) {
        wr_get(ctx, buf, &buf_len, "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_OperatingSystem");
        printf("%d\n", i);
    }

    /*
    for(int i=1; i <= argc; i++) {
        if(!load_from_file(&message, argv[i])) {
            result = 1;
            goto end;
        }
        if(!wr_send_message(ctx, &response, &message)) {
            result = 1;
            printf("%s\n", response.data);
            goto end;
        }
        printf("%s\n", response.data);
    }
    */


    end:
    /*
    FREE(message.data);
    */
    wr_transport_free(ctx);
    return result;
}