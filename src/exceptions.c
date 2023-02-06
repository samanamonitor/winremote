#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#define FREE(x) do { \
   if((x) != NULL) free(x); \
   x = NULL; \
} while(0);

#define EXCEPTION_SEPARATOR ';'
#define EXC_VALUE_SEPARATOR ','

typedef struct _log_exceptions {
    uint32_t exceptionNr;
    uint32_t exceptionMax;
    struct {
        int32_t EventCode;
        char *r_SourceName;
        char *r_Message;
    } *exceptionTab;
} *log_exceptions_t;

void
free_exceptions(log_exceptions_t l)
{
    if(l == NULL) return;

    for (int i = 0; i < l->exceptionNr; i++) {
        FREE(l->exceptionTab[i].r_Message);
        FREE(l->exceptionTab[i].r_SourceName);
        l->exceptionTab[i].EventCode = 0;
    }
    l->exceptionMax = 0;
    l->exceptionNr = 0;
    if(l->exceptionTab) free(l->exceptionTab);
    l->exceptionTab = NULL;
}

uint32_t
process_exceptions(log_exceptions_t l, const char *e)
{
    uint16_t EventCode;
    char *p;
    char *msg_start, *msg_end;
    char *src_start, *src_end;

    if(l == NULL || e == NULL) return 0;

    l->exceptionNr = 0;
    l->exceptionMax = 0;
    l->exceptionTab = NULL;

    while(*e) {

        if(l->exceptionNr == l->exceptionMax) {
            l->exceptionMax += 10;
            void *temp = realloc(l->exceptionTab, l->exceptionMax * sizeof(*(l->exceptionTab)));
            if(temp == NULL) {
                goto error;
            }
            l->exceptionTab = temp;
        }

        l->exceptionTab[l->exceptionNr].EventCode = strtol(e, &src_start, 10);
        if(errno == EINVAL || errno == ERANGE) {
            goto error;
        }

        if(*src_start == EXC_VALUE_SEPARATOR || *src_start == EXCEPTION_SEPARATOR || *src_start == '\0') {
            if(*src_start == EXC_VALUE_SEPARATOR) src_start++;
        } else {
            goto error;
        }

        src_end = src_start;
        while(*src_end != '\0' && *src_end != EXC_VALUE_SEPARATOR && *src_end != EXCEPTION_SEPARATOR) src_end++;
        msg_start = src_end;

        if(*msg_start == EXC_VALUE_SEPARATOR) msg_start++;
        msg_end = msg_start;

        while(*msg_end != '\0' && *msg_end != EXC_VALUE_SEPARATOR && *msg_end != EXCEPTION_SEPARATOR) msg_end++;
        if(*msg_end == EXC_VALUE_SEPARATOR) {
            goto error;
        }

        l->exceptionTab[l->exceptionNr].r_SourceName = strndup(src_start, src_end-src_start);
        l->exceptionTab[l->exceptionNr].r_Message = strndup(msg_start, msg_end-msg_start);
        l->exceptionNr++;

        e = msg_end;
        if(*e == EXCEPTION_SEPARATOR) e++;
    }
    end:
    return 1;

    error:
    fprintf(stderr, "Error\n");
    free_exceptions(l);
    return 0;
}

int main(int argc, char const *argv[])
{
    struct _log_exceptions l = {0};
    if(argc < 2) return 0;

    process_exceptions(&l, argv[1]);
    printf("exceptionNr: %d\n", l.exceptionNr);
    printf("exceptionMax: %d\n", l.exceptionMax);
    for (int i = 0; i < l.exceptionNr; i++) {
        printf("  %d, '%s', '%s'\n", l.exceptionTab[i].EventCode, l.exceptionTab[i].r_SourceName, l.exceptionTab[i].r_Message);
    }
    /* code */
    return 0;
}