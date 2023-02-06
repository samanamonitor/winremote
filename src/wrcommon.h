#ifndef __COMMON_H_
#define __COMMON_H_

#include <stdint.h>

typedef struct _keyval {
        char *key;
        char *value;
} keyval_desc, *keyval_t;

struct ntlm_buffer {
    uint8_t *data;
    size_t length;
};

#define UTF8 "utf-8"

#endif