#ifndef __TRANSPORT_H_
#define __TRANSPORT_H_
#include "wrcommon.h"

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#define DEBUG_BUFFER(b) printf(#b ".data=%p " #b ".length=%ld\n", b.data, b.length)
#define FREE(v) if(v) { free(v); v = NULL; }
#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))
#define WR_MECH_NTLM 1


void *wr_transport_ctx_new();
uint32_t wr_transport_ctx_init(void *c, const char *username, const char *password, const char *url, uint32_t mech_val);
uint32_t wr_transport_login(void *c);
uint32_t wr_send_message(void *c, struct ntlm_buffer *recv_data, const struct ntlm_buffer *message);
void wr_transport_free(void *c);

#endif