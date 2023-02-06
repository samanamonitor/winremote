#ifndef __PROTOCOL_H_
#define __PROTOCOL_H_
#include <stdint.h>
#include <libxml/tree.h>
#include "wrcommon.h"


void* wrprotocol_ctx_new();
uint32_t wrprotocol_ctx_init(void *c, const char *username, 
        const char *password, const char *url, uint32_t mech_val);
void wrprotocol_ctx_free(void *c);

uint32_t wr_enumerate(void *ctx, const char *resourceuri, const char *filter, 
        const char *WQL, const keyval_t *selectorset);
uint32_t wr_get(void *c, const char *resourceuri, const keyval_t *selectorset);
uint32_t wr_pull(void *c, const char *resourceuri, uint32_t maxelements);
uint32_t wr_pull_all(void *c, const char *resourceuri);

size_t extract_class_name(char *classname, size_t max_buffer_size, const char *wql);
uint32_t wr_wql(void *ctx, const char *namespace, const char *WQL);

size_t wr_get_cim_schema(void *ctx, char *out_xml, size_t max_buffer_size, const char *namespace, const char *classname);
size_t wr_get_wmi_class(void *ctx, char *out_xml, size_t max_buffer_size, const char *namespace, const char *classname);
size_t wr_response_to_buffer(void *c, char *out_xml, size_t max_buffer_size);
size_t wr_pull_to_buffer(void *c, char *out_xml, size_t max_buffer_size);
size_t xml_to_buffer(char *out_xml, size_t max_buffer_size, xmlDocPtr doc);


xmlDocPtr wr_get_cim_schema_xml(void *c, const char *namespace, const char *classname);
xmlDocPtr wr_result_toxml(void *c);

size_t wr_wql_tostring(void *c, char *out_xml, size_t max_buffer_size);

void wr_wql_free(void *w);
void *wr_wql_new(void *p, const char *namespace, const char *query);
uint32_t wr_wql_run(void *w);
uint64_t wr_wql_get_integer(void *w, const char *property);
xmlDocPtr wr_wql_response_toxml(void *w);
xmlDocPtr wr_wql_schema_toxml(void *w);


#endif