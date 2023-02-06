#ifndef __XML_H_
#define __XML_H_
#include <libxml/tree.h>
#include <uuid/uuid.h>
#include <libxml/xpathInternals.h>
#include "wrcommon.h"

typedef struct xmlWRDoc {
    xmlDocPtr doc;
    xmlNodePtr envelope;
    xmlNodePtr header;
    xmlNodePtr body;
    struct ntlm_buffer response;
} xmlWRDoc_desc, *xmlWRDoc_p;


uint32_t xml_new_basic_header(xmlWRDoc_p wrd, const char *resourceuri, const char *action);
uint32_t xml_get_uuid(uuid_t uuid, xmlDocPtr doc, const char *xpathExpr, 
        const char *nsSuffix, const char *nsHref);
xmlWRDoc_p xml_new_wr_doc();
uint32_t xml_add_selectorset(xmlWRDoc_p wrd, const keyval_t *selectorset);
void xml_free_wr_doc(xmlWRDoc_p wrd);
xmlNsPtr xml_get_ns(xmlNsPtr *list, const char *prefix);
uint32_t xml_find_first(xmlNodePtr *node, xmlDocPtr doc, const char *xpathExpr,
        const char *nsSuffix, const char *nsHref);

uint32_t xml_find_all(xmlNodeSetPtr *nodes, xmlDocPtr doc, const char *xpathExpr,
        const char *nsSuffix, const char *nsHref);
uint32_t xml_prop_node_to_number(xmlNodePtr node, xmlDocPtr schema, uint64_t *value);
uint32_t xml_schema_is_number(const xmlDocPtr schema, const char *name);
uint32_t xml_class_get_prop_num(uint64_t *value, const xmlNodePtr class, const char *name, const xmlDocPtr schema);
uint32_t xml_class_get_prop_string(char **value, const xmlNodePtr class, const char *name, const xmlDocPtr schema);

#endif