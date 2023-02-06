#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <uuid/uuid.h>
#include <regex.h>
#include "transport.h"
#include "protocol.h"
#include "xml.h"

#define WR_PULL_MAX 10

typedef struct _wrprotocol_ctx {
    xmlDocPtr xml_wr_response_doc;
    void *wrtransport_ctx;
    xmlWRDoc_p wrd;
    uuid_t EnumerationContext;
    xmlDocPtr xml_wr_error_doc;
    xmlDocPtr xml_wr_pulled_doc;
} *wrprotocol_ctx_t;

typedef struct _wr_wql_ctx {
    wrprotocol_ctx_t protocol_ctx;
    char *query;
    char *classname;
    char *namespace;
    char *resourceuri;
    char *classuri;
    uuid_t enumeration_context;
    xmlDocPtr xml_schema;
    xmlDocPtr xml_response;
} *wr_wql_ctx_t;

void *
wrprotocol_ctx_new()
{
    wrprotocol_ctx_t ctx = calloc(1, sizeof(struct _wrprotocol_ctx));
    if(ctx == NULL) return NULL;

    xmlInitParser();
    ctx->wrtransport_ctx = wr_transport_ctx_new();
    if(ctx->wrtransport_ctx == NULL) {
        fprintf(stderr, "Unable to create transport context\n");
        goto error;
    }
    return ctx;
    error:
    free(ctx);
    return NULL;
}

uint32_t
wrprotocol_ctx_init(void *c, const char *username, const char *password, const char *url, uint32_t mech_val)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    if(ctx == NULL) return 0;

    if(!wr_transport_ctx_init(ctx->wrtransport_ctx, username, password, url, mech_val)) {
        fprintf(stderr, "Error - Unable to initialize transport context\n");
        return 0;
    }
    if(username != NULL && password != NULL && !wr_transport_login(ctx->wrtransport_ctx)) {
        fprintf(stderr, "Error - Unable to login to server.\n");
        return 0;
    }
    return 1;
}

void
wrprotocol_ctx_free(void *c)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;

    if(ctx == NULL) return;

    wr_transport_free(ctx->wrtransport_ctx);
    ctx->wrtransport_ctx = NULL;
    if(ctx->xml_wr_response_doc) xmlFreeDoc(ctx->xml_wr_response_doc);
    ctx->xml_wr_response_doc = NULL;
    if(ctx->xml_wr_pulled_doc) xmlFreeDoc(ctx->xml_wr_pulled_doc);
    ctx->xml_wr_pulled_doc = NULL;
    if(ctx->xml_wr_error_doc) xmlFreeDoc(ctx->xml_wr_error_doc);
    ctx->xml_wr_error_doc = NULL;
    free(ctx);
    xmlCleanupParser();
}

size_t
wr_response_to_buffer(void *c, char *out_xml, size_t max_buffer_size)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;

    if(ctx == NULL || out_xml == NULL) return 0;

    return xml_to_buffer(out_xml, max_buffer_size, ctx->xml_wr_response_doc);
}

size_t
wr_pull_to_buffer(void *c, char *out_xml, size_t max_buffer_size)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;

    if(ctx == NULL || out_xml == NULL) return 0;

    return xml_to_buffer(out_xml, max_buffer_size, ctx->xml_wr_pulled_doc);
}

static uint32_t
check_message_id(xmlDocPtr xml_wr_response_doc, uuid_t messageid)
{
    uint32_t result = 1;
    uuid_t related_to;
    if(!xml_get_uuid(related_to, xml_wr_response_doc, "//add:RelatesTo",
            "add", "http://schemas.xmlsoap.org/ws/2004/08/addressing")) {
        fprintf(stderr, "Error - Invalid message ID received.\n");
        result = 0;
        goto end;
    }
    if(uuid_compare(related_to, messageid)) {
        char buf[32];
        fprintf(stderr, "Error - Message received has wrong messageid.\n");
        uuid_unparse_upper(related_to, buf);
        fprintf(stderr, "Received id: %s\n", buf);
        uuid_unparse_upper(messageid, buf);
        fprintf(stderr, "Sent id: %s\n", buf);
        result = 0;
        goto end;
    }
    end:
    return result;
}

static uint32_t
wr_send(void *c, xmlDocPtr request_doc)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    uint32_t result = 1;
    struct ntlm_buffer message = { NULL, 0 };
    struct ntlm_buffer response = { NULL, 0 };
    xmlBufferPtr buf = NULL;
    xmlOutputBufferPtr outbuf;
    uuid_t messageid;

    if(ctx == NULL || request_doc == NULL) return 0;

    if(!xml_get_uuid(messageid, request_doc, "//add:MessageID", "add", 
            "http://schemas.xmlsoap.org/ws/2004/08/addressing")) {
        fprintf(stderr, "Error - Invalid message ID in request message.\n");
        result = 0;
        goto end;
    }

    buf = xmlBufferCreate();
    if (buf == NULL) {
        fprintf(stderr, "Error creating the xml buffer\n");
        result = 0;
        goto end;
    }

    outbuf = xmlOutputBufferCreateBuffer(buf, xmlFindCharEncodingHandler(UTF8));
    if(outbuf == NULL) {
        fprintf(stderr, "Error creating output buffer\n");
        result = 0;
        goto end;
    }
    if(xmlSaveFileTo(outbuf, request_doc, UTF8) == -1) {
        fprintf(stderr, "Error - Unable to generate request xml file.\n");
        result = 0;
        goto end;
    }

    message.data = buf->content;
    message.length = strlen(message.data);

    if(ctx->xml_wr_response_doc) 
        xmlFreeDoc(ctx->xml_wr_response_doc);

    if(!wr_send_message(ctx->wrtransport_ctx, &response, &message)) {
        result = 0;
        fprintf(stderr, "%s\n", response.data);
        ctx->xml_wr_error_doc = xmlParseDoc(response.data);
        goto end;
    }

    ctx->xml_wr_response_doc = xmlParseDoc(response.data);
    if(ctx->xml_wr_response_doc == NULL) {
        fprintf(stderr, "Error. Response is not XML.\n");
        result = 0;
        goto end;
    }

    if(!check_message_id(ctx->xml_wr_response_doc, messageid)) {
        fprintf(stderr, "Error. Invalid message id recieved.");
        result = 0;
        goto end;
    }

    end:
    if(buf) xmlBufferFree(buf);
    FREE(response.data);
    return result;
}

uint32_t
wr_get(void *c, const char *resourceuri, const keyval_t *selectorset)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    uint32_t result = 1;
    xmlWRDoc_p wrd;
    const char *action = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";

    if(ctx == NULL || resourceuri == NULL) return 0;

    wrd = xml_new_wr_doc();
    if(wrd == NULL) {
        result = 0;
        goto end;
    }
    if(!xml_new_basic_header(wrd, resourceuri, action)) {
        result = 0;
        goto end;
    }

    if(!xml_add_selectorset(wrd, selectorset)) {
        result = 0;
        goto end;
    }

    if(!wr_send(ctx, wrd->doc)) {
        result = 0;
        goto end;
    }

    end:
    xml_free_wr_doc(wrd);
    return result;
}

uint32_t
wr_enumerate(void *c, const char *resourceuri, const char *filter, 
        const char *WQL, const keyval_t *selectorset)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    uint32_t result = 1;
    const char *action = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";
    const char *xml;
    xmlWRDoc_p wrd;
    xmlNodePtr enumerate_n;
    xmlNsPtr *nslist=NULL, n, w;

    if(ctx == NULL || resourceuri == NULL) return 0;

    wrd = xml_new_wr_doc();
    if(wrd == NULL) {
        result = 0;
        goto end;
    }
    if(!xml_new_basic_header(wrd, resourceuri, action)) {
        result = 0;
        goto end;
    }

    nslist = xmlGetNsList(wrd->doc, wrd->envelope);
    if(nslist == NULL) {
        fprintf(stderr, "Error. Unable to create list of namespaces.\n");
        result = 0;
        goto end;
    }
    n = xml_get_ns(nslist, "n");
    if(n == NULL) {
        fprintf(stderr, "Error. Namespace 'n' not found.\n");
        result = 0;
        goto end;
    }
    w = xml_get_ns(nslist, "w");
    if(w == NULL) {
        fprintf(stderr, "Error. Namespace 'w' not found.\n");
        result = 0;
        goto end;
    }

    enumerate_n = xmlNewChild(wrd->body, n, "Enumerate", NULL);
    if(enumerate_n == NULL) {
        fprintf(stderr, "Error - Unable to create 'Enumerate' node.\n");
        result = 0;
        goto end;
    }
    if(WQL) {
        xmlNodePtr wql_n;
        wql_n = xmlNewChild(enumerate_n, w, "Filter", BAD_CAST WQL);
        if(wql_n == NULL) {
            fprintf(stderr, "Error - Unable to create 'Filter' node.\n");
            result = 0;
            goto end;
        }
        if(xmlNewProp(wql_n, BAD_CAST "Dialect", 
                BAD_CAST "http://schemas.microsoft.com/wbem/wsman/1/WQL") == NULL) {
            fprintf(stderr, "Error - Unable to set 'Dialect' property to 'Filter' node.\n");
            result = 0;
            goto end;
        }
    } else if (filter) {
        xmlNodePtr filter_n;
        filter_n = xmlNewChild(enumerate_n, w, "Filter", BAD_CAST filter);
        if(filter_n = NULL) {
            fprintf(stderr, "Error - Unable to create 'Filter' node.\n");
            result = 0;
            goto end;
        }
        if(xmlNewProp(filter_n, BAD_CAST "Dialect", 
                BAD_CAST "http://schemas.dmtf.org/wbem/wsman/1/wsman/SelectorFilter") == NULL) {
            fprintf(stderr, "Error - Unable to set 'Dialect' property to 'Filter' node.\n");
            result = 0;
            goto end;
        }

    } else if (selectorset) {
        if(!xml_add_selectorset(wrd, selectorset)) {
            result = 0;
            goto end;
        }
    }

    if(!wr_send(ctx, wrd->doc)) {
        result = 0;
        goto end;
    }
    if(!xml_get_uuid(ctx->EnumerationContext, ctx->xml_wr_response_doc, 
            "//en:EnumerationContext", "en", 
            "http://schemas.xmlsoap.org/ws/2004/09/enumeration")) {
        fprintf(stderr, "Error - Invalid EnumerationContext received.\n");
        result = 0;
        goto end;
    }

    end:
    if(nslist) free(nslist);
    xml_free_wr_doc(wrd);
    return result;
}

uint32_t
wr_pull(void *c, const char *resourceuri, uint32_t maxelements)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    uint32_t result = 1;
    xmlWRDoc_p wrd;
    xmlNsPtr *nslist=NULL, n;
    xmlNodePtr pull_n;
    char buf[48];
    const char *action = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull";


    if(ctx == NULL || resourceuri == NULL) return 0;

    wrd = xml_new_wr_doc();
    if(wrd == NULL) {
        result = 0;
        goto end;
    }
    if(!xml_new_basic_header(wrd, resourceuri, action)) {
        result = 0;
        goto end;
    }

    nslist = xmlGetNsList(wrd->doc, wrd->envelope);
    if(nslist == NULL) {
        fprintf(stderr, "Error. Unable to create list of namespaces.\n");
        result = 0;
        goto end;
    }
    n = xml_get_ns(nslist, "n");
    if(n == NULL) {
        fprintf(stderr, "Error. Namespace 'n' not found.\n");
        result = 0;
        goto end;
    }

    pull_n = xmlNewChild(wrd->body, n, "Pull", NULL);
    if(pull_n == NULL) {
        fprintf(stderr, "Error - Unable to create 'Pull' node.\n");
        result = 0;
        goto end;
    }

    sprintf(buf, "uuid:");
    uuid_unparse_upper(ctx->EnumerationContext, buf+5);
    if(xmlNewChild(pull_n, n, "EnumerationContext", buf) == NULL) {
        fprintf(stderr, "Error - Unable to create 'EnumerationContext' node.\n");
        result = 0;
        goto end;
    }

    sprintf(buf, "%d", maxelements);
    if(xmlNewChild(pull_n, n, "MaxElements", buf) == NULL) {
        fprintf(stderr, "Error - Unable to create 'MaxElements' node.\n");
        result = 0;
        goto end;
    }

    if(!wr_send(ctx, wrd->doc)) {
        result = 0;
        goto end;
    }

    if(xml_find_first(NULL, ctx->xml_wr_response_doc, "//e:EndOfSequence", 
            "e", "http://schemas.xmlsoap.org/ws/2004/09/enumeration")) {
        memset(ctx->EnumerationContext, 0, sizeof(uuid_t));
        result = 0;
        goto end;
    }

    if(!xml_get_uuid(ctx->EnumerationContext, ctx->xml_wr_response_doc, 
            "//e:EnumerationContext", "e", 
            "http://schemas.xmlsoap.org/ws/2004/09/enumeration")) {
        fprintf(stderr, "Error - Invalid EnumerationContext received.\n");
        result = 0;
        goto end;
    }

    end:
    if(nslist) free(nslist);
    xml_free_wr_doc(wrd);
    return result;
}

uint32_t
wr_pull_all(void *c, const char *resourceuri)
{
    uint32_t result = 1;
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    xmlWRDoc_p wrd;
    xmlNodePtr pullreponse, response_items;
    uint32_t pull_continue = 0;
    xmlNsPtr *nslist, n;
    

    if(ctx == NULL || resourceuri == NULL) return 0;

    wrd = xml_new_wr_doc();
    if (wrd == NULL) {
        fprintf(stderr, "Error - Unable to create an XML doc for the result\n");
        result = 0;
        goto end;
    }
    nslist = xmlGetNsList(wrd->doc, wrd->envelope);
    n = xml_get_ns(nslist, "n");
    free(nslist);
    pullreponse = xmlNewChild(wrd->body, n, BAD_CAST "PullReponse", NULL);
    if(pullreponse == NULL) {
        fprintf(stderr, "Error - Unable to create PullReponse node.\n");
        result = 0;
        goto end;
    }
    response_items = xmlNewChild(pullreponse, n, BAD_CAST "Items", NULL);
    if(pullreponse == NULL) {
        fprintf(stderr, "Error - Unable to create Items node.\n");
        result = 0;
        goto end;
    }

    do {
        xmlNodePtr items, item;

        pull_continue = wr_pull(c, resourceuri, WR_PULL_MAX);
        xml_find_first(&items, ctx->xml_wr_response_doc, "//n:PullResponse/n:Items",
            "n", "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
        for(item = items->children; item; item = item->next) {
            xmlNodePtr item_copy = xmlCopyNode(item, 1);
            if(item_copy == NULL) {
                fprintf(stderr, "Error - Unable to create a copy of the node.\n");
                result = 0;
                goto end;
            }
            xmlAddChild(response_items, item_copy);
        }
    } while(pull_continue);

    if(ctx->xml_wr_pulled_doc) {
        xmlFreeDoc(ctx->xml_wr_pulled_doc);
        ctx->xml_wr_pulled_doc = NULL;
    }
    ctx->xml_wr_pulled_doc = xmlCopyDoc(wrd->doc, 1);

    end:
    xml_free_wr_doc(wrd);
    return result;

}

size_t
extract_class_name(char *classname, size_t max_buffer_size, const char *wql)
{
    regex_t regex;
    regmatch_t  pmatch[1];
    char *re = " FROM \\+";
    const char *s=wql;
    char *cn;

    if(classname == NULL || wql == NULL) {
        return -1;
    }

    if (regcomp(&regex, re, REG_NEWLINE | REG_ICASE)){
        fprintf(stderr, "Error - Unable to create regex context for Class Name.\n");
        regfree(&regex);
        return -1;
    }
    if (regexec(&regex, wql, ARRAY_SIZE(pmatch), pmatch, 0)) {
        fprintf(stderr, "Error - Unable to find Class Name.\n");
        regfree(&regex);
        return -1;
    }
    regfree(&regex);
    s += pmatch[0].rm_eo;
    sscanf(s, "%ms", &cn);
    if(cn == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for buffer.\n");
        return -1;
    }
    strncpy(classname, cn, max_buffer_size - 1);
    free(cn);

    return strlen(classname);
}

uint32_t
wr_wql(void *c, const char *namespace, const char *WQL)
{
    uint32_t result = 1;
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    char *resourceuri = NULL;

    if(ctx == NULL || namespace == NULL || WQL == NULL) {
        return 0;
    }

    asprintf(&resourceuri, "http://schemas.microsoft.com/wbem/wsman/1/wmi/%s/*", namespace);
    if(resourceuri == NULL) {
        result = 0;
        goto end;
    }

    if(!wr_enumerate(ctx, resourceuri, NULL, WQL, NULL)) {
        result = 0;
        goto end;
    }

    if(!wr_pull_all(ctx, resourceuri)) {
        result = 0;
        goto end;
    }

    end:
    if(resourceuri) free(resourceuri);
    return result;
}

size_t
wr_wql_tostring(void *c, char *out_xml, size_t max_buffer_size)
{
    size_t out_xml_len;
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;

    if(ctx == NULL || out_xml == NULL) return -1;

    out_xml_len = xml_to_buffer(out_xml, max_buffer_size, ctx->xml_wr_pulled_doc);
    return out_xml_len;
}

xmlDocPtr
wr_result_toxml(void *c)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;

    if(ctx == NULL) return NULL;
    return xmlCopyDoc(ctx->xml_wr_pulled_doc, 1);
}

xmlDocPtr
wr_get_cim_schema_xml(void *c, const char *namespace, const char *classname)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    xmlDocPtr outdoc = NULL;
    char *resourceuri = "http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*";
    keyval_t selectorset[] = {
        &(keyval_desc){ .key = "__cimnamespace", .value = discard_const(namespace)},
        &(keyval_desc){ .key = "ClassName", .value = discard_const(classname) },
        0
    };

    if(ctx == NULL || namespace == NULL || classname == NULL) {
        goto end;
    }

    if(strlen(classname) == 0) {
        if(!wr_enumerate(ctx, resourceuri, NULL, NULL, selectorset)) {
            goto end;
        }
        if(!wr_pull_all(ctx, resourceuri)) {
            goto end;
        }
        outdoc = xmlCopyDoc(ctx->xml_wr_pulled_doc, 1);
    }
    if(!wr_get(ctx, resourceuri, selectorset)) {
        goto end;
    } else {
        outdoc = xmlCopyDoc(ctx->xml_wr_response_doc, 1);
    }
    end:
    return outdoc;
}

size_t
wr_get_cim_schema(void *c, char *out_xml, size_t max_buffer_size, const char *namespace, const char *classname)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    char *resourceuri = "http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*";
    keyval_t selectorset[] = {
        &(keyval_desc){ .key = "__cimnamespace", .value = discard_const(namespace)},
        &(keyval_desc){ .key = "ClassName", .value = discard_const(classname) },
        0
    };

    if(ctx == NULL || namespace == NULL || classname == NULL) {
        return -1;
    }

    if(strlen(classname) == 0) {
        if(!wr_enumerate(ctx, resourceuri, NULL, NULL, selectorset)) {
            return -1;
        }
        if(!wr_pull_all(ctx, resourceuri)) {
            return -1;
        }
        return xml_to_buffer(out_xml, max_buffer_size, ctx->xml_wr_pulled_doc);
    }
    if(!wr_get(ctx, resourceuri, selectorset)) {
        return -1;
    }
    return xml_to_buffer(out_xml, max_buffer_size, ctx->xml_wr_response_doc);
}

size_t
wr_get_wmi_class(void *c, char *out_xml, size_t max_buffer_size, const char *namespace, const char *classname)
{
    wrprotocol_ctx_t ctx = (wrprotocol_ctx_t) c;
    char *resourceuri = NULL;
    size_t out_xml_len = 0;

    if(ctx == NULL || classname == NULL || namespace == NULL) return 0;

    asprintf(&resourceuri,  "http://schemas.microsoft.com/wbem/wsman/1/wmi/%s/%s", namespace, classname);
    if(resourceuri == NULL) {
        out_xml_len = -1;
        goto end;
    }

    if(!wr_enumerate(ctx, resourceuri, NULL, NULL, NULL)) {
        out_xml_len = -1;
        goto end;
    }
    if(!wr_pull_all(ctx, resourceuri)) {
        out_xml_len = -1;
        goto end;
    }
    out_xml_len = xml_to_buffer(out_xml, max_buffer_size, ctx->xml_wr_pulled_doc);

    end:
    if(resourceuri) free(resourceuri);
    return out_xml_len;
}

void
wr_wql_free(void *w)
{
    wr_wql_ctx_t *wql_ctx = (wr_wql_ctx_t*) w;

    if(wql_ctx == NULL || *wql_ctx == NULL) return;

    if((*wql_ctx)->query) {
        free((*wql_ctx)->query);
        (*wql_ctx)->query = NULL;
    }
    if((*wql_ctx)->namespace) {
        free((*wql_ctx)->namespace);
        (*wql_ctx)->namespace = NULL;
    }
    if((*wql_ctx)->classname) {
        free((*wql_ctx)->classname);
        (*wql_ctx)->classname = NULL;
    }
    if((*wql_ctx)->resourceuri) {
        free((*wql_ctx)->resourceuri);
        (*wql_ctx)->resourceuri = NULL;
    }
    if((*wql_ctx)->classuri) {
        free((*wql_ctx)->classuri);
        (*wql_ctx)->classuri = NULL;
    }
    xmlFreeDoc((*wql_ctx)->xml_schema);
    xmlFreeDoc((*wql_ctx)->xml_response);
    free(*wql_ctx);
    *wql_ctx = NULL;
}

#define MAX_CLASS_NAME_LENGTH 128

void *
wr_wql_new(void *p, const char *namespace, const char *query)
{
    wr_wql_ctx_t wql_ctx;
    char buffer[MAX_CLASS_NAME_LENGTH];
    xmlDocPtr xml_schema;
    xmlNodePtr node;
    char *classname;

    if(p == NULL || namespace == NULL || query == NULL) return NULL;

    classname = buffer;
    extract_class_name(classname, MAX_CLASS_NAME_LENGTH, query);
    xml_schema = wr_get_cim_schema_xml(p, namespace, classname);
    if(xml_schema == NULL) {
        fprintf(stderr, "Error - Unable to locate schema for class %s.\n", classname);
        return NULL;
    }

    xml_find_first(&node, xml_schema, "//CLASS", NULL, NULL);
    if(node == NULL) {
        xmlFreeDoc(xml_schema);
        fprintf(stderr, "Error - Invalid schema.\n");
        return NULL;
    }

    classname = xmlGetProp(node, "NAME");
    if(classname == NULL) {
        xmlFreeDoc(xml_schema);
        fprintf(stderr, "Error - Invalid schema.\n");
        return NULL;
    }

    wql_ctx = calloc(1, sizeof(struct _wr_wql_ctx));
    if(wql_ctx == NULL) {
        free(classname);
        xmlFreeDoc(xml_schema);
        fprintf(stderr, "Error - Unable to reserve memory for WQL context.\n");
        goto error;
    }

    wql_ctx->xml_schema = xml_schema;
    wql_ctx->protocol_ctx = (wrprotocol_ctx_t) p;
    wql_ctx->query = strdup(query);
    if(wql_ctx->query == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for query string.\n");
        goto error;
    }

    wql_ctx->namespace = strdup(namespace);
    if(wql_ctx->namespace == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for namespace string.\n");
        goto error;
    }

    wql_ctx->classname = classname;
    if(wql_ctx->classname == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for class name string.\n");
        goto error;

    }
    asprintf(&wql_ctx->resourceuri, 
        "http://schemas.microsoft.com/wbem/wsman/1/wmi/%s/*", wql_ctx->namespace);
    if(wql_ctx->resourceuri == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for resourceuri string.\n");
        goto error;
    }

    asprintf(&wql_ctx->classuri,
        "http://schemas.microsoft.com/wbem/wsman/1/wmi/%s/%s", wql_ctx->namespace, 
        wql_ctx->classname);
    if(wql_ctx->classuri == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for classuri string.\n");
        goto error;
    }

    return wql_ctx;
    error:
    wr_wql_free(wql_ctx);
    return NULL;
}

uint32_t
wr_wql_run(void *w)
{
    uint32_t result = 1;
    if(w == NULL) return 0;

    wr_wql_ctx_t wql_ctx = (wr_wql_ctx_t) w;

    if(!wr_enumerate(wql_ctx->protocol_ctx, 
            wql_ctx->resourceuri, NULL, wql_ctx->query, NULL)) {
        result = 0;
        goto end;
    }

    if(!wr_pull_all(wql_ctx->protocol_ctx, wql_ctx->resourceuri)) {
        result = 0;
        goto end;
    }

    if(wql_ctx->xml_response != NULL) {
        xmlFreeDoc(wql_ctx->xml_response);
    }
    wql_ctx->xml_response = wr_result_toxml(wql_ctx->protocol_ctx);
    if(wql_ctx->xml_response == NULL) {
        fprintf(stderr, "Error - Unable to make a copy of the result XML.\n");
        result = 0;
        goto end;
    }

    end:
    return result;
}

xmlDocPtr
wr_wql_response_toxml(void *w)
{
    wr_wql_ctx_t wql_ctx = (wr_wql_ctx_t) w;

    if(wql_ctx == NULL) return NULL;
    return wql_ctx->xml_response;
}

xmlDocPtr
wr_wql_schema_toxml(void *w)
{
    wr_wql_ctx_t wql_ctx = (wr_wql_ctx_t) w;

    if(wql_ctx == NULL) return NULL;
    return wql_ctx->xml_schema;
}

uint64_t
wr_wql_get_integer(void *w, const char *property)
{
    wr_wql_ctx_t wql_ctx = (wr_wql_ctx_t) w;
    char *xPathExpr;
    xmlNodePtr node;
    char *type, *str_value;
    uint64_t l_value;
    char *nil;

    if(wql_ctx == NULL || wql_ctx->xml_schema == NULL || 
        wql_ctx->xml_response == NULL) return -1;

    asprintf(&xPathExpr, "//CLASS/PROPERTY[@NAME='%s']", property);
    if(xPathExpr == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for xpath expression.\n");
        return -1;
    }
    xml_find_first(&node, wql_ctx->xml_schema, xPathExpr, NULL, NULL);
    free(xPathExpr);
    if(node == NULL) {
        fprintf(stderr, "Error - Property \"%s\" not found in class \"%s\".\n", 
            property, wql_ctx->classname);
        return -1;
    }

    type = xmlGetProp(node, "TYPE");
    if(type == NULL) {
        fprintf(stderr, "Error - Invalid schema.\n");
        return -1;
    }

    if(strncmp(type, "uint", 4) != 0 && strncmp(type, "sint", 4) != 0) {
        free(type);
        fprintf(stderr, "Error - Property cannot be converted to integer.\n");
        return -1;
    }
    free(type);

    asprintf(&xPathExpr, "//p:%s/p:%s", wql_ctx->classname, property);
    if(xPathExpr == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for xpath expression.\n");
        return -1;
    }
    xml_find_first(&node, wql_ctx->xml_response, xPathExpr, "p", wql_ctx->classuri);
    free(xPathExpr);
    if(node == NULL) {
        fprintf(stderr, "Error - No elements found.\n");
        return -1;
    }

    nil = xmlGetProp(node, "nil");
    if(nil != NULL) {
        free(nil);
        return -1;
    } else {
        str_value = xmlNodeGetContent(node);
    }
    l_value = strtol(str_value, NULL, 10);
    free(str_value);
    return l_value;
}
