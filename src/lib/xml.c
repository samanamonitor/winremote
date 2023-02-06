#define _GNU_SOURCE
#include <string.h>
#include "xml.h"


#define XML_NODE_FIRST_NAME(r, name, node) do { \
    xmlNodePtr __n = r->children; \
    while(__n && strcmp(__n->name, name) != 0) { \
        __n = __n->next; \
    } \
    node = __n; \
} while(0)

#define XML_NODE_NEXT_NAME(node, name) do {\
    xmlNodePtr __n = node->next; \
    while(__n && strcmp(__n->name, name) != 0) { \
        __n = __n->next; \
    } \
} while(0)


xmlNsPtr
xml_get_ns(xmlNsPtr *list, const char *prefix)
{
    if(list == NULL || prefix == NULL) return NULL;

    while(*list) {
        if(!strcmp((*list)->prefix, prefix)) {
            return *list;
        }
        list++;
    }
    return NULL;
}

uint32_t
xml_add_selectorset(xmlWRDoc_p wrd, const keyval_t *selectorset)
{
    uint32_t result = 1;
    xmlNodePtr selector_set_node;
    xmlNsPtr *nslist=NULL, w;

    if(selectorset == NULL) return 1;

    nslist = xmlGetNsList(wrd->doc, wrd->envelope);
    w = xml_get_ns(nslist, "w");

    selector_set_node = xmlNewChild(wrd->header, w, BAD_CAST "SelectorSet", NULL);
    if(selector_set_node == NULL) {
        fprintf(stderr, "Error - Unable to create 'SelectorSet' node.\n");
        result = 0;
        goto end;
    }

    while(*selectorset) {
        xmlNodePtr s;
        s = xmlNewChild(selector_set_node, w, BAD_CAST "Selector", 
            BAD_CAST (*selectorset)->value);
        if(s == NULL) {
            fprintf(stderr, "Error - Unable to create 'Selector' node.\n");
            result = 0;
            goto end;
        }
        xmlNewProp(s, BAD_CAST "Name", BAD_CAST (*selectorset)->key);
        selectorset++;
    }

    end:
    if(nslist) free(nslist);
    return result;
}


uint32_t
xml_new_basic_header(xmlWRDoc_p wrd, const char *resourceuri, const char *action)
{
    uint32_t result = 1;
    xmlNodePtr header, current_node;
    xmlAttrPtr current_node_prop;
    xmlNsPtr *nslist, a, w;
    uint8_t uuid_str[48];
    uuid_t messageid;

    nslist = xmlGetNsList(wrd->doc, wrd->envelope);
    if(nslist == NULL) {
        fprintf(stderr, "Error. Unable to create list of namespaces.\n");
        result = 0;
        goto end;
    }

    a = xml_get_ns(nslist, "a");
    if(a == NULL) {
        fprintf(stderr, "Error. Namespace 'a' not found.\n");
        result = 0;
        goto end;
    }

    w = xml_get_ns(nslist, "w");
    if(w == NULL) {
        fprintf(stderr, "Error. Namespace 'w' not found.\n");
        result = 0;
        goto end;
    }

    sprintf(uuid_str, "uuid:");
    uuid_generate(messageid);
    uuid_unparse_upper(messageid, uuid_str + 5);

    header = wrd->header;

    current_node = xmlNewChild(header, a, "To", BAD_CAST "http://windows-host:5985/wsman");
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'To' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(header, a, "ReplyTo", NULL);
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'ReplyTo' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(current_node, a, "Address", BAD_CAST "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous");
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'ReplyTo' node.\n");
        result = 0;
        goto end;
    }
    current_node_prop = xmlNewProp(current_node, BAD_CAST "mustUnderstand", BAD_CAST "true");
    if(current_node_prop == NULL) {
        fprintf(stderr, "Error. Unable to set 'mustUnderstand' property to 'Address' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(header, w, "MaxEnvelopeSize", BAD_CAST "153600");
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'MaxEnvelopeSize' node.\n");
        result = 0;
        goto end;
    }
    current_node_prop = xmlNewProp(current_node, BAD_CAST "mustUnderstand", BAD_CAST "true");
    if(current_node_prop == NULL) {
        fprintf(stderr, "Error. Unable to set 'mustUnderstand' property to 'MaxEnvelopeSize' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(header, a, "MessageID", BAD_CAST uuid_str);
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'MessageID' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(header, w, "Locale", NULL);
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'Locale' node.\n");
        result = 0;
        goto end;
    }
    current_node_prop = xmlNewProp(current_node, BAD_CAST "mustUnderstand", BAD_CAST "false");
    if(current_node_prop == NULL) {
        fprintf(stderr, "Error. Unable to set 'mustUnderstand' property to 'Locale' node.\n");
        result = 0;
        goto end;
    }
    current_node_prop = xmlNewProp(current_node, BAD_CAST "xml:lang", BAD_CAST "en-US");
    if(current_node_prop == NULL) {
        fprintf(stderr, "Error. Unable to set 'xml:lang' property to 'Locale' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(header, w, "DataLocale", NULL);
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'DataLocale' node.\n");
        result = 0;
        goto end;
    }
    current_node_prop = xmlNewProp(current_node, BAD_CAST "mustUnderstand", BAD_CAST "false");
    if(current_node_prop == NULL) {
        fprintf(stderr, "Error. Unable to set 'mustUnderstand' property to 'DataLocale' node.\n");
        result = 0;
        goto end;
    }
    current_node_prop = xmlNewProp(current_node, BAD_CAST "xml:lang", BAD_CAST "en-US");
    if(current_node_prop == NULL) {
        fprintf(stderr, "Error. Unable to set 'xml:lang' property to 'DataLocale' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(header, w, "OperationTimeout", BAD_CAST "PT20S");
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'OperationTimeout' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(header, w, "ResourceURI", BAD_CAST resourceuri);
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'ResourceURI' node.\n");
        result = 0;
        goto end;
    }
    current_node_prop = xmlNewProp(current_node, BAD_CAST "mustUnderstand", BAD_CAST "true");
    if(current_node_prop == NULL) {
        fprintf(stderr, "Error. Unable to set 'mustUnderstand' property to 'ResourceURI' node.\n");
        result = 0;
        goto end;
    }

    current_node = xmlNewChild(header, a, "Action", BAD_CAST action);
    if(current_node == NULL) {
        fprintf(stderr, "Error. Unable to create 'Action' node.\n");
        result = 0;
        goto end;
    }
    current_node_prop = xmlNewProp(current_node, BAD_CAST "mustUnderstand", BAD_CAST "true");
    if(current_node_prop == NULL) {
        fprintf(stderr, "Error. Unable to set 'mustUnderstand' property to 'Action' node.\n");
        result = 0;
        goto end;
    }

    end:
    if(nslist) free(nslist);
    return result;
}

xmlWRDoc_p
xml_new_wr_doc()
{
    xmlNsPtr xsi, env, a, w, n, xsd;
    xmlWRDoc_p wrd = calloc(1, sizeof(xmlWRDoc_desc));
    if(wrd == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for xmlWRDoc.\n");
        goto error;
    }

    wrd->doc = xmlNewDoc(BAD_CAST XML_DEFAULT_VERSION);
    if (wrd->doc == NULL) {
        fprintf(stderr, "Error creating the xml document tree\n");
        goto error;
    }

    wrd->envelope = xmlNewDocNode(wrd->doc, NULL, BAD_CAST "env:Envelope", NULL);
    if (wrd->envelope == NULL) {
        fprintf(stderr, "Error creating the xml node\n");
        goto error;
    }
    xmlDocSetRootElement(wrd->doc, wrd->envelope);

    env = xmlNewNs(wrd->envelope, BAD_CAST "http://www.w3.org/2003/05/soap-envelope", BAD_CAST "env");
    if(env == NULL) {
        fprintf(stderr, "Error - Unable to create 'env' namespace.\n");
        goto error;
    }
    a = xmlNewNs(wrd->envelope, BAD_CAST "http://schemas.xmlsoap.org/ws/2004/08/addressing", BAD_CAST "a");
    if(a == NULL) {
        fprintf(stderr, "Error - Unable to create 'a' namespace.\n");
        goto error;
    }
    w = xmlNewNs(wrd->envelope, BAD_CAST "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", BAD_CAST "w");
    if(w == NULL) {
        fprintf(stderr, "Error - Unable to create 'w' namespace.\n");
        goto error;
    }
    n = xmlNewNs(wrd->envelope, BAD_CAST "http://schemas.xmlsoap.org/ws/2004/09/enumeration", BAD_CAST "n");
    if(n == NULL) {
        fprintf(stderr, "Error - Unable to create 'n' namespace.\n");
        goto error;
    }

    wrd->header = xmlNewChild(wrd->envelope, env, "Header", NULL);
    if (wrd->header == NULL) {
        fprintf(stderr, "Error creating header\n");
        goto error;
    }
    wrd->body = xmlNewChild(wrd->envelope, env, "Body", NULL);
    if (wrd->body == NULL) {
        fprintf(stderr, "Error creating body\n");
        goto error;
    }

    return wrd;
    error:
    if(wrd && wrd->doc) xmlFreeDoc(wrd->doc);
    if(wrd) free(wrd);
    return NULL;
}

void
xml_free_wr_doc(xmlWRDoc_p wrd)
{
    if(wrd == NULL) return;
    if(wrd->doc) xmlFreeDoc(wrd->doc);
    free(wrd);
}

size_t
xml_to_buffer(char *out_xml, size_t max_buffer_size, xmlDocPtr doc)
{
    xmlBufferPtr buf;
    xmlOutputBufferPtr outbuf;
    size_t out_xml_len;

    if(doc == NULL || out_xml == NULL) return 0;

    buf = xmlBufferCreate();
    if (buf == NULL) {
        fprintf(stderr, "Error creating the xml buffer\n");
        out_xml_len = -1;
        goto end;
    }

    outbuf = xmlOutputBufferCreateBuffer(buf, xmlFindCharEncodingHandler(UTF8));
    if(outbuf == NULL) {
        fprintf(stderr, "Error creating output buffer\n");
        out_xml_len = -1;
        goto end;
    }
    if(xmlSaveFileTo(outbuf, doc, UTF8) == -1) {
        xmlOutputBufferClose(outbuf);
        out_xml_len = -1;
        goto end;
    }

    out_xml_len = strlen(buf->content);
    if(out_xml_len > max_buffer_size) {
        out_xml_len = max_buffer_size - 1;
    }
    memcpy(out_xml, buf->content, out_xml_len);
    out_xml[out_xml_len] = '\0';

    end:
    xmlBufferFree(buf);
    return out_xml_len;
}

uint32_t
xml_find_all(xmlNodeSetPtr *nodes, xmlDocPtr doc, const char *xpathExpr,
        const char *nsSuffix, const char *nsHref)
{
    /* user must free nodeset even if nodeset has 0 nodes */
    uint32_t size;
    int i;
    xmlXPathContextPtr xpathCtx; 
    xmlXPathObjectPtr xpathObj; 

    *nodes = NULL;
    size = 0;
    if(doc == NULL || xpathExpr == NULL) return 0;

    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        goto end;
    }
    if(nsSuffix != NULL && nsHref != NULL) {
        xmlXPathRegisterNs(xpathCtx, nsSuffix, nsHref);
    }

    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
    if(xpathObj == NULL) {
        goto end;
    }
    *nodes = xpathObj->nodesetval;
    size = (*nodes) ? (*nodes)->nodeNr : 0;

    end:
    xmlXPathFreeNodeSetList(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    return size;
}

uint32_t
xml_find_first(xmlNodePtr *node, xmlDocPtr doc, const char *xpathExpr,
        const char *nsSuffix, const char *nsHref)
{
    uint32_t size = 0;
    xmlNodeSetPtr nodes = NULL;

    if(doc == NULL || xpathExpr == NULL) return 0;

    size = xml_find_all(&nodes, doc, xpathExpr, nsSuffix, nsHref);
    if(size == 0) {
        goto end;
    }

    if(node != NULL) {
        *node = NULL;
        if(nodes->nodeTab[0]->type == XML_ELEMENT_NODE) {
            *node = nodes->nodeTab[0];
        }
    }

    end:
    xmlXPathFreeNodeSet(nodes);
    return size ? 1 : 0;
}

uint32_t
xml_get_uuid(uuid_t uuid, xmlDocPtr doc, const char *xpathExpr, 
        const char *nsSuffix, const char *nsHref)
{
    int result = 0;
    xmlNodePtr node;
    char *uuid_str = NULL;

    if(doc == NULL || xpathExpr == NULL || nsSuffix == NULL || 
        nsHref == NULL || uuid == NULL) return 0;

    memset(uuid, 0, sizeof(uuid_t));
    if(!xml_find_first(&node, doc, xpathExpr, nsSuffix, nsHref)) {
        result = 0;
        goto end;
    }
    uuid_str = xmlNodeGetContent(node);
    if(strlen(uuid_str) != 41) {
        result = 0;
        goto end;
    }
    if(uuid_parse(uuid_str + 5, uuid) == -1) {
        /* Error */
        result = 0;
    } else {
        result = 1;
    }

    end:
    if(uuid_str) free(uuid_str);
    return result;
}

uint32_t
xml_schema_is_number(const xmlDocPtr schema, const char *name)
{
    xmlNodePtr schema_node = NULL;
    char *xPathExpr = NULL, *type = NULL;

    if(schema == NULL || name == NULL) return 0;
    asprintf(&xPathExpr, "//CLASS/PROPERTY[@NAME='%s']", name);
    if(xPathExpr == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for xpath expression.\n");
        return 0;
    }
    if(!xml_find_first(&schema_node, schema, xPathExpr, NULL, NULL)) {
        free(xPathExpr);
        return 0;
    }
    free(xPathExpr);

    if(schema_node == NULL) {
        fprintf(stderr, "Error - Property \"%s\" not found in class.\n", 
            name);
        return 0;
    }

    type = xmlGetProp(schema_node, "TYPE");
    if(type == NULL) {
        fprintf(stderr, "Error - Invalid schema.\n");
        return 0;
    }

    if(strncmp(type, "uint", 4) != 0 && strncmp(type, "sint", 4) != 0) {
        fprintf(stderr, "Error - Property cannot be converted to integer. (%s)\n", type);
        free(type);
        return 0;
    }
    free(type);

    return 1;
}

uint32_t
xml_prop_node_to_number(xmlNodePtr property_node, xmlDocPtr schema, uint64_t *value)
{
    char *xPathExpr = NULL;
    const char *property;
    char *type, *str_value, *nil;
    xmlNodePtr schema_node = NULL;

    if(property_node == NULL || schema == NULL || value == NULL) return 0;

    property = property_node->name;

    if(!xml_schema_is_number(schema, property)) {
        return 0;
    }

    nil = xmlGetProp(property_node, "nil");
    if(nil != NULL) {
        *value = 0;
        free(nil);
        return 0;
    } else {
        str_value = xmlNodeGetContent(property_node);
    }
    *value = strtol(str_value, NULL, 10);
    free(str_value);
    return 1;
}

uint32_t
xml_class_get_prop_num(uint64_t *value, const xmlNodePtr class, const char *name, const xmlDocPtr schema)
{
    xmlNodePtr property = NULL;
    char *nil = NULL, *str_value = NULL;

    if(class == NULL || schema == NULL || value == NULL) return 0;

    if(!xml_schema_is_number(schema, name)) {
        return 0;
    }

    property = class->children;
    do {
        if(strcmp(property->name, name) != 0) continue;

        nil = xmlGetProp(property, "nil");
        if(nil != NULL) {
            *value = 0;
            free(nil);
            return 0;
        } else {
            str_value = xmlNodeGetContent(property);
            if(str_value == NULL) {
                return 0;
            }
        }
        *value = strtol(str_value, NULL, 10);
        free(str_value);
        return 1;

    } while(property = property->next);
    return 0;
}

uint32_t
xml_class_get_prop_string(char **value, const xmlNodePtr class, const char *name, const xmlDocPtr schema)
{
    xmlNodePtr property = NULL;
    char *nil = NULL;

    if(class == NULL || schema == NULL || value == NULL) return 0;

    property = class->children;
    do {
        if(strcmp(property->name, name) != 0) continue;

        nil = xmlGetProp(property, "nil");
        if(nil != NULL) {
            *value = NULL;
            free(nil);
            return 0;
        } else {
            *value = xmlNodeGetContent(property);
            if(*value == NULL) {
                return 0;
            }
            return 1;
        }

    } while(property = property->next);
    return 0;
}
