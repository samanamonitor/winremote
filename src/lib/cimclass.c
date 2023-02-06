#include <libxml/tree.h>
#include <string.h>
#include "protocol.h"
#include "cimclass.h"
#include "xml.h"

char *_cimval_name[] = {
    "invalid",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "sint8",
    "sint16",
    "sint32",
    "sint64",
    "real32",
    "real64",
    "string",
    "datetime",
    "boolean",
    "octetstring",
    "array",
    0
};

size_t _cimval_size[] = {
    -1,
    sizeof(uint8_t),
    sizeof(uint16_t),
    sizeof(uint32_t),
    sizeof(uint64_t),
    sizeof(int8_t),
    sizeof(int16_t),
    sizeof(int32_t),
    sizeof(int64_t),
    sizeof(float),
    sizeof(double),
    -1,
    -1,
    sizeof(uint8_t),
    -1,
    -1
};

static uint32_t
cimval_typeid_from_string(const char *type)
{
    for(uint32_t i = 0; _cimval_name[i] != NULL; i++) {
        if(!strcmp(type, _cimval_name[i])) {
            return i;
        }
    }
    return -1;
}

void
cimval_value_print(uint32_t typeid, void *value)
{
    if(value == NULL) {
        printf("<NULL>");
        return;
    }
    switch(typeid) {
    case CIM_UINT8:
        printf("%d", *((uint8_t*)value));
        break;
    case CIM_UINT16:
        printf("%d", *((uint16_t*)value));
        break;
    case CIM_UINT32:
        printf("%d", *((uint32_t*)value));
        break;
    case CIM_UINT64:
        printf("%ld", *((uint64_t*)value));
        break;
    case CIM_SINT8:
        printf("%d", *((int8_t*)value));
        break;
    case CIM_SINT16:
        printf("%d", *((int16_t*)value));
        break;
    case CIM_SINT32:
        printf("%d", *((int32_t*)value));
        break;
    case CIM_SINT64:
        printf("%ld", *((int64_t*)value));
        break;
    case CIM_REAL32:
        printf("%f", *((float*)value));
        break;
    case CIM_REAL64:
        printf("%lf", *((double*)value));
        break;
    case CIM_STRING:
    case CIM_DATETIME:
        printf("\"%s\"", *(char**)value);
        break;
    case CIM_BOOLEAN:
        printf("%s", *((uint8_t*)value) ? "<true>" : "<false>");
        break;
    case CIM_OCTETSTRING:
        printf("(bin)");
        break;
    default:
        printf("(invalid type)");
        break;
    }
}

uint32_t
cimval_value_set(cimval_t cv, const char *value)
{
    uint32_t result = 1;
    void *new_value;
    size_t new_size = cv->size == -1 ? sizeof(char **) : cv->size;

    if(value == NULL) return 1;


    if(cv->is_array) {

        cv->array_len++;
        if(cv->array_len > cv->array_max) {
            cv->array_max += 10;
            void *temp = realloc(cv->value, new_size * (cv->array_max + 1));
            if(temp == NULL) {
                fprintf(stderr, "Error - Unable to reserver memory for CIM Value\n");
                return 0;
            }
            cv->value = temp;
        }

        new_value = cv->value + (new_size * (cv->array_len - 1));

    } else {
        if(cv->value != NULL) {
            fprintf(stderr, "Error - Value already defined.\n");
            return 0;
        }
        cv->value = calloc(1, new_size);
        new_value = cv->value;
    }

    switch(cv->type) {
    case CIM_UINT8:
        *((uint8_t*)new_value) = (uint8_t) strtol(value, NULL, 10);
        break;
    case CIM_UINT16:
        *((uint16_t*)new_value) = (uint16_t) strtol(value, NULL, 10);
        break;
    case CIM_UINT32:
        *((uint32_t*)new_value) = (uint32_t) strtol(value, NULL, 10);
        break;
    case CIM_UINT64:
        *((uint64_t*)new_value) = (uint64_t) strtoul(value, NULL, 10);
        break;
    case CIM_SINT8:
        *((int8_t*)new_value) = (int8_t) strtol(value, NULL, 10);
        break;
    case CIM_SINT16:
        *((int16_t*)new_value) = (int16_t) strtol(value, NULL, 10);
        break;
    case CIM_SINT32:
        *((int32_t*)new_value) = (int32_t) strtol(value, NULL, 10);
        break;
    case CIM_SINT64:
        *((int64_t*)new_value) = (int64_t) strtol(value, NULL, 10);
        break;
    case CIM_REAL32:
        *((float*)new_value) = strtof(value, NULL);
        break;
    case CIM_REAL64:
        *((double*)new_value) = (double) strtod(value, NULL);
        break;
    case CIM_STRING:
    case CIM_DATETIME:
        *((char**)new_value) = strdup(value);
        break;
    case CIM_BOOLEAN:
        *((uint8_t*)new_value) = strcmp(value, "true") == 0 ? 1 : 0;
        break;
    case CIM_OCTETSTRING:
        new_value = NULL;
        break;
    default:
        fprintf(stderr, "(invalid type)");
        result = 0;
        break;
    }
    return result;
}

void
cimval_print(cimval_t cv)
{
    if(cv == NULL || cv->value == NULL) return;
    printf("| %s[%s(%ld)]): ", cv->name,
        cv->type > 0 ? _cimval_name[cv->type] : "(invalid)", cv->size);
    if(cv->is_array) {
        printf("[ ");
        for(int i = 0; i < cv->array_len; i++) {
            size_t s = cv->size == -1 ? sizeof(char**) : cv->size;
            cimval_value_print(cv->type, cv->value + (s * i));
            printf(", ");
        }
        printf(" ]");
    } else {
        cimval_value_print(cv->type, cv->value);
    }
    printf("\n");
}

cimval_t
cimval_new(const char *name, const char *type_name, uint32_t is_array)
{
    cimval_t cv;
    uint32_t typeid;

    if(name == NULL || type_name == NULL) return NULL;
    typeid = cimval_typeid_from_string(type_name);
    if(typeid == -1) {
        fprintf(stderr, "Error - Invalid cimval type %s\n", type_name);
        goto error;
    }

    cv = calloc(1, sizeof(struct _cimval));
    if(cv == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for cimvalue.\n");
        goto error;
    }
    cv->type = typeid;
    cv->name = strdup(name);
    if(cv->name == NULL) goto error;
    cv->size = _cimval_size[typeid];
    cv->value = NULL;
    cv->is_array = is_array;

    return cv;

    error:
    if(cv == NULL) return NULL;
    if(cv->name) free(cv->name);
    free(cv);
}

void
cimval_free(cimval_t cv)
{
    if(cv == NULL) return;
    if(cv->name) free(cv->name);
    if(cv->value) {
        if(cv->type == CIM_STRING || cv->type == CIM_DATETIME) {
            uint32_t array_len = cv->is_array ? cv->array_len : 1;
            char **s = (char**)cv->value;
            for(int i = 0; i < array_len; i++) {
                if(s[i]) free(s[i]);
            }
        }
        free(cv->value);
    }
    free(cv);
}

cimclass_t
cimclass_new(const char *name, uint32_t property_max)
{
    cimclass_t cimclass = NULL;

    if(name == NULL) return NULL;
    cimclass = calloc(1, sizeof(struct _cimclass));
    if(cimclass == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for CIM Class.\n");
        return NULL;
    }

    cimclass->name = strdup(name);
    if(cimclass->name == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for CIM Class name.\n");
        free(cimclass);
        return NULL;
    }
    cimclass->property_count = 0;
    cimclass->__property_max = property_max + 1;
    cimclass->__property_step = 10;

    cimclass->property = calloc(1, sizeof(cimval_t) * property_max);

    return cimclass;

    error:
    if(cimclass == NULL) return NULL;
    if(cimclass->name) free(cimclass->name);
    if(cimclass->property) free(cimclass->property);
    free(cimclass);
    return NULL;
}

void
cimclass_free(cimclass_t *cimclass_p)
{
    cimclass_t cimclass;
    if(cimclass_p == NULL || *cimclass_p == NULL) return;

    cimclass = *cimclass_p;
    if(cimclass->name) free(cimclass->name);
    for(int i = 0; i < cimclass->property_count; i++) {
        cimval_free(cimclass->property[i]);
    }
    if(cimclass->property) free(cimclass->property);
    free(*cimclass_p);
    *cimclass_p = NULL;
}

void
cimclass_print(cimclass_t cimclass)
{
    if(cimclass == NULL) return;

    printf("ClassName      : %s\n", cimclass->name);
    printf("property_count : %d\n", cimclass->property_count);
    for(int i = 0; i < cimclass->property_count; i++) {
        cimval_print(cimclass->property[i]);
    }
}

uint32_t
cimclass_property_add(cimclass_t cimclass, const char *name, const char *type_name, 
        uint32_t is_array)
{
    if(cimclass == NULL || name == NULL || type_name == NULL) return 0;

    if(cimclass->property_count >= cimclass->__property_max) {
        cimclass->__property_max += cimclass->__property_step;
        void *temp = realloc(cimclass->property, sizeof(cimval_t) * cimclass->__property_max);
        if(temp == NULL) {
            fprintf(stderr, "Error - Unable to reserve memory for class property array.\n");
            return 0;
        }
        cimclass->property = temp;
    }

    cimclass->property[cimclass->property_count++] = cimval_new(name, type_name, is_array);
    return 1;
}

cimclass_t
cimclass_copy(cimclass_t source)
{
    cimclass_t copy = NULL;
    copy = cimclass_new(source->name, source->property_count);
    if(copy == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for cimclass copy.\n");
        return NULL;
    }
    for(int i = 0; i < source->property_count; i++) {
        if(!cimclass_property_add(copy, source->property[i]->name, 
                _cimval_name[source->property[i]->type], source->property[i]->is_array)) {
            goto error;
        }
    }
    return copy;

    error:
    cimclass_free(&copy);
    return NULL;
}


cimval_t
cimclass_property_value_get(cimclass_t cimclass, const char *name)
{
    if(cimclass == NULL || name == NULL) return NULL;

    for(int i = 0; i < cimclass->property_count; i++) {
        if(!strcmp(cimclass->property[i]->name, name)) {
            return cimclass->property[i];
        }
    }
    return NULL;
}

uint32_t
cimclass_property_value_set(cimclass_t cimclass, const char *name, const char *value)
{
    cimval_t cim_property = NULL;

    if(cimclass == NULL || name == NULL) return 0;

    cim_property = cimclass_property_value_get(cimclass, name);
    if(cim_property == NULL) return 0;

    cimval_value_set(cim_property, value);
    return 1;
}

cimclass_t
cimschema_from_xmlschema(xmlDocPtr doc)
{
    uint32_t result = 1;
    xmlNodePtr xml_class, xml_property;
    cimclass_t cimclass;
    char *class_name;

    xml_find_first(&xml_class, doc, "//CLASS", NULL, NULL);
    if(xml_class == NULL) return NULL;

    class_name = xmlGetProp(xml_class, "NAME");
    if(class_name == NULL) return NULL;

    cimclass = cimclass_new(class_name, xmlChildElementCount(xml_class));
    if(cimclass == NULL) {
        result = 0;
        goto error;
    }
    free(class_name);

    xml_property = xmlFirstElementChild(xml_class);
    do {
        char *name, *type_name;
        uint32_t is_array;

        if(strncmp(xml_property->name, "PROPERTY", 8) != 0) continue;

        if(strcmp(xml_property->name, "PROPERTY.ARRAY") == 0) {
            is_array = 1;
        } else {
            is_array = 0;
        }
        name = xmlGetNsProp(xml_property, "NAME", NULL);
        if(name == NULL) {
            fprintf(stderr, "Error - Property has no attribute \"NAME\".\n");
            goto error;
        }
        type_name = xmlGetNsProp(xml_property, "TYPE", NULL);
        if(type_name == NULL) {
            fprintf(stderr, "Error - Property has no attribute \"TYPE\".\n");
            goto error;
        }
        if(!cimclass_property_add(cimclass, name, type_name, is_array)) {
            free(name);
            free(type_name);
            result = 0;
            goto error;
        }
        free(name);
        free(type_name);

    } while((xml_property = xmlNextElementSibling(xml_property)));

    return cimclass;

    error:
    cimclass_free(&cimclass);
    return NULL;
}

uint32_t
cimclass_from_xml_class(cimclass_t cimclass, xmlNodePtr class_node)
{
    xmlNodePtr xml_property;
    if(cimclass == NULL || class_node == NULL) return 0;

    xml_property = xmlFirstElementChild(class_node);
    do {
        char *value;
        value = xmlGetProp(xml_property, "nil");
        if(value != NULL) {
            free(value);
            value = NULL;
        } else {
            value = xmlNodeGetContent(xml_property);
        }
        if(!cimclass_property_value_set(cimclass, xml_property->name, value)) {
            if(value) free(value);
            fprintf(stderr, "Warning - Cannot set property %s.\n", xml_property->name);
        }
        if(value) free(value);
    } while(xml_property = xmlNextElementSibling(xml_property));
    return 1;
}


cimclass_set_t
cimclass_set_from_xml_doc(xmlDocPtr xml_class, cimclass_t cimclass_schema)
{
    cimclass_set_t cimclass_set;
    xmlNodePtr xml_item_set, xml_class_node;
    uint32_t cimclass_set_count;

    xml_find_first(&xml_item_set, xml_class, "//n:Items", "n", 
        "http://schemas.xmlsoap.org/ws/2004/09/enumeration");
    cimclass_set_count = xmlChildElementCount(xml_item_set);

    cimclass_set = cimclass_set_new(cimclass_set_count);
    if(cimclass_set == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for cimclass set.\n");
        goto error;
    }

    xml_class_node = xmlFirstElementChild(xml_item_set);
    for(int i = 0; i < cimclass_set_count && xml_class_node; i++) {
        cimclass_t cs = cimclass_copy(cimclass_schema);

        if(cs == NULL) {
            fprintf(stderr, "Error - Unable to copy cimclass from schema.\n");
            goto error;
        }
        if(!cimclass_from_xml_class(cs, xml_class_node)) {
            free(cs);
            fprintf(stderr, "Error - Unable to extract values from xml node.\n");
            goto error;
        }
        cimclass_set->node[i] = cs;
        xml_class_node = xmlNextElementSibling(xml_class_node);
    }

    cimclass_set->node[cimclass_set_count] = NULL;
    return cimclass_set;

    error:
    cimclass_set_free(&cimclass_set);
    return NULL;
}

void
cimclass_set_free(cimclass_set_t* cimclass_set)
{
    if(cimclass_set == NULL || *cimclass_set == NULL) return;

    if((*cimclass_set)->node == NULL) goto end;

    for(int i = 0; i < (*cimclass_set)->nodeNr; i++) {
        if((*cimclass_set)->node[i]) 
            free((*cimclass_set)->node[i]);
    }
    free((*cimclass_set)->node);

    end:
    free(*cimclass_set);
    *cimclass_set = NULL;
}

cimclass_set_t
cimclass_set_new(uint32_t nodeMax)
{
    cimclass_set_t cs;
    cs = calloc(1, sizeof(struct _cimclass_set));
    if(cs == NULL) {
        fprintf(stderr, "Error - Unable to reserve memory for cimclass set.\n");
        return NULL;
    }
    cs->nodeNr = nodeMax;
    cs->nodeMax = nodeMax;
    if(nodeMax > 0) {
        cs->node = calloc(nodeMax + 1, sizeof(cimclass_t));
    } else {
        cs->node = NULL;
    }
    return cs;
}

void
cimclass_set_print(cimclass_set_t cimclass_set)
{
    cimclass_t *node = cimclass_set->node;
    while(*node) {
        cimclass_print(*node);
        node++;
    }
}