#ifndef __CIMCLASS_H_
#define __CIMCLASS_H_

typedef enum _cimval_type {
    CIM_INVALID,
    CIM_UINT8,
    CIM_UINT16,
    CIM_UINT32,
    CIM_UINT64,
    CIM_SINT8,
    CIM_SINT16,
    CIM_SINT32,
    CIM_SINT64,
    CIM_REAL32,
    CIM_REAL64,
    CIM_STRING,
    CIM_DATETIME,
    CIM_BOOLEAN,
    CIM_OCTETSTRING
} cimval_type_e;

typedef struct _cimval {
    cimval_type_e type;
    uint32_t is_array;
    uint32_t array_len;
    uint32_t array_max;
    char *name;
    size_t size;
    void *value;
} *cimval_t;

typedef struct _cimclass {
    char *name;
    uint32_t property_count;
    uint32_t __property_max;
    uint32_t __property_step;
    cimval_t *property;
} *cimclass_t;

typedef struct _cimclass_set {
    uint32_t nodeNr;
    uint32_t nodeMax;
    cimclass_t *node;
} *cimclass_set_t;

cimclass_t cimschema_from_xmlschema(xmlDocPtr doc);
cimclass_set_t cimclass_set_from_xml_doc(xmlDocPtr xml_class, cimclass_t cimclass_schema);
cimclass_set_t cimclass_set_new(uint32_t nodeMax);

void cimclass_set_print(cimclass_set_t cimclass_set);
void cimclass_set_free(cimclass_set_t* cimclass_set);
void cimclass_free(cimclass_t *cimclass_p);

cimval_t cimclass_property_value_get(cimclass_t cimclass, const char *name);

#endif
