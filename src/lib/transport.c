#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_ntlmssp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <regex.h>
#include "transport.h"

#define SAMM_USERAGENT "User-Agent: samm/1.0.0"

struct wr_transport_ctx {
    gss_ctx_id_t gss_ctx;
    CURL *curl_ctx;
    gss_OID_set_desc *mechsp;
    gss_cred_id_t cred;
    gss_name_t target_name;
    uint64_t response_code;
    struct ntlm_buffer response;
};

static size_t 
header_callback(char *ptr, size_t size, size_t nmemb, void *challenge)
{
    int data_len = size*nmemb;

    if(challenge == NULL) return data_len;
    if(data_len < 18) return data_len;
    if(strncmp(ptr, "WWW-Authenticate: Negotiate", 27) != 0) return data_len;

    struct ntlm_buffer *buffer = (struct ntlm_buffer*) challenge;
    ptr += 27;
    data_len -= 27;
    while(*(ptr++) != ' ' && data_len-- > 0);
    if(data_len < 1) return size*nmemb;

    /* Challenge is in the header, need to process it */
    buffer->length = data_len-2;
    buffer->data = calloc(1, buffer->length + 1);
    memcpy(buffer->data, ptr, buffer->length);
    return size * nmemb;
}

static void
debug_bin_print(const void *b, int len, int indent)
{
    if(b==NULL) return;
    const char *bin = (const char *)b;
    char *indent_str=malloc(indent+1);
    for(int i=0; i < indent; i++) indent_str[i] = ' ';
    indent_str[indent]='\0';
    for(int i=0; i < len; i++) {
        if(i > 0 && i % 16 == 0) {
            printf("\n%s", indent_str);
        } else if (i > 0 && i % 8 == 0) {
            printf(" ");
        } else if (i == 0) {
            printf("%s", indent_str);
        } else {
            printf(" ");
        }
        printf("%02x", bin[i] & 0xff);
    }
    printf("\n");
    free(indent_str);    
}

static void
debug_bin_print_escaped_string(const void *b, int len, int indent)
{
    if(b==NULL) return;
    const char *bin = (const char *)b;
    char *indent_str=malloc(indent+1);
    for(int i=0; i < indent; i++) indent_str[i] = ' ';
    indent_str[indent]='\0';
    printf("%s", indent_str);
    for(int i=0; i < len; i++) {
        printf("\\x%02x", bin[i] & 0xff);
    }
    free(indent_str);    
}

static void *
b64decode(void *outbuf, size_t *outlen, const void *inbuf, size_t buff_size)
{
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(inbuf, -1);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *outlen = BIO_read(bio, outbuf, buff_size);
    BIO_free_all(bio);
    return outbuf;
}

static void *
b64encode(void *outbuf, size_t *outlen, size_t outbuf_size, const void *in, size_t inlen)
{
    BIO *bio, *b64;
    if(in == NULL) return 0;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, in, inlen);
    BIO_flush(b64);
    *outlen = BIO_read(bio, outbuf, outbuf_size);
    *((uint8_t*)outbuf + *outlen) = '\0';

    BIO_free_all(b64);
    return outbuf;
}

static uint32_t
list_mechs()
{
    OM_uint32 maj_stat, min_stat;
    gss_OID_set oid_set;
    maj_stat = gss_indicate_mechs(&min_stat, &oid_set);
    if(maj_stat != GSS_S_COMPLETE) {
        return 0;
    }

    printf("Available mechs: count=%ld\n", oid_set->count);
    gss_OID j = oid_set->elements;
    for(int i = 0; i < oid_set->count; i++, j++) {
        gss_buffer_desc buf;
        gss_oid_to_str(&min_stat, j, &buf);
        if(min_stat == GSS_S_COMPLETE) {
            printf("  length=%ld value=%s\n", buf.length, (char*) buf.value);
            gss_release_buffer(&min_stat, &buf);
        } else {
            printf("Error\n");
            return 0;
        }
    }
    debug_bin_print(&oid_set, sizeof(oid_set), 0);
    gss_release_oid_set(&min_stat, &oid_set);
    return 1;
}

static uint32_t
names_for_mech(gss_OID oid)
{
    OM_uint32 maj_stat, min_stat;
    gss_OID_set oid_set;
    maj_stat = gss_inquire_names_for_mech(&min_stat, oid, &oid_set);
    printf("maj_stat=%d\n", maj_stat);
    if(maj_stat != GSS_S_COMPLETE) {
        printf("Error: Unable to inquire names\n");
        return 0;
    }

    gss_OID element = oid_set->elements;
    for(int i = 0; i < oid_set->count; i++, element++) {
        printf("  length=%d\n", element->length);
        debug_bin_print(element->elements, element->length, 5);
    }
    gss_release_oid_set(&min_stat, &oid_set);
    return 1;
}

#if 0
static uint32_t
set_ntlm_flags(gss_cred_id_t cred, uint32_t flags)
{
    /* test value 0xe2898236 */
    OM_uint32 maj_stat, min_stat;
    gss_OID_desc o;
    o.length = GSS_NTLMSSP_NEG_FLAGS_OID_LENGTH;
    o.elements = GSS_NTLMSSP_NEG_FLAGS_OID_STRING;
    gss_buffer_desc ntlm_flags;
    ntlm_flags.length = sizeof(flags);
    ntlm_flags.value = &flags;
    maj_stat = gss_set_cred_option(&min_stat, &cred, &o, &ntlm_flags);
    if (maj_stat != GSS_S_COMPLETE) {
        printf("Error - setting flags %x %x\n", maj_stat, min_stat);
        return 0;
    }
    return 1;
}
#endif
static uint32_t
get_ntlm_session_key(gss_ctx_id_t gss_context)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_set_t buffer_set;

    maj_stat = gss_inquire_sec_context_by_oid(&min_stat, gss_context, GSS_C_INQ_SSPI_SESSION_KEY, &buffer_set);
    if (maj_stat != GSS_S_COMPLETE) {
        printf("Error - Getting session key. %x %x\n", maj_stat, min_stat);
        return 0;
    }
    for(int i=0; i < buffer_set->count; i++) {
        gss_buffer_t b;
        b = (gss_buffer_t) buffer_set->elements;
        printf("ExportedSessionKey=b'");
        debug_bin_print_escaped_string(b->value, b->length, 0);
        printf("'\n");
    }

    gss_release_buffer_set(&min_stat, &buffer_set);
    return 1;
}

static uint32_t
enable_ntlm_mic(gss_ctx_id_t gss_context)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_set_t buffer_set;
    gss_OID_desc o;
    o.length = GSS_SPNEGO_REQUIRE_MIC_OID_LENGTH;
    o.elements = GSS_SPNEGO_REQUIRE_MIC_OID_STRING;
    maj_stat = gss_inquire_sec_context_by_oid(&min_stat, gss_context, &o, &buffer_set);
    if (maj_stat != GSS_S_COMPLETE) {
        printf("Error - setting MIC on %x %x\n", maj_stat, min_stat);
        return 0;
    }

    gss_release_buffer_set(&min_stat, &buffer_set);
    return 1;
}

void *
wr_transport_ctx_new()
{
    struct wr_transport_ctx *ctx = calloc(1, sizeof(struct wr_transport_ctx));
    if(ctx == NULL) return NULL;
    return ctx;
}

uint32_t
wr_transport_ctx_init(void *c, const char *username, const char *password, const char *url, uint32_t mech_val)
{
    uint32_t result = 1;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc tok;
    gss_name_t gss_username = GSS_C_NO_NAME;
    struct wr_transport_ctx *ctx = (struct wr_transport_ctx*) c;
    gss_OID_desc mech;

    if(ctx == NULL || username == NULL || password == NULL || url == NULL) return 0;

    ctx->cred = GSS_C_NO_CREDENTIAL;
    ctx->gss_ctx = GSS_C_NO_CONTEXT;
    if(mech_val == WR_MECH_NTLM) {
        maj_stat = gss_create_empty_oid_set(&min_stat, &ctx->mechsp);
        if(maj_stat != GSS_S_COMPLETE) {
            fprintf(stderr, "Error - Unable to create mech oid set.\n");
            result = 0;
            goto end;
        }
        gss_OID_desc mech = {
            .length = GSS_NTLMSSP_OID_LENGTH,
            .elements = GSS_NTLMSSP_OID_STRING
        };
        maj_stat = gss_add_oid_set_member(&min_stat, &mech, &ctx->mechsp);
        if(maj_stat != GSS_S_COMPLETE) {
            fprintf(stderr, "Error - Unable to add mech to oid set.\n");
            result = 0;
            goto end;
        }
    } else {
        result = 0;
        goto end;
    }

    tok.value = discard_const(username);
    tok.length = strlen(username);
    maj_stat = gss_import_name(&min_stat, &tok,
                               (gss_OID) gss_nt_user_name,
                               &gss_username);
    if (maj_stat != GSS_S_COMPLETE) {
        fprintf(stderr, "Error - parsing client name %d %d\n", maj_stat, min_stat);
        result = 0;
        goto end;
    }

    tok.value = discard_const(password);
    tok.length = strlen(password);
    min_stat=0;
    maj_stat = gss_acquire_cred_with_password(&min_stat,
                                              gss_username,
                                              &tok, 0,
                                              ctx->mechsp, GSS_C_INITIATE,
                                              &ctx->cred, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE) {
        fprintf(stderr, "Error - acquiring creds %x %x\n", maj_stat, min_stat);
        result = 0;
        goto end;
    }

    ctx->curl_ctx = curl_easy_init();
    if(ctx->curl_ctx == NULL) {
        fprintf(stderr, "Error - Unable to initialize curl context.\n");
        result = 0;
        goto end;
    }
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_CUSTOMREQUEST, "POST");

    end:
    if(gss_username != GSS_C_NO_NAME) gss_release_name(&min_stat, &gss_username);
    return result;
}

uint32_t
wr_transport_login(void *c)
{
    uint32_t result = 1;
    struct wr_transport_ctx *ctx = (struct wr_transport_ctx*) c;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc tok;
    gss_buffer_desc send_tok, recv_tok, *token_ptr;
    token_ptr = GSS_C_NO_BUFFER;
    OM_uint32 ret_flags;
    OM_uint32 gss_flags = GSS_C_INTEG_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG;
    struct ntlm_buffer challenge_buffer = { NULL, 0 };
    char *challenge = NULL;
    size_t challenge_len;
    struct curl_slist *list = NULL;
    uint64_t response_code;
    char *p;
    CURLcode res;

    if(ctx == NULL) return 0;

    ctx->target_name = GSS_C_NO_NAME;

    tok.value = "samana";
    tok.length = strlen(tok.value);
    maj_stat = gss_import_name(&min_stat, &tok,
                               (gss_OID) gss_nt_service_name,
                               &ctx->target_name);

    curl_easy_setopt(ctx->curl_ctx, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_HEADERDATA, &challenge_buffer);

    do {
        maj_stat = gss_init_sec_context(&min_stat,
                                        ctx->cred, &ctx->gss_ctx,
                                        ctx->target_name, ctx->mechsp->elements,
                                        gss_flags, 0,
                                        NULL, /* channel bindings */
                                        token_ptr, NULL, /* mech type */
                                        &send_tok, &ret_flags,
                                        NULL);  /* time_rec */
        if(GSS_ERROR(maj_stat)) {
            fprintf(stderr, "Unable to create context. %x %x\n", maj_stat, min_stat);
            result = 0;
            goto end;
        }
        if(challenge != NULL) {
            free(challenge);
            challenge = NULL;
        }

        list = curl_slist_append(list, "Content-Length: 0");
        list = curl_slist_append(list, "Connection: Keep-Alive");
        list = curl_slist_append(list, SAMM_USERAGENT);


        size_t auth_buffer_size = send_tok.length * 2.5;
        char *auth_buffer = malloc(auth_buffer_size);
        size_t auth_buffer_len;
        if(auth_buffer == NULL) {
            printf("Unable to allocate memory for auth buffer\n");
            result = 0;
            goto end;
        }
        p=auth_buffer;
        sprintf(p, "Authorization: Negotiate ");
        p += strlen(p);
        auth_buffer_size -= strlen(auth_buffer);
        b64encode(p, &auth_buffer_len, auth_buffer_size, send_tok.value, send_tok.length);
        list = curl_slist_append(list, auth_buffer);
        free(auth_buffer);
        gss_release_buffer(&min_stat, &send_tok);

        curl_easy_setopt(ctx->curl_ctx, CURLOPT_HTTPHEADER, list);

        res = curl_easy_perform(ctx->curl_ctx);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
            result = 0;
            goto end;
        }
        curl_slist_free_all(list); /* free the list again */
        list = NULL;

        if(maj_stat == GSS_S_CONTINUE_NEEDED) {
            if(challenge_buffer.data == NULL) {
                printf("Server didn't send a challenge.\n");
                result = 0;
                goto end;
            }
            challenge = calloc(1, challenge_buffer.length);
            if(challenge == NULL) {
                fprintf(stderr, "Unable to reserve memory for challenge.\n");
                free(challenge_buffer.data);
                goto end;
            }
            b64decode(challenge, &challenge_len, 
                challenge_buffer.data, challenge_buffer.length);

            recv_tok.length = challenge_len;
            recv_tok.value = challenge;
            token_ptr = &recv_tok;
            free(challenge_buffer.data);
        }
    } while(maj_stat == GSS_S_CONTINUE_NEEDED);
    if(challenge) free(challenge);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_HEADERFUNCTION, NULL);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_HEADERDATA, NULL);
    curl_easy_getinfo(ctx->curl_ctx, CURLINFO_RESPONSE_CODE, &response_code);
    if(response_code != 200) {
        fprintf(stderr, "Error. Server response code was %ld\n", response_code);
        result = 0;
        goto end;
    }
    end:
    return result;
}

void
wr_transport_free(void *c)
{
    OM_uint32 maj_stat, min_stat;
    struct wr_transport_ctx *ctx = (struct wr_transport_ctx*) c;
    if(ctx == NULL) return;
    if(ctx->mechsp != GSS_C_NO_OID_SET) 
        gss_release_oid_set(&min_stat, &ctx->mechsp);
    if(ctx->target_name != GSS_C_NO_NAME) 
        gss_release_name(&min_stat, &ctx->target_name);
    if(ctx->cred != GSS_C_NO_CREDENTIAL) 
        gss_release_cred(&min_stat, &ctx->cred);
    if(ctx->gss_ctx != GSS_C_NO_CONTEXT) 
        gss_delete_sec_context(&min_stat, &ctx->gss_ctx,
                                           GSS_C_NO_BUFFER);
    if(ctx->curl_ctx) curl_easy_cleanup(ctx->curl_ctx);
    free(ctx);
}

static uint32_t
multipart_encode(struct ntlm_buffer *payload, struct ntlm_buffer *encrypted)
{
    if(payload == NULL || encrypted == NULL || encrypted->data == NULL)
        return 0;
    uint8_t *p;

    payload->data = calloc(1, encrypted->length + 256);
    if(payload->data == NULL) {
        fprintf(stderr, "Unable to reserve memory for payload data.\n");
        return 0;
    }
    p = payload->data;
    sprintf(p, "--Encrypted Boundary\r\n"
        "\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n"
        "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%ld\r\n"
        "--Encrypted Boundary\r\n"
        "\tContent-Type: application/octet-stream\r\n", encrypted->length - 0x10);
    p += strlen(p);
    *(uint32_t*)p = 0x10;
    p += sizeof(uint32_t);
    memcpy(p, encrypted->data, encrypted->length);
    p += encrypted->length;
    sprintf(p, "--Encrypted Boundary--\r\n");
    p += strlen(p);
    payload->length = p - payload->data;
    uint8_t *ptr = realloc(payload->data, payload->length);
    payload->data = ptr;
    return 1;
}

static uint32_t
wr_prepare_encrypted_request(void *c, struct ntlm_buffer *payload, const struct ntlm_buffer* message)
{
    uint32_t result = 1;
    OM_uint32 maj_stat, min_stat;
    struct wr_transport_ctx *ctx = (struct wr_transport_ctx*) c;
    struct ntlm_buffer encrypted = { NULL, 0 };
    if(ctx == NULL || message == NULL || message->data == NULL) return 0;

    gss_buffer_desc msg_buffer = {
        .length = message->length,
        .value = message->data
    };
    gss_buffer_desc out_msg;

    uint32_t conf_state;
    maj_stat = gss_wrap (&min_stat, ctx->gss_ctx, 1, GSS_C_QOP_DEFAULT,
        &msg_buffer, &conf_state, &out_msg);
    if(GSS_ERROR(maj_stat)) {
        fprintf(stderr, "Unable to create context. %x %x\n", maj_stat, min_stat);
        result = 0;
        goto end;
    }

    encrypted.data = out_msg.value;
    encrypted.length = out_msg.length;

    if(!multipart_encode(payload, &encrypted)) {
        fprintf(stderr, "Error encoding data into multipart\n");
        result = 0;
        goto end;
    }

    end:
    gss_release_buffer(&min_stat, &out_msg);
    return result;
}

/*
 * Function: multipart_decode
 *
 * Purpose: searches for the size and start of the encrypted data.
 *
 * Arguments:
 *
 *      encrypted       (w) ntlm_buffer that will hold the encrypted data
 *                          data will point to the location where encrypted
 *                          data starts inside the received_payload variable
 *                          length will hold the amount of encrypted data.
 *      multipart_encoded (r) ntlm_buffer that holds the multipart encoded data.
 *                          data pointer will have a buffer that is NOT \0 terminated
 *                          data must contain all the payload information included
 *                          in a multipart encoded data stream.
 *
 * Returns: 1 if succesfull
 *          0 if fails. In case of failure, the reason will be printed in stderr
 *          This means that the function will be called until it returns 0.
 *
 * Effects:
 *
 * No memory reservation happens in this function.
 *
 */
static uint32_t
multipart_decode(struct ntlm_buffer *encrypted, struct ntlm_buffer *multipart_encoded)
{
    if(multipart_encoded == NULL || multipart_encoded->data == NULL || 
            encrypted == NULL) return 0;
    regex_t regex;
    regmatch_t  pmatch[1];
    regoff_t    off, len;
    const uint8_t *s = multipart_encoded->data;


    char *re = "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=";

    if (regcomp(&regex, re, REG_NEWLINE)){
        fprintf(stderr, "Error - Unable to create regex context for length.\n");
        regfree(&regex);
        return 0;
    }
    if (regexec(&regex, s, ARRAY_SIZE(pmatch), pmatch, 0)) {
        fprintf(stderr, "Error - Unable to find multipart length.\n");
        regfree(&regex);
        return 0;
    }
    regfree(&regex);
    s += pmatch[0].rm_eo;
    sscanf(s, "%ld", &encrypted->length);
    encrypted->length += 20;
    re = "Content-Type: application/octet-stream";
    if (regcomp(&regex, re, REG_NEWLINE)) {
        fprintf(stderr, "Error - Unable to create regex context for data.\n");
        regfree(&regex);
        return 0;
    }
    if (regexec(&regex, s, ARRAY_SIZE(pmatch), pmatch, 0)) {
        /* Invalid data, could not find Length */
        fprintf(stderr, "Error - Unable to find start of data.\n");
        regfree(&regex);
        return 0;
    }
    regfree(&regex);
    s += pmatch[0].rm_eo + 2; /* 2 because of \r\n */
    encrypted->data = discard_const(s);
    return 1;
}

/*
 * Function: wr_unwrap
 *
 * Purpose: reads multipart encoded data coming from the server
 * that is also encrypted.
 * fills out the output buffer with the data decrypted.
 *
 * Arguments:
 *
 *      c              (rw) to the wr transport context. Context must be
 *                          previously initialized
 *      outmsg          (w) ntlm_buffer that will hold the unencrypted data
 *                          outmsg->data will be reserved and user must free.
 *                          outmsg->length will hold the amount of data.
 *                          decrypted message is \0 terminated
 *      multipart_encoded (r) ntlm_buffer that holds the multipart encoded data.
 *                          data pointer will have a buffer that is NOT \0 terminated
 *                          data must be prefixed with an uint32 which is the
 *                          size of the signature header.
 *
 * Returns: 1 if succesfull
 *          0 if fails. In case of failure, the reason will be printed in stderr
 *          This means that the function will be called until it returns 0.
 *
 * Effects:
 *
 * Memory reservation happens if data is succesfully unwrapped.
 *
 */
static uint32_t
wr_unwrap(void *c, struct ntlm_buffer *outmsg, struct ntlm_buffer *multipart_encoded)
{
    struct wr_transport_ctx *ctx = (struct wr_transport_ctx*) c;
    uint32_t result = 1;
    OM_uint32 maj_stat, min_stat;
    struct ntlm_buffer received_encrypted = { NULL, 0 };
    gss_buffer_desc out_msg;
    gss_qop_t qop_state;
    uint32_t conf_state;

    if(ctx == NULL || outmsg == NULL) return 0;

    if(!multipart_decode(&received_encrypted, multipart_encoded)) {
        result = 0;
        goto end;
    }

    gss_buffer_desc msg_buffer = {
        .length = received_encrypted.length - sizeof(uint32_t),
        .value = received_encrypted.data + sizeof(uint32_t)
    };

    maj_stat = gss_unwrap (&min_stat, ctx->gss_ctx, &msg_buffer, &out_msg,
        &conf_state, &qop_state);
    if(GSS_ERROR(maj_stat)) {
        fprintf(stderr, "Unable to unwrap message. %x %x\n", maj_stat, min_stat);
        result = 0;
        goto end;
    }
    /* adds the size of the wrap header at the beginning of the data */
    outmsg->length = out_msg.length;
    outmsg->data = calloc(1, outmsg->length + 1);
    memcpy(outmsg->data, out_msg.value, outmsg->length);
    outmsg->data[outmsg->length] = '\0';

    end:
    gss_release_buffer(&min_stat, &out_msg);
    return result;
}

/*
 * Function: curl_read_cb
 *
 * Purpose: reads local data and writes data over the curl connection.
 * return the amount of bytes that were sent.
 *
 * Arguments:
 *
 *      ptr             (r) pointer to a curl buffer that is ready to
 *                          send data to the server.
 *      size            (r) size of elements to be stored in the buffer
 *      nmemb           (r) number of elements to be stored in the buffer.
 *                          buffer size can be calculated as size*nmemb
 *      userp           (w) pointer to a struct ntlm_buffer where
 *                          the data was stored to be sent.
 *
 * Returns: number of bytes stored in the ptr buffer. If there is no more
 *          data to be sent, this function returns 0.
 *          This means that the function will be called until it returns 0.
 *
 * Effects:
 *
 * No memory is reserver in this function.
 */
static size_t
curl_read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
    if(ptr == NULL || userp == NULL)
        return CURL_READFUNC_ABORT;

    struct ntlm_buffer *ud = (struct ntlm_buffer*) userp;
    size_t nread = size * nmemb;
    if(nread > ud->length) {
        nread = ud->length;
    }

    memcpy(ptr, ud->data, nread);
    ud->data += nread;
    ud->length -= nread;
    return nread;
}

/*
 * Function: curl_write_cb
 *
 * Purpose: reads data from server using curl via a callback and 
 *          writes it in local memory.
 *          returns the amount of bytes that were received.
 *
 * Arguments:
 *
 *      data            (r) pointer to the data to be received
 *      size            (r) size of elements to be received
 *      nmemb           (r) number of elements.
 *      userp           (w) pointer to a struct ntlm_buffer where
 *                          the data will be stored.
 *
 * Returns: number of bytes received. If there are more bytes in queue
 *          this function will be called again. If there is an error,
 *          this function returns CURL_WRITEFUNC_ERROR.
 *
 * Effects:
 *
 * ntlm_buffer structure will reserve memory to store the received
 * data. This memory needs to be released later.
 * The data received will not be null terminaded!
 */
static size_t
curl_write_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct ntlm_buffer *mem = (struct ntlm_buffer *)userp;
    if(userp == NULL) return CURLE_WRITE_ERROR;

    char *ptr = realloc(mem->data, mem->length + realsize + 1);
    if(ptr == NULL)
        return CURLE_WRITE_ERROR;  /* out of memory! */

    mem->data = ptr;
    memcpy(&(mem->data[mem->length]), data, realsize);
    mem->length += realsize;
    mem->data[mem->length] = 0;

    return realsize;
}

static uint32_t
wr_send_message_request(void *c, struct ntlm_buffer *encrypted_message)
{
    uint32_t result = 1;
    if(c == NULL || encrypted_message == NULL || encrypted_message->data == NULL) return 0;
    struct wr_transport_ctx *ctx = (struct wr_transport_ctx*) c;
    struct curl_slist *list = NULL;
    CURLcode res;

    struct ntlm_buffer payload_temp = *encrypted_message;
    FREE(ctx->response.data);
    ctx->response.length = 0;

    list = curl_slist_append(list, "Accept-Encoding: gzip, deflate");
    list = curl_slist_append(list, "Accept: *.*");
    list = curl_slist_append(list, "Connection: Keep-Alive");
    list = curl_slist_append(list, "Content-Type: multipart/encrypted;"
        "protocol=\"application/HTTP-SPNEGO-session-encrypted\";"
        "boundary=\"Encrypted Boundary\"");
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_POSTFIELDSIZE_LARGE, encrypted_message->length);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_POST, 1L);

    uint8_t header_cl[100];
    sprintf(header_cl, "Content-Length: %ld", encrypted_message->length);
    list = curl_slist_append(list, header_cl);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_READFUNCTION, curl_read_cb);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_READDATA, &payload_temp);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_WRITEDATA, &ctx->response);
    res = curl_easy_perform(ctx->curl_ctx);
    if(res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
        curl_easy_strerror(res));
        result = 0;
        goto end;
    }
    curl_easy_getinfo(ctx->curl_ctx, CURLINFO_RESPONSE_CODE, &ctx->response_code);

    end:
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_READFUNCTION, NULL);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_READDATA, NULL);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(ctx->curl_ctx, CURLOPT_WRITEDATA, NULL);
    curl_slist_free_all(list); /* free the list again */

    return result;
}

static uint32_t
wr_get_message_response(void *c, struct ntlm_buffer *recv_data)
{
    if(c == NULL || recv_data == NULL) return 0;
    uint32_t result = 1;
    struct wr_transport_ctx *ctx = (struct wr_transport_ctx*) c;
    if(!wr_unwrap(ctx, recv_data, &ctx->response)) {
        result = 0;
        goto end;
    }
    if(ctx->response_code != 200) {
        result = 0;
        goto end;
    }
    end:
    FREE(ctx->response.data);
    ctx->response.length = 0;
    return result;

}

uint32_t
wr_send_message(void *c, struct ntlm_buffer *recv_data, const struct ntlm_buffer *message)
{
    uint32_t result = 1;
    struct ntlm_buffer encrypted_message = { NULL, 0 };
    struct wr_transport_ctx *ctx = (struct wr_transport_ctx*) c;
    if(c == NULL || message == NULL || message->data == NULL) return 0;

    if(!wr_prepare_encrypted_request(ctx, &encrypted_message, message)) {
        fprintf(stderr, "Error wrapping message.\n");
        result = 0;
        goto end;
    }
    if(!wr_send_message_request(ctx, &encrypted_message)) {
        fprintf(stderr, "Error sending enrypted message.\n");
        result = 0;
        goto end;
    }
    if(!wr_get_message_response(ctx, recv_data)) {
        fprintf(stderr, "Error getting data from server.\n");
        result = 0;
        goto end;
    }

    end:
    FREE(encrypted_message.data);
    return result;
}
