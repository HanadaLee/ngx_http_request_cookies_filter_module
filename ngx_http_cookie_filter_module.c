
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Operation types */
typedef enum {
    NGX_HTTP_COOKIE_FILTER_OP_ADD = 0,
    NGX_HTTP_COOKIE_FILTER_OP_SET,
    NGX_HTTP_COOKIE_FILTER_OP_MODIFY,
    NGX_HTTP_COOKIE_FILTER_OP_CLEAR
} ngx_http_cookie_filter_op_e;


/* Cookie flags bitmask for response rules */
#define NGX_HTTP_COOKIE_FILTER_FLAG_SECURE       0x01
#define NGX_HTTP_COOKIE_FILTER_FLAG_HTTPONLY     0x02
#define NGX_HTTP_COOKIE_FILTER_FLAG_SAMESITE     0x04
#define NGX_HTTP_COOKIE_FILTER_FLAG_NO_SECURE    0x08
#define NGX_HTTP_COOKIE_FILTER_FLAG_NO_HTTPONLY  0x10
#define NGX_HTTP_COOKIE_FILTER_FLAG_NO_SAMESITE  0x20


/* SameSite attribute values */
typedef enum {
    NGX_HTTP_COOKIE_SAMESITE_UNSET = 0,
    NGX_HTTP_COOKIE_SAMESITE_STRICT,
    NGX_HTTP_COOKIE_SAMESITE_LAX,
    NGX_HTTP_COOKIE_SAMESITE_NONE
} ngx_http_cookie_samesite_e;


/* Rule structure for request_cookie_filter */
typedef struct {
    ngx_uint_t                  op_type; /* ngx_http_cookie_filter_op_e */
    ngx_str_t                   name;
    ngx_http_script_t          *value_script;
} ngx_http_cookie_filter_req_rule_t;


/* Rule structure for response_cookie_filter */
typedef struct {
    ngx_uint_t                  op_type;
    ngx_str_t                   name;
    ngx_http_script_t          *value_script;
    ngx_http_script_t          *domain_script;
    ngx_http_script_t          *path_script;
    ngx_uint_t                  flags;
    ngx_uint_t                  samesite; /* ngx_http_cookie_samesite_e */
} ngx_http_cookie_filter_resp_rule_t;


/* Location configuration structure */
typedef struct {
    ngx_array_t                *req_rules;  /* array of ngx_http_cookie_filter_req_rule_t */
    ngx_array_t                *resp_rules; /* array of ngx_http_cookie_filter_resp_rule_t */
} ngx_http_cookie_filter_loc_conf_t;


/* Helper struct for parsed request cookies */
typedef struct {
    ngx_str_t                    name;
    ngx_str_t                    value;
    ngx_uint_t                   deleted;
} ngx_http_cookie_kv_t;


/* Helper struct for parsed Set-Cookie attributes */
typedef struct {
    ngx_str_t                     name;
    ngx_str_t                     value;
    ngx_str_t                     domain;
    ngx_str_t                     path;
    ngx_str_t                     expires;
    ngx_str_t                     max_age;
    ngx_uint_t                    flags;
    ngx_uint_t                    samesite;
} ngx_http_parsed_cookie_t;


static ngx_int_t ngx_http_cookie_filter_init(ngx_conf_t *cf);
static void *ngx_http_cookie_filter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cookie_filter_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_request_cookie_filter(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_response_cookie_filter(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_cookie_filter_commands[] = {

    { ngx_string("set_request_cookie"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_request_cookie_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("add_request_cookie"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_request_cookie_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("modify_request_cookie"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_request_cookie_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("clear_request_cookie"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_request_cookie_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_response_cookie"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_response_cookie_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("add_response_cookie"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_response_cookie_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("modify_response_cookie"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_response_cookie_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("clear_response_cookie"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_response_cookie_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


/* Module context */
static ngx_http_module_t ngx_http_cookie_filter_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_http_cookie_filter_init,             /* postconfiguration */
    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */
    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
    ngx_http_cookie_filter_create_loc_conf,  /* create location configuration */
    ngx_http_cookie_filter_merge_loc_conf    /* merge location configuration */
};


/* Module itself */
ngx_module_t ngx_http_cookie_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_cookie_filter_module_ctx,      /* module context */
    ngx_http_cookie_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_cookie_filter_request_handler(ngx_http_request_t *r)
{
    ngx_http_cookie_filter_loc_conf_t  *clcf;
    ngx_array_t                        *cookies;
    ngx_http_cookie_kv_t               *cookie_kv;
    ngx_http_cookie_filter_req_rule_t  *rule;
    ngx_uint_t                          i, j;
    ngx_str_t                           new_cookie_header, value;
    u_char                             *p, *buf;
    size_t                              len;
    ngx_uint_t                          found;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cookie_filter_module);

    if (clcf->req_rules == NULL || clcf->req_rules->nelts == 0) {
        return NGX_DECLINED;
    }

    /* 1. Parse existing Cookie header into an array of key-value pairs */
    cookies = ngx_array_create(r->pool, 8, sizeof(ngx_http_cookie_kv_t));
    if (cookies == NULL) {
        return NGX_ERROR;
    }

    if (r->headers_in.cookie!= NULL) {
        p = r->headers_in.cookie->value.data;
        u_char *end = p + r->headers_in.cookie->value.len;
        while (p < end) {
            while (p < end && (*p == ' ' || *p == ';')) {
                p++;
            }
            if (p == end) break;

            u_char *eq = ngx_strlchr(p, end, '=');
            if (eq == NULL) break;

            cookie_kv = ngx_array_push(cookies);
            if (cookie_kv == NULL) return NGX_ERROR;

            cookie_kv->name.data = p;
            cookie_kv->name.len = eq - p;
            cookie_kv->deleted = 0;
            
            p = eq + 1;
            u_char *semi = ngx_strlchr(p, end, ';');
            if (semi == NULL) {
                cookie_kv->value.data = p;
                cookie_kv->value.len = end - p;
                p = end;
            } else {
                cookie_kv->value.data = p;
                cookie_kv->value.len = semi - p;
                p = semi;
            }
        }
    }

    /* 2. Apply rules */
    rule = clcf->req_rules->elts;
    for (i = 0; i < clcf->req_rules->nelts; i++) {
        found = 0;
        cookie_kv = cookies->elts;
        for (j = 0; j < cookies->nelts; j++) {
            if (cookie_kv[j].name.len == rule[i].name.len
                && ngx_strncmp(cookie_kv[j].name.data, rule[i].name.data, rule[i].name.len) == 0)
            {
                found = 1;
                break;
            }
        }

        if (rule[i].op_type == NGX_HTTP_COOKIE_FILTER_OP_CLEAR) {
            if (found) {
                cookie_kv[j].deleted = 1;
            }
            continue;
        }

        /* Get dynamic value */
        if (ngx_http_script_run(r, &value, rule[i].value_script->lengths, 0, rule[i].value_script->values)!= NGX_OK) {
            return NGX_ERROR;
        }

        switch (rule[i].op_type) {
            case NGX_HTTP_COOKIE_FILTER_OP_ADD:
                if (!found) {
                    cookie_kv = ngx_array_push(cookies);
                    if (cookie_kv == NULL) return NGX_ERROR;
                    cookie_kv->name = rule[i].name;
                    cookie_kv->value = value;
                    cookie_kv->deleted = 0;
                }
                break;
            case NGX_HTTP_COOKIE_FILTER_OP_MODIFY:
                if (found) {
                    cookie_kv[j].value = value;
                }
                break;
            case NGX_HTTP_COOKIE_FILTER_OP_SET:
                if (found) {
                    cookie_kv[j].value = value;
                } else {
                    cookie_kv = ngx_array_push(cookies);
                    if (cookie_kv == NULL) return NGX_ERROR;
                    cookie_kv->name = rule[i].name;
                    cookie_kv->value = value;
                    cookie_kv->deleted = 0;
                }
                break;
            default:
                break;
        }
    }

    /* 3. Rebuild Cookie header */
    len = 0;
    cookie_kv = cookies->elts;
    for (i = 0; i < cookies->nelts; i++) {
        if (!cookie_kv[i].deleted) {
            len += cookie_kv[i].name.len + 1 + cookie_kv[i].value.len + 2; /* name=value;  */
        }
    }

    if (len == 0) {
        if (r->headers_in.cookie) {
            r->headers_in.cookie->hash = 0;
        }
        return NGX_DECLINED;
    }

    len -= 2; /* No trailing "; " */
    buf = ngx_palloc(r->pool, len);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    p = buf;

    found = 0;
    for (i = 0; i < cookies->nelts; i++) {
        if (!cookie_kv[i].deleted) {
            if (found) {
                *p++ = ';';
                *p++ = ' ';
            }
            p = ngx_copy(p, cookie_kv[i].name.data, cookie_kv[i].name.len);
            *p++ = '=';
            p = ngx_copy(p, cookie_kv[i].value.data, cookie_kv[i].value.len);
            found = 1;
        }
    }
    
    new_cookie_header.len = len;
    new_cookie_header.data = buf;

    /* 4. Set new Cookie header */
    ngx_table_elt_t *h = r->headers_in.cookie;
    if (h == NULL) {
        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }
        r->headers_in.cookie = h;
    }
    
    h->key.len = sizeof("Cookie") - 1;
    h->key.data = (u_char *) "Cookie";
    h->value = new_cookie_header;
    h->hash = ngx_hash_key_lc(h->key.data, h->key.len);
    
    return NGX_DECLINED;
}


/* 
 * Parse Cookie header, copy from ngx_http_proxy_module
 */
static ngx_int_t
ngx_http_cookie_filter_parse_cookie(ngx_str_t *value, ngx_array_t *attrs)
{
    u_char        *start, *end, *p, *last;
    ngx_str_t      name, val;
    ngx_keyval_t  *attr;

    start = value->data;
    end = value->data + value->len;

    for ( ;; ) {

        last = (u_char *) ngx_strchr(start, ';');

        if (last == NULL) {
            last = end;
        }

        while (start < last && *start == ' ') { start++; }

        for (p = start; p < last && *p != '='; p++) { /* void */ }

        name.data = start;
        name.len = p - start;

        while (name.len && name.data[name.len - 1] == ' ') {
            name.len--;
        }

        if (p < last) {

            p++;

            while (p < last && *p == ' ') { p++; }

            val.data = p;
            val.len = last - val.data;

            while (val.len && val.data[val.len - 1] == ' ') {
                val.len--;
            }

        } else {
            ngx_str_null(&val);
        }

        attr = ngx_array_push(attrs);
        if (attr == NULL) {
            return NGX_ERROR;
        }

        attr->key = name;
        attr->value = val;

        if (last == end) {
            break;
        }

        start = last + 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cookie_filter_header_filter(ngx_http_request_t *r)
{
    /* todo */

    return ngx_http_next_header_filter(r);
}


static char *
ngx_http_request_cookie_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cookie_filter_loc_conf_t *clcf = conf;
    ngx_str_t                         *value;
    ngx_http_cookie_filter_req_rule_t *rule;
    ngx_http_script_compile_t          sc;

    value = cf->args->elts;

    if (clcf->req_rules == NULL) {
        clcf->req_rules = ngx_array_create(cf->pool, 4, sizeof(ngx_http_cookie_filter_req_rule_t));
        if (clcf->req_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(clcf->req_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(ngx_http_cookie_filter_req_rule_t));

    /* Parse operation type */
    if (value[0].data[0] == 'a') {
        rule->op_type = NGX_HTTP_COOKIE_FILTER_OP_ADD;

    } else if (value[0].data[0] == 's') {
        rule->op_type = NGX_HTTP_COOKIE_FILTER_OP_SET;

    } else if (value[0].data[0] == 'm') {
        rule->op_type = NGX_HTTP_COOKIE_FILTER_OP_MODIFY;

    } else if (value[0].data[0] == 'c') {
        rule->op_type = NGX_HTTP_COOKIE_FILTER_OP_CLEAR;
    }

    /* Parse cookie name */
    rule->name = value[1];

    /* Parse and compile value if it exists */
    if (cf->args->nelts == 3) {

        if (rule->op_type == NGX_HTTP_COOKIE_FILTER_OP_CLEAR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" should not "
                                                     "take a value",
                                                     &value[0]);
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
        sc.cf = cf;
        sc.source = &value;
        sc.lengths = &rule->value_script;
        sc.values = &rule->value_script;
        sc.variables = ngx_http_script_variables_count(&value);
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc)!= NGX_OK) {
            return NGX_CONF_ERROR;
        }

    } else {

         if (rule->op_type != NGX_HTTP_COOKIE_FILTER_OP_CLEAR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "action \"%V\" requires a value", &value);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_response_cookie_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    /* todo */
    return NGX_CONF_OK;
}


static void *
ngx_http_cookie_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cookie_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cookie_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_cookie_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cookie_filter_loc_conf_t *prev = parent;
    ngx_http_cookie_filter_loc_conf_t *conf = child;

    if (conf->req_rules == NULL) {
        conf->req_rules = prev->req_rules;
    }

    if (conf->resp_rules == NULL) {
        conf->resp_rules = prev->resp_rules;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_cookie_filter_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_cookie_filter_request_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cookie_filter_header_filter;

    return NGX_OK;
}