
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Operation types */
typedef enum {
    NGX_HTTP_REQUEST_COOKIES_FILTER_ADD = 0,
    NGX_HTTP_REQUEST_COOKIES_FILTER_SET,
    NGX_HTTP_REQUEST_COOKIES_FILTER_REWRITE,
    NGX_HTTP_REQUEST_COOKIES_FILTER_CLEAR
} ngx_http_request_cookies_filter_op_e;


/* Rule structure for request_cookie_filter */
typedef struct {
    ngx_uint_t                  op_type; /* ngx_http_request_cookies_filter_op_e */
    ngx_str_t                   name;
    ngx_http_complex_value_t   *value;
    ngx_http_complex_value_t   *filter;
    ngx_int_t                   negative;
} ngx_http_request_cookies_filter_rule_t;


/* Location configuration structure */
typedef struct {
    ngx_array_t                *rules;  /* array of ngx_http_request_cookies_filter_rule_t */
} ngx_http_request_cookies_filter_loc_conf_t;


/* Helper struct for parsed request cookies */
typedef struct {
    ngx_str_t                   name;
    ngx_str_t                   value;
    ngx_uint_t                  cleared;
} ngx_http_request_cookie_t;


static ngx_int_t ngx_http_request_cookies_filter_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_filtered_request_cookies_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_fallback_request_cookies_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_request_cookies_filter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_request_cookies_filter_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_request_cookies_filter(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_request_cookies_filter_commands[] = {

    { ngx_string("set_request_cookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_request_cookies_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("add_request_cookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_request_cookies_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("rewrite_request_cookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_request_cookies_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("clear_request_cookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_request_cookies_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_request_cookies_filter_module_ctx = {
    ngx_http_request_cookies_filter_add_variables,    /* preconfiguration */
    NULL,                                             /* postconfiguration */
    NULL,                                             /* create main configuration */
    NULL,                                             /* init main configuration */
    NULL,                                             /* create server configuration */
    NULL,                                             /* merge server configuration */
    ngx_http_request_cookies_filter_create_loc_conf,  /* create location configuration */
    ngx_http_request_cookies_filter_merge_loc_conf    /* merge location configuration */
};


ngx_module_t ngx_http_request_cookies_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_request_cookies_filter_module_ctx,      /* module context */
    ngx_http_request_cookies_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                                  /* module type */
    NULL,                                             /* init master */
    NULL,                                             /* init module */
    NULL,                                             /* init process */
    NULL,                                             /* init thread */
    NULL,                                             /* exit thread */
    NULL,                                             /* exit process */
    NULL,                                             /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_request_cookies_filter_vars[] = {

    { ngx_string("filtered_request_cookies"), NULL,
      ngx_http_filtered_request_cookies_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_request_cookies_filter_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_request_cookies_filter_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/*
 * Copy from ngx_http_variable_cookies and ngx_http_variable_headers_internal
 * Used to generate the same value as $http_cookie when cookies filter
 * is not needed
 */
static ngx_int_t
ngx_http_fallback_request_cookies_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    size_t            len;
    u_char           *p, *end;
    ngx_table_elt_t  *h, *th;

    h = r->headers_in.cookie;

    len = 0;

    for (th = h; th; th = th->next) {

        if (th->hash == 0) {
            continue;
        }

        len += th->value.len + 2;  // 2 for "; " separator
    }

    if (len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len -= 2;  // Remove trailing separator

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (h->next == NULL) {
        v->len = h->value.len;
        v->data = h->value.data;

        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = len;
    v->data = p;

    end = p + len;

    for (th = h; th; th = th->next) {
        if (th->hash == 0) {
            continue;
        }

        p = ngx_copy(p, th->value.data, th->value.len);

        if (p == end) {
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_filtered_request_cookies_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_request_cookies_filter_loc_conf_t  *clcf;

    ngx_array_t                             *cookies;
    ngx_http_request_cookie_t               *cookie;
    ngx_http_request_cookies_filter_rule_t  *rule;
    ngx_table_elt_t                         *h;
    ngx_uint_t                               i, j;
    ngx_str_t                                name, value;
    u_char                                  *p, *start, *end, *last;
    ngx_uint_t                               found, op_type, filtered;

    clcf = ngx_http_get_module_loc_conf(r,
        ngx_http_request_cookies_filter_module);

    if (clcf->rules == NULL || clcf->rules->nelts == 0) {
        goto not_filtered;
    }

    /* Parse existing Cookie header into an array of key-value pairs */
    cookies = ngx_array_create(r->pool, 4, sizeof(ngx_http_request_cookie_t));
    if (cookies == NULL) {
        return NGX_ERROR;
    }

    h = r->headers_in.cookie;
    if (h != NULL) {

        for ( /* void */ ; h; h = h->next) {

            if (h->hash == 0 || h->value.len == 0) {
                continue;
            }

            start = h->value.data;
            end = h->value.data + h->value.len;

            while (start < end) {

                while (start < end && (*start == ' ' || *start == ';')) {
                    start++;
                }

                if (start == end) {
                    break;
                }

                last = ngx_strlchr(start, end, '=');
                if (last == NULL) {
                    break;
                }

                name.data = start;
                name.len = last - start;

                start = last + 1;
                last = ngx_strlchr(start, end, ';');
                if (last == NULL) {
                    last = end;
                }

                value.data = start;
                value.len = last - start;

                cookie = ngx_array_push(cookies);
                if (cookie == NULL) {
                    return NGX_ERROR;
                }

                cookie->name = name;
                cookie->value = value;
                cookie->cleared = 0;

                start = last;
            }
        }
    }

    /* Apply rules */
    rule = clcf->rules->elts;
    for (i = 0; i < clcf->rules->nelts; i++) {

        if (rule[i].filter) {

            if (ngx_http_complex_value(r, rule[i].filter, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (value.len == 0 || (value.len == 1 && value.data[0] == '0')) {

                if (!rule[i].negative) {
                    continue;
                }

            } else {

                if (rule[i].negative) {
                    continue;
                }
            }
        }

        found = 0;
        op_type = rule[i].op_type;
        cookie = cookies->elts;

        for (j = 0; j < cookies->nelts; j++) {

            if (cookie[j].cleared == 1) {
                continue;
            }

            if (cookie[j].name.len == rule[i].name.len
                && ngx_strncasecmp(cookie[j].name.data, rule[i].name.data,
                                   rule[i].name.len) == 0)
            {
                found = 1;

                if (op_type == NGX_HTTP_REQUEST_COOKIES_FILTER_CLEAR) {
                    cookie[j].cleared = 1;
                    filtered = 1;

                    continue;
                }
                
                if (op_type == NGX_HTTP_REQUEST_COOKIES_FILTER_REWRITE
                    || op_type == NGX_HTTP_REQUEST_COOKIES_FILTER_SET)
                {

                    if (ngx_http_complex_value(r, rule[i].value, &value)
                            != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    if (value.len == 0) {
                        cookie[j].cleared = 1;
                        filtered = 1;

                        continue;
                    }

                    cookie[j].value = value;

                    filtered = 1;
                    /* clear multiple values */
                    op_type = NGX_HTTP_REQUEST_COOKIES_FILTER_CLEAR;
                }
            }
        }

        if (found) {
            continue;
        }

        if (rule[i].op_type == NGX_HTTP_REQUEST_COOKIES_FILTER_ADD
            || rule[i].op_type == NGX_HTTP_REQUEST_COOKIES_FILTER_SET)
        {
            cookie = ngx_array_push(cookies);
            if (cookie == NULL) {
                return NGX_ERROR;
            }

            if (ngx_http_complex_value(r, rule[i].value, &value)
                    != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (value.len == 0) {
                continue;
            }

            cookie->name = rule[i].name;
            cookie->value = value;
            cookie->cleared = 0;
            filtered = 1;
        }
    }

    if (!filtered) {
        goto not_filtered;
    }

    /* Rebuild Cookie header */
    v->len = 0;
    cookie = cookies->elts;
    for (i = 0; i < cookies->nelts; i++) {

        if (cookie[i].cleared == 1) {
            continue;
        }

        /* name=value; */
        v->len += cookie[i].name.len + 1 + cookie[i].value.len + 2;
    }

    if (v->len == 0) {
        *v = ngx_http_variable_null_value;

        return NGX_OK;
    }

    v->len -= 2; /* No trailing "; " */
    v->data = ngx_palloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    p = v->data;

    found = 0;
    for (i = 0; i < cookies->nelts; i++) {

        if (cookie[i].cleared == 1) {
            continue;
        }

        if (found) {
            *p++ = ';'; *p++ = ' ';
        }

        p = ngx_copy(p, cookie[i].name.data, cookie[i].name.len);
        *p++ = '=';
        p = ngx_copy(p, cookie[i].value.data, cookie[i].value.len);

        found = 1;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_filtered:

    /* fallback to $http_cookie */
    return ngx_http_fallback_request_cookies_variable(r, v, data);
}


static char *
ngx_http_request_cookies_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_request_cookies_filter_loc_conf_t  *clcf = conf;

    ngx_str_t                                *value;
    ngx_http_request_cookies_filter_rule_t   *rule;
    ngx_uint_t                                n;
    ngx_str_t                                 s;
    ngx_http_compile_complex_value_t          ccv;

    value = cf->args->elts;

    if (clcf->rules == NGX_CONF_UNSET_PTR) {
        clcf->rules = ngx_array_create(cf->pool, 4,
            sizeof(ngx_http_request_cookies_filter_rule_t));
        if (clcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(clcf->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(ngx_http_request_cookies_filter_rule_t));

    /* Parse operation type */
    if (value[0].data[0] == 'a') {
        rule->op_type = NGX_HTTP_REQUEST_COOKIES_FILTER_ADD;

    } else if (value[0].data[0] == 's') {
        rule->op_type = NGX_HTTP_REQUEST_COOKIES_FILTER_SET;

    } else if (value[0].data[0] == 'r') {
        rule->op_type = NGX_HTTP_REQUEST_COOKIES_FILTER_REWRITE;

    } else if (value[0].data[0] == 'c') {
        rule->op_type = NGX_HTTP_REQUEST_COOKIES_FILTER_CLEAR;
    }

    /* Parse cookie name */
    rule->name = value[1];
    if (rule->name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cookie name is empty");
        return NGX_CONF_ERROR;
    }

    if (rule->op_type == NGX_HTTP_REQUEST_COOKIES_FILTER_CLEAR) {

        if (cf->args->nelts == 3) {
            n = 2;
            goto if_filter;
        }

        return NGX_CONF_OK;
    }

    /* Parse and compile value */
    if (cf->args->nelts != 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "action \"%V\" requires a value", &value);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    rule->value = ccv.complex_value;

    if (cf->args->nelts == 3) {
        return NGX_CONF_OK;
    }

    n = 3;

if_filter:

    if (ngx_strncmp(value[n].data, "if=", 3) == 0) {
        s.len = value[n].len - 3;
        s.data = value[n].data + 3;
        rule->negative = 0;

    } else if (ngx_strncmp(value[n].data, "if!=", 4) == 0) {
        s.len = value[n].len - 4;
        s.data = value[n].data + 4;
        rule->negative = 1;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid parameter \"%V\"", &value[n]);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &s;
    ccv.complex_value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    rule->filter = ccv.complex_value;

    return NGX_CONF_OK;
}


static void *
ngx_http_request_cookies_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_request_cookies_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
        sizeof(ngx_http_request_cookies_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->rules = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_request_cookies_filter_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_request_cookies_filter_loc_conf_t *prev = parent;
    ngx_http_request_cookies_filter_loc_conf_t *conf = child;

    ngx_http_request_cookies_filter_rule_t  *prule, *crule, *nrule;
    ngx_uint_t                               i, j, found;
    ngx_uint_t                               crules_nelts;

    if (conf->rules == NGX_CONF_UNSET_PTR) {
        conf->rules = (prev->rules == NGX_CONF_UNSET_PTR) ? NULL : prev->rules;
        return NGX_CONF_OK;
    }

    if (prev->rules == NGX_CONF_UNSET_PTR || prev->rules == NULL) {
        return NGX_CONF_OK;
    }

    prule = prev->rules->elts;
    crules_nelts = conf->rules->nelts;
    for (i = 0; i < prev->rules->nelts; i++) {
        crule = conf->rules->elts;
        found = 0;

        for (j = 0; j < crules_nelts; j++) {
            if (prule[i].name.len == crule[j].name.len
                && ngx_strncasecmp(prule[i].name.data, crule[j].name.data,
                            prule[i].name.len) == 0)
            {
                found = 1;
                break;
            }
        }

        if (!found) {
            nrule = ngx_array_push(conf->rules);
            if (nrule == NULL) {
                return NGX_CONF_ERROR;
            }

            *nrule = prule[i];
        }
    }

    return NGX_CONF_OK;
}