
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_COOKIES_FILTER_INHERIT_OFF      0
#define NGX_HTTP_COOKIES_FILTER_INHERIT_ON       1
#define NGX_HTTP_COOKIES_FILTER_INHERIT_BEFORE   2
#define NGX_HTTP_COOKIES_FILTER_INHERIT_AFTER    3


typedef enum {
    NGX_HTTP_COOKIES_FILTER_ADD = 0,
    NGX_HTTP_COOKIES_FILTER_APPEND,
    NGX_HTTP_COOKIES_FILTER_SET,
    NGX_HTTP_COOKIES_FILTER_REWRITE,
    NGX_HTTP_COOKIES_FILTER_CLEAR,
    NGX_HTTP_COOKIES_FILTER_CLEAR_ALL,
    NGX_HTTP_COOKIES_FILTER_KEEP
} ngx_http_cookies_filter_op_e;


typedef struct {
    ngx_uint_t                  op;         /* ngx_http_cookies_filter_op_e */
    ngx_uint_t                  ignore_case;
    ngx_str_t                   name;
    ngx_array_t                *name_list;  /* array of ngx_str_t */
    ngx_http_complex_value_t   *value;
    ngx_uint_t                  flag;
    ngx_http_complex_value_t   *filter;
    ngx_int_t                   negative;
} ngx_http_cookies_filter_rule_t;


typedef struct {
    ngx_array_t                *rules;      /* array of ngx_http_cookies_filter_rule_t */
    ngx_uint_t                  inherit_mode;
} ngx_http_cookies_filter_loc_conf_t;


typedef struct {
    ngx_str_t                   name;
    ngx_str_t                   value;
    ngx_uint_t                  cleared;
} ngx_http_cookie_t;


static ngx_int_t ngx_http_cookies_filter_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_filtered_cookies_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_cookies_filter_fallback_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_cookies_filter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cookies_filter_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_cookies_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_enum_t  ngx_http_cookies_filter_inherit[] = {
    { ngx_string("on"), NGX_HTTP_COOKIES_FILTER_INHERIT_ON },
    { ngx_string("off"), NGX_HTTP_COOKIES_FILTER_INHERIT_OFF },
    { ngx_string("before"), NGX_HTTP_COOKIES_FILTER_INHERIT_BEFORE },
    { ngx_string("after"), NGX_HTTP_COOKIES_FILTER_INHERIT_AFTER },
    { ngx_null_string, 0 }
};


static ngx_command_t ngx_http_cookies_filter_commands[] = {

    { ngx_string("cookies_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_cookies_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cookies_filter_inherit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cookies_filter_loc_conf_t, inherit_mode),
      &ngx_http_cookies_filter_inherit },

      ngx_null_command
};


static ngx_http_module_t ngx_http_cookies_filter_module_ctx = {
    ngx_http_cookies_filter_add_variables,            /* preconfiguration */
    NULL,                                             /* postconfiguration */
    NULL,                                             /* create main configuration */
    NULL,                                             /* init main configuration */
    NULL,                                             /* create server configuration */
    NULL,                                             /* merge server configuration */
    ngx_http_cookies_filter_create_loc_conf,          /* create location configuration */
    ngx_http_cookies_filter_merge_loc_conf            /* merge location configuration */
};


ngx_module_t ngx_http_cookies_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_cookies_filter_module_ctx,              /* module context */
    ngx_http_cookies_filter_commands,                 /* module directives */
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


static ngx_http_variable_t  ngx_http_cookies_filter_vars[] = {

    { ngx_string("filtered_cookies"), NULL,
      ngx_http_filtered_cookies_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_cookies_filter_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_cookies_filter_vars; v->name.len; v++) {
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
ngx_http_cookies_filter_fallback_variable(ngx_http_request_t *r,
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
ngx_http_cookies_filter_parse_cookies(ngx_http_request_t *r,
    ngx_array_t *cookies)
{
    ngx_table_elt_t                 *h;
    u_char                          *start, *end, *last;
    ngx_http_cookie_t               *cookie;
    ngx_str_t                        name, value;

    h = r->headers_in.cookie;
    if (h == NULL) {
        return NGX_OK;
    }

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

    return NGX_OK;
}


static ngx_int_t
ngx_http_filtered_cookies_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cookies_filter_loc_conf_t  *clcf;

    ngx_array_t                     *cookies, *new_cookies;
    ngx_http_cookie_t               *cookie, *new_cookie;
    ngx_http_cookies_filter_rule_t  *rule;
    ngx_table_elt_t                 *h;
    ngx_uint_t                       i, j, k;
    ngx_str_t                        value;
    ngx_str_t                       *n;
    u_char                          *p, *start, *end, *last;
    ngx_uint_t                       parsed, found, applied, filtered;
    ngx_uint_t                       op;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cookies_filter_module);

    if (clcf->rules == NULL || clcf->rules->nelts == 0) {
        goto not_filtered;
    }

    parsed = 0;
    filtered = 0;
    cookies = NULL;

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

        op = rule[i].op;

        if (op == NGX_HTTP_COOKIES_FILTER_CLEAR_ALL) {

            /* break after clear all cookie */
            if (rule[i].flag == 1) {
                *v = ngx_http_variable_null_value;
                return NGX_OK;
            }

            cookies = ngx_array_create(r->pool, 4, sizeof(ngx_http_cookie_t));
            if (cookies == NULL) {
                return NGX_ERROR;
            }

            parsed = 1;
            filtered = 1;

            continue;
        }

        if (parsed == 0) {
            cookies = ngx_array_create(r->pool, 4, sizeof(ngx_http_cookie_t));
            if (cookies == NULL) {
                return NGX_ERROR;
            }

            if (ngx_http_cookies_filter_parse_cookies(r, cookies) != NGX_OK) {
                return NGX_ERROR;
            }

            parsed = 1;
        }

        if (op == NGX_HTTP_COOKIES_FILTER_APPEND) {

            if (ngx_http_complex_value(r, rule[i].value, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (value.len == 0) {
                continue;
            }

            cookie = ngx_array_push(cookies);
            if (cookie == NULL) {
                return NGX_ERROR;
            }

            cookie->name = rule[i].name;
            cookie->value = value;
            cookie->cleared = 0;
            filtered = 1;

            if (rule[i].flag == 1) {
                goto rebuild_cookie_header;
            }

            continue;
        }

        found = 0;
        applied = 0;
        cookie = cookies->elts;

        if (op == NGX_HTTP_COOKIES_FILTER_KEEP) {
            new_cookies = ngx_array_create(r->pool,
                ngx_max(rule[i].name_list->nelts, 4),
                sizeof(ngx_http_cookie_t));

            if (new_cookies == NULL) {
                return NGX_ERROR;
            }

            for (j = 0; j < cookies->nelts; j++) {

                if (cookie[j].cleared == 1) {
                    continue;
                }

                found = 0;

                for (k = 0; k < rule[i].name_list->nelts; k++) {
                    n = (ngx_str_t *) rule[i].name_list->elts + k;

                    if (n->len != cookie[j].name.len) {
                        continue;
                    }

                    if (rule[i].ignore_case
                        ? (ngx_strncasecmp(cookie[j].name.data, n->data,
                                            n->len) == 0)
                        : (ngx_strncmp(cookie[j].name.data, n->data,
                                        n->len) == 0))
                    {
                        found = 1;
                        break;
                    }
                }

                if (found) {
                    new_cookie = ngx_array_push(new_cookies);
                    if (new_cookie == NULL) {
                        return NGX_ERROR;
                    }

                    *new_cookie = cookie[j];
                }
            }

            cookies = new_cookies;
            filtered = 1;

            if (rule[i].flag == 1) {
                goto rebuild_cookie_header;
            }

            continue;
        }

        for (j = 0; j < cookies->nelts; j++) {

            if (cookie[j].cleared == 1) {
                continue;
            }

            if (cookie[j].name.len != rule[i].name.len) {
                continue;
            }

            if (rule[i].ignore_case
                ? (ngx_strncasecmp(cookie[j].name.data, rule[i].name.data,
                                   rule[i].name.len) != 0)
                : (ngx_strncmp(cookie[j].name.data, rule[i].name.data,
                               rule[i].name.len) != 0))
            {
                continue;
            }

            found = 1;

            if (op == NGX_HTTP_COOKIES_FILTER_CLEAR) {
                cookie[j].cleared = 1;
                applied = 1;
                filtered = 1;

                continue;
            }
                
            if (op == NGX_HTTP_COOKIES_FILTER_REWRITE
                || op == NGX_HTTP_COOKIES_FILTER_SET)
            {

                if (ngx_http_complex_value(r, rule[i].value, &value)
                        != NGX_OK)
                {
                    return NGX_ERROR;
                }

                if (value.len == 0) {
                    cookie[j].cleared = 1;
                    applied = 1;
                    filtered = 1;

                    continue;
                }

                cookie[j].value = value;

                applied = 1;
                filtered = 1;
            }
        }

        if (rule[i].flag == 1 && applied) {
            goto rebuild_cookie_header;
        }

        if (found) {
            continue;
        }

        if (op == NGX_HTTP_COOKIES_FILTER_ADD
            || op == NGX_HTTP_COOKIES_FILTER_SET)
        {
            if (ngx_http_complex_value(r, rule[i].value, &value)
                    != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (value.len == 0) {
                continue;
            }

            cookie = ngx_array_push(cookies);
            if (cookie == NULL) {
                return NGX_ERROR;
            }

            cookie->name = rule[i].name;
            cookie->value = value;
            cookie->cleared = 0;
            filtered = 1;

            if (rule[i].flag == 1) {
                goto rebuild_cookie_header;
            }
        }
    }

rebuild_cookie_header:

    if (!filtered) {
        goto not_filtered;
    }

    /* rebuild Cookie header */
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
    return ngx_http_cookies_filter_fallback_variable(r, v, data);
}


static char *
ngx_http_cookies_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cookies_filter_loc_conf_t  *clcf = conf;

    ngx_str_t                           *value;
    ngx_http_cookies_filter_rule_t      *rule;
    ngx_uint_t                           i;
    ngx_str_t                            s;
    ngx_str_t                           *n;
    ngx_http_compile_complex_value_t     ccv;

    value = cf->args->elts;

    if (clcf->rules == NGX_CONF_UNSET_PTR) {
        clcf->rules = ngx_array_create(cf->pool, 4,
            sizeof(ngx_http_cookies_filter_rule_t));
        if (clcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(clcf->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(ngx_http_cookies_filter_rule_t));

    if (value[1].data[0] == 'a' || value[1].data[0] == 'A') {

        if (value[1].data[1] == 'd' || value[1].data[1] == 'D') {
            rule->op = NGX_HTTP_COOKIES_FILTER_ADD;

        } else {
            rule->op = NGX_HTTP_COOKIES_FILTER_APPEND;
        }

    } else if (value[1].data[0] == 's' || value[1].data[0] == 'S') {
        rule->op = NGX_HTTP_COOKIES_FILTER_SET;

    } else if (value[1].data[0] == 'r' || value[1].data[0] == 'R') {
        rule->op = NGX_HTTP_COOKIES_FILTER_REWRITE;

    } else if (value[1].data[0] == 'c' || value[1].data[0] == 'C') {
        rule->op = NGX_HTTP_COOKIES_FILTER_CLEAR;

    } else if (value[1].data[0] == 'k' || value[1].data[0] == 'K') {
        rule->op = NGX_HTTP_COOKIES_FILTER_KEEP;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid parameter: \"%V\"", &value[0]);
        return NGX_CONF_ERROR;
    }

    i = 2;

    if (value[i].len == 2 && ngx_strncmp(value[i].data, "-i", 2) == 0) {
        rule->ignore_case = 1;
        i++;
    }

    /* Parse cookie name or name_list */
    if (rule->op == NGX_HTTP_COOKIES_FILTER_KEEP) {
        if (i == cf->args->nelts) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"%V\" requires a name list", &value[1]);
            return NGX_CONF_ERROR;
        }

        for ( /* void */ ; i < cf->args->nelts; i++) {

            if (value[i].len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cookie name is empty");
                return NGX_CONF_ERROR;
            }

            /* go to check for name=value */
            if (ngx_strchr(value[i].data, '=') != NULL) {
                goto parse_tail;
            }

            if (rule->name_list == NULL) {
                rule->name_list = ngx_array_create(cf->pool, 4,
                    sizeof(ngx_str_t));

                if (rule->name_list == NULL) {
                    return NGX_CONF_ERROR;
                }
            }

            n = ngx_array_push(rule->name_list);
            if (n == NULL) {
                return NGX_CONF_ERROR;
            }

            *n = value[i];
        }

        return NGX_CONF_OK;
    }

    rule->name = value[i];
    if (rule->name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cookie name is empty");
        return NGX_CONF_ERROR;
    }

    i++;

    if (rule->op == NGX_HTTP_COOKIES_FILTER_CLEAR) {
        
        if (rule->name.len == 1 && rule->name.data[0] == '*') {
            rule->op = NGX_HTTP_COOKIES_FILTER_CLEAR_ALL;
        }

        goto parse_tail;
        return NGX_CONF_OK;
    }

    /* Parse and compile value */
    if (i == cf->args->nelts) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "action \"%V\" requires a value", &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[i];
    ccv.complex_value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    rule->value = ccv.complex_value;

    if (i == cf->args->nelts - 1) {
        return NGX_CONF_OK;
    }

    i++;

parse_tail:

    for ( /* void */ ; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "if=", 3) == 0
            || ngx_strncmp(value[i].data, "if!=", 4) == 0)
        {
            if (value[i].data[2] == '=') {
                s.len = value[i].len - 3;
                s.data = value[i].data + 3;
                rule->negative = 0;

            } else {
                s.len = value[i].len - 4;
                s.data = value[i].data + 4;
                rule->negative = 1;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            rule->filter = ccv.complex_value;

            continue;
        }

        if (ngx_strncmp(value[i].data, "flag=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            if (ngx_strcmp(s.data, "break") == 0) {
                rule->flag = 1;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid flag \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid parameter \"%V\"", &value[i]);
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_cookies_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cookies_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cookies_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->rules = NGX_CONF_UNSET_PTR;
    conf->inherit_mode = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_cookies_filter_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_cookies_filter_loc_conf_t *prev = parent;
    ngx_http_cookies_filter_loc_conf_t *conf = child;

    ngx_array_t                        *new_rules;
    ngx_http_cookies_filter_rule_t     *pr, *cr, *nr;
    ngx_uint_t                          i;

    ngx_conf_merge_uint_value(conf->inherit_mode, prev->inherit_mode,
                              NGX_HTTP_COOKIES_FILTER_INHERIT_ON);

    if (conf->inherit_mode == NGX_HTTP_COOKIES_FILTER_INHERIT_OFF) {
        if (conf->rules == NGX_CONF_UNSET_PTR) {
            conf->rules = NULL;
        }

        return NGX_CONF_OK;
    }

    if (conf->rules == NGX_CONF_UNSET_PTR) {
        conf->rules = (prev->rules == NGX_CONF_UNSET_PTR) ? NULL : prev->rules;
        return NGX_CONF_OK;
    }

    if (prev->rules == NGX_CONF_UNSET_PTR || prev->rules == NULL) {
        return NGX_CONF_OK;
    }

    if (conf->inherit_mode == NGX_HTTP_COOKIES_FILTER_INHERIT_ON) {
        return NGX_CONF_OK;
    }

    if (conf->inherit_mode == NGX_HTTP_COOKIES_FILTER_INHERIT_AFTER) {
        pr = prev->rules->elts;
        for (i = 0; i < prev->rules->nelts; i++) {
            cr = ngx_array_push(conf->rules);
            if (cr == NULL) {
                return NGX_CONF_ERROR;
            }

            *cr = pr[i];
        }

        return NGX_CONF_OK;
    }

    /* NGX_HTTP_COOKIES_FILTER_INHERIT_BEFORE */
    new_rules = ngx_array_create(cf->pool,
        prev->rules->nelts + conf->rules->nelts,
        sizeof(ngx_http_cookies_filter_rule_t));

    if (new_rules == NULL) {
        return NGX_CONF_ERROR;
    }

    pr = prev->rules->elts;
    for (i = 0; i < prev->rules->nelts; i++) {
        nr = ngx_array_push(new_rules);
        if (nr == NULL) {
            return NGX_CONF_ERROR;
        }

        *nr = pr[i];
    }

    cr = conf->rules->elts;
    for (i = 0; i < conf->rules->nelts; i++) {
        nr = ngx_array_push(new_rules);
        if (nr == NULL) {
            return NGX_CONF_ERROR;
        }

        *nr = cr[i];
    }

    conf->rules = new_rules;

    return NGX_CONF_OK;
}
