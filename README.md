# ngx_http_request_cookies_filter_module

# Name
ngx_http_request_cookies_filter_module

A NGINX module for fine-grained request cookies control.

# Table of Content

- [ngx\_http\_request\_cookies\_filter\_module](#ngx_http_request_cookies_filter_module)
- [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
  - [set\_request\_cookie](#set_request_cookie)
  - [add\_request\_cookie](#add_request_cookie)
  - [modify\_request\_cookie](#modify_request_cookie)
  - [clear\_request\_cookie](#clear_request_cookie)
- [Variables](#variables)
  - [$filtered\_request\_cookies](#filtered_request_cookies)
- [Author](#author)
- [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```nginx
http {
    server {
        listen 80;
        server_name example.com;

        location / {
            # If a cookie named "a" exists, set it to 1. Otherwise, add a cookie named "a" with value 1.
            set_request_cookie a 1;

            # If a cookie named "b" exists, do nothing. Otherwise, add a cookie named "a" with value 1.
            add_request_cookie b 2;

            # If a cookie named "c" exists, set it to 3. Otherwise, do nothing.
            modify_request_cookie c 3;
    
            # If a cookie named "d" exists, delete it. Otherwise, do nothing.
            clear_request_cookie d;

            # Conditional filtering. Only effected if varialbe $http_a is not empty or '0'.
            set_request_cookie e 4 if=$http_a;

            # Send the filtered cookies to upstream.
            proxy_set_header Cookie $filtered_request_cookies;

            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_request_cookies_filter_module`.

# Directives

## set_request_cookie

**Syntax:** `set_request_cookie cookie_name value [if=condition];`

**Default:** —

**Context:** http, server, location

Sets the value of a cookie. If the cookie already exists, it will be modified.

Cookie names are case-sensitive, the same below.

## add_request_cookie

**Syntax:** `add_request_cookie cookie_name value [if=condition];`

**Default:** —

**Context:** http, server, location

Adds a new cookie. If the cookie already exists, the operation is ignored.

## modify_request_cookie

**Syntax:** `modify_request_cookie cookie_name value [if=condition];`

**Default:** —

**Context:** http, server, location

Modifies an existing cookie's value. If the cookie doesn't exist, the operation is ignored.

## clear_request_cookie

**Syntax:** `clear_request_cookie cookie_name [if=condition];`

**Default:** —

**Context:** http, server, location

Removes a cookie from the request headers.

# Variables

## $filtered_request_cookies

A semicolon-separated string of filtered cookies. Contains the final cookie string after applying all filter rules.
If no filter rules are applied, the variable contains the original cookie string, like `$http_cookie`.


**Example:**  
```nginx
location / {
    set_request_cookie user "test_user";
    add_request_cookie theme "dark";
    # will be "user=test_user; theme=dark" if request do not contain any cookies.
    proxy_set_header Cookie $filtered_request_cookies;
    proxy_pass http://backend;
}
```

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
