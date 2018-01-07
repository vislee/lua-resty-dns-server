Name
====

lua-resty-dns-server - Lua DNS server driver for the OpenResty

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Description](#description)
* [Synopsis](#synopsis)
* [Methods](#methods)
    * [new](#new)
    * [decode_request](#decode_request)
    * [create_a_answer](#create_a_answer)
    * [create_aaaa_answer](#create_aaaa_answer)
    * [create_cname_answer](#create_cname_answer)
    * [create_ns_answer](#create_ns_answer)
    * [create_soa_answer](#create_soa_answer)
    * [encode_response](#encode_response)
* [Constants](#constants)
    * [TYPE_A](#type_a)
    * [TYPE_NS](#type_ns)
    * [TYPE_CNAME](#type_cname)
    * [TYPE_SOA](#type_soa)
    * [TYPE_MX](#type_mx)
    * [TYPE_TXT](#type_txt)
    * [TYPE_AAAA](#type_aaaa)
    * [TYPE_SRV](#type_srv)
* [TODO](#todo)
* [Author](#author)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

Status
======

This library is still under early development and is still experimental.

Description
===========

This Lua library provies a DNS server driver for the ngx_lua nginx module:

https://github.com/openresty/stream-lua-nginx-module/#readme

Synopsis
========

```nginx
lua_package_path "/path/to/lua-resty-dns-server/lib/?.lua;;";

stream {
    server {
        listen 53 udp;
        content_by_lua_block {
            local server = require 'resty.dns.server'
            local sock, err = ngx.req.udp_socket()
            if not sock then
                ngx.log(ngx.ERR, "failed to get the request socket: ", err)
                return ngx.exit(ngx.ERROR)
            end

            local req, err = sock:receive()
            if not req then
                ngx.log(ngx.ERR, "failed to receive: ", err)
                return ngx.exit(ngx.ERROR)
            end

            local dns = server:new()
            local ok, err = dns:decode_request(req)
            if not ok then
                ngx.log(ngx.ERR, "failed to decode request: ", err)

                local resp = dns:encode_response()
                local ok, err = sock:send(resp)
                if not ok then
                    ngx.log(ngx.ERR, "failed to send: ", err)
                    ngx.exit(ngx.ERROR)
                end

                return
            end

            local query = dns.request.questions[1]
            ngx.log(ngx.DEBUG, "qname: ", query.qname, " qtype: ", query.qtype)

            local cname = "sinacloud.com"

            if query.qtype == dns.TYPE_CNAME or
            query.qtype == dns.TYPE_AAAA or query.qtype == dns.TYPE_A then

                local err = dns:create_cname_answer(query.qname, 600, cname)
                if err then
                    ngx.log(ngx.ERR, "failed to create cname answer: ", err)
                    return
                end
            else
                dns:create_soa_answer("test.com", 600, "a.root-test.com", "liwq.test.com", 1515161223, 1800, 900, 604800, 86400)
            end
        }

        local resp = dns:encode_response()
        local ok, err = sock:send(resp)
        if not ok then
            ngx.log(ngx.ERR, "failed to send: ", err)
            return
        end
    }
}

```

[Back to TOC](#table-of-contents)

Methods
=======

[Back to TOC](#table-of-contents)

new
---
`syntax: s, err = class:new()`

Creates a dns.server object. Returns `nil` and an message string on error.

[Back to TOC](#table-of-contents)

decode_request
--------------
`syntax: ok, err = s:decode_request(request)`

Parse the DNS request.

[Back to TOC](#table-of-contents)

create_a_answer
--------------
`syntax: err = s:create_a_answer(name, ttl, ipv4)`

Create the A records. Returns `nil` or an message string on error.
which usually takes some of the following fields:

* `name`

    The resource record name.
* `ttl`

    The time-to-live (TTL) value in seconds for the current resource record.
* `ipv4`

    The IPv4 address.

[Back to TOC](#table-of-contents)

create_aaaa_answer
---------------
`syntax: err = s:create_aaaa_answer(name, ttl, ipv6)`

Create the AAAA records. Returns `nil` or an message string on error.
which usually takes some of the following fields:

* `name`

    The resource record name.
* `ttl`

    The time-to-live (TTL) value in seconds for the current resource record.
* `ipv6`

    The IPv6 address.

[Back to TOC](#table-of-contents)

create_cname_answer
-------------------
`syntax: err = s:create_cname_answer(name, ttl, cname)`

Create the CNAME records. Returns `nil` or an message string on error.
which usually takes some of the following fields:

* `name`

    The resource record name.
* `ttl`

    The time-to-live (TTL) value in seconds for the current resource record.
* `cname`

    The name for an alias.

[Back to TOC](#table-of-contents)

create_ns_answer
----------------
`syntax: err = s:create_ns_answer(name, ttl, nsdname)`

Create the NS records. Returns `nil` or an message string on error.
which usually takes some of the following fields:

* `name`

    The resource record name.
* `ttl`

    The time-to-live (TTL) value in seconds for the current resource record.
* `nsdname`

    The specifies a host which should be authoritative for the specified class and domain.

[Back to TOC](#table-of-contents)

create_soa_answer
-----------------
`syntax: err = s:create_soa_answer(name, ttl, mname, rname, serial, refresh, retry, expire, minimum)`

Create the SOA records. Returns `nil` or an message string on error.
which usually takes some of the following fields:

* `name`

    The resource record name.
* `ttl`

    The time-to-live (TTL) value in seconds for the current resource record.
* `mname`

    The the name server that was the original or primary source of data for this zone.
* `rname`

    The mailbox of the person responsible for this zone.
* `serial`

    The unsigned 32 bit version number of the original copy of the zone.
* `refresh`

    A 32 bit time interval before the zone should be refreshed.
* `retry`

    A 32 bit time interval that should elapse before a failed refresh should be retried.
* `expire`

    A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative.
* `minimum`

    The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.

[Back to TOC](#table-of-contents)

encode_response
---------------
`syntax: resp = s:encode_response()`

Encode the DNS answers. Returns an message string on respone or `nil`.

[Back to TOC](#table-of-contents)

Constants
=========

[Back to TOC](#table-of-contents)

TYPE_A
------

The `A` resource record type, equal to the decimal number `1`.

[Back to TOC](#table-of-contents)

TYPE_NS
-------

The `NS` resource record type, equal to the decimal number `2`.

[Back to TOC](#table-of-contents)

TYPE_CNAME
----------

The `CNAME` resource record type, equal to the decimal number `5`.

[Back to TOC](#table-of-contents)

TYPE_SOA
----------

The `SOA` resource record type, equal to the decimal number `6`.

[Back to TOC](#table-of-contents)

TYPE_MX
-------

The `MX` resource record type, equal to the decimal number `15`.

[Back to TOC](#table-of-contents)

TYPE_TXT
--------

The `TXT` resource record type, equal to the decimal number `16`.

[Back to TOC](#table-of-contents)

TYPE_AAAA
---------
`syntax: typ = s.TYPE_AAAA`

The `AAAA` resource record type, equal to the decimal number `28`.

[Back to TOC](#table-of-contents)

TYPE_SRV
---------
`syntax: typ = s.TYPE_SRV`

The `SRV` resource record type, equal to the decimal number `33`.

See RFC 2782 for details.

[Back to TOC](#table-of-contents)


TODO
====

[Back to TOC](#table-of-contents)

Author
======

wenqiang li(vislee)

[Back to TOC](#table-of-contents)


Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2018, by vislee.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

See Also
========
* the stream-lua-nginx-module: https://github.com/openresty/stream-lua-nginx-module/#readme
* the [lua-resty-dns](https://github.com/openresty/lua-resty-dns) library.

[Back to TOC](#table-of-contents)
