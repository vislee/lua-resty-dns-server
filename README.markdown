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
    * [create_txt_answer](#create_txt_answer)
    * [create_ns_answer](#create_ns_answer)
    * [create_soa_answer](#create_soa_answer)
    * [create_mx_answer](#create_mx_answer)
    * [create_srv_answer](#create_srv_answer)
    * [create_response_header](#create_response_header)
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
    * [TYPE_ANY](#type_any)
    * [RCODE_NOT_IMPLEMENTED](#rcode_not_implemented)
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
            local request, err = dns:decode_request(req)
            if not request then
                ngx.log(ngx.ERR, "failed to decode request: ", err)

                local resp = dns:encode_response()
                local ok, err = sock:send(resp)
                if not ok then
                    ngx.log(ngx.ERR, "failed to send: ", err)
                    ngx.exit(ngx.ERROR)
                end

                return
            end

            local query = request.questions[1]
            ngx.log(ngx.DEBUG, "qname: ", query.qname, " qtype: ", query.qtype)

            local cname = "sinacloud.com"

            if query.qtype == server.TYPE_CNAME or
                query.qtype == server.TYPE_AAAA or query.qtype == server.TYPE_A then

                local err = dns:create_cname_answer(query.qname, 600, cname)
                if err then
                    ngx.log(ngx.ERR, "failed to create cname answer: ", err)
                    return
                end
            else
                dns:create_soa_answer("test.com", 600, "a.root-test.com", "vislee.test.com", 1515161223, 1800, 900, 604800, 86400)
            end

            local resp = dns:encode_response()
            local ok, err = sock:send(resp)
            if not ok then
                ngx.log(ngx.ERR, "failed to send: ", err)
                return
            end
        }
    }

    server {
        listen 53;
        content_by_lua_block {
            local bit    = require 'bit'
            local lshift = bit.lshift
            local rshift = bit.rshift
            local band   = bit.band
            local byte   = string.byte
            local char   = string.char
            local server = require 'resty.dns.server'

            local sock, err = ngx.req.socket()
            if not sock then
                ngx.log(ngx.ERR, "failed to get the request socket: ", err)
                return ngx.exit(ngx.ERROR)
            end

            local buf, err = sock:receive(2)
            if not buf then
                ngx.log(ngx.ERR, "failed to receive: ", err)
                return ngx.exit(ngx.ERROR)
            end

            local len_hi = byte(buf, 1)
            local len_lo = byte(buf, 2)
            local len = lshift(len_hi, 8) + len_lo
            local data, err = sock:receive(len)
            if not data then
                ngx.log(ngx.ERR, "failed to receive: ", err)
                return ngx.exit(ngx.ERROR)
            end

            local dns = server:new()
            local request, err = dns:decode_request(data)
            if not request then
                ngx.log(ngx.ERR, "failed to decode dns request: ", err)
                return
            end

            local query = request.questions[1]
            ngx.log(ngx.DEBUG, "qname: ", query.qname, " qtype: ", query.qtype)

            if query.qtype == server.TYPE_CNAME or query.qtype == server.TYPE_A then
                dns:create_cname_answer(query.qname, 600, "sinacloud.com")
            elseif query.qtype == server.TYPE_AAAA then
                local resp_header, err = dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
                resp_header.ra = 0
            else
                dns:create_soa_answer("test.com", 600, "a.root-test.com", "vislee.test.com", 1515161223, 1800, 900, 604800, 86400)
            end

            local resp = dns:encode_response()
            local len = #resp
            local len_hi = char(rshift(len, 8))
            local len_lo = char(band(len, 0xff))

            local ok, err = sock:send({len_hi, len_lo, resp})
            if not ok then
                ngx.log(ngx.ERR, "failed to send: ", err)
                return
            end
            return
        }
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
`syntax: request, err = s:decode_request(buf)`

Parse the DNS request.

The request returned the lua table which takes some of the following fields:

* `header`: The `header` is also a lua table which usually takes some of the following fields:

    * `id` : The identifier assigned by the program that generates any kind of query.
    * `qr` : The field specifies whether this message is a query (`0`), or a response (`1`).
    * `opcode` : The field specifies kind of query in this message.
    * `tc` : The field specifies that this message was truncated due to length greater than that permitted on the transmission channel.
    * `rd` : Recursion Desired. If `RD` is set, it directs the name server to pursue the query recursively.
    * `rcode` : response code.
    * `qdcount` : The field specifying the number of entries in the question section.

* `questions` : Each entry in the `questions` is also a lua table which takes some of the following:

    * `qname` : A domain name of query.
    * `qtype` : Specifies the type of the query.
    * `qclass` : Specifies the class of the query. Usually the field is `IN` for the Internet.


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

create_txt_answer
------------------
`syntax: err = s:create_txt_answer(name, ttl, txt)`

Create the txt records. Returns `nil` or an message string on error.
which usually takes some of the following fields:

* `name`

    The resource record name.
* `ttl`

    The time-to-live (TTL) value in seconds for the current resource record.
* `txt`

    The text strings.

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

create_mx_answer
----------------
`syntax: err = s:create_mx_answer(name, ttl, preference, exchange)`

Create the MX records. Returns `nil` or an message string on error.
which usually takes some of the following fields:

* `name`

    The resource record name.
* `ttl`

    The time-to-live (TTL) value in seconds for the current resource record.
* `preference`

    The preference of this mail exchange.
* `exchange`

    The mail exchange.

[Back to TOC](#table-of-contents)

create_srv_answer
-----------------
`syntax: err = s:create_srv_answer(name, ttl, priority, weight, port, target)`

Create the SRV records. Returns `nil` or an message string on error.
which usually takes some of the following fields:

* `name`

    The resource record name.
* `ttl`

    The time-to-live (TTL) value in seconds for the current resource record.
* `priority`

    The priority of this target host.
* `weight`

    The weight field specifies a relative weight for entries with the same priority.
* `port`

    The port on this target host of this service.
* `target`

    The domain name of the target host.

[Back to TOC](#table-of-contents)

create_response_header
-----------------
`syntax: resp_header, err = s:create_response_header(rcode)`

[Back to TOC](#table-of-contents)

encode_response
---------------
`syntax: resp = s:encode_response()`

Encode the DNS answers. Returns an message string on response or `nil`.

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

TYPE_ANY
---------
`syntax: typ = s.TYPE_ANY`

The all resource record type, equal to the decimal number `255`.

[Back to TOC](#table-of-contents)

RCODE_FORMAT_ERROR
------------------

[Back to TOC](#table-of-contents)

RCODE_NOT_IMPLEMENTED
---------------------

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
