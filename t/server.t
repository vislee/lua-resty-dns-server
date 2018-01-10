# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(1);

log_level('warn');

plan tests => repeat_each() * (blocks() * 3);

no_long_string();
#no_diff();
run_tests();

__DATA__


=== TEST 1: test CNAME records
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("www.test.com", { qtype = r.TYPE_CNAME })
        if not answers then
            ngx.say("failed to query: ", err)
            return
        end

        if answers[1].name ~= "www.test.com" or answers[1].cname ~= "sinacloud.com" or answers[1].ttl ~= 600 or answers[1].type ~= r.TYPE_CNAME then
            ngx.say("error")
        else
            ngx.say("ok")
        end
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "www.test.com" and query.qtype == server.TYPE_CNAME then
            dns:create_cname_answer(query.qname, 600, "sinacloud.com")
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok
--- error_log
stream lua tcp socket read timed out


=== TEST 2: test A records
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("www.test.com", { qtype = r.TYPE_A })
        if not answers then
            ngx.say("failed to query: ", err)
            return
        end

        if answers[1].name ~= "www.test.com" or answers[1].address ~= "127.0.0.1" or answers[1].ttl ~= 300 or answers[1].type ~= r.TYPE_A then
            ngx.say("error")
        else
            ngx.say("ok")
        end
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "www.test.com" and query.qtype == server.TYPE_A then
            dns:create_a_answer(query.qname, 300, "127.0.0.1")
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok

--- error_log
stream lua tcp socket read timed out


=== TEST 3: test AAAA records
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("www.test.com", { qtype = r.TYPE_AAAA })
        if not answers then
            ngx.say("failed to query: ", err)
            return
        end

        if answers[1].name ~= "www.test.com" or answers[1].address ~= "1001:1002:1003:1004:1005:1006:1007:1008" or 
        answers[1].ttl ~= 300 or answers[1].type ~= r.TYPE_AAAA then
            ngx.say("error")
        else
            ngx.say("ok")
        end
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "www.test.com" and query.qtype == server.TYPE_AAAA then
            dns:create_aaaa_answer(query.qname, 300, "1001:1002:1003:1004:1005:1006:1007:1008")
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok

--- error_log
stream lua tcp socket read timed out


=== TEST 4: test TXT records
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("www.test.com", { qtype = r.TYPE_TXT })
        if not answers then
            ngx.say("failed to query: ", err)
            return
        end

        if answers[1].name ~= "www.test.com" or answers[1].txt ~= "v=spf1 include:_spf.test.com ~all" or 
        answers[1].ttl ~= 3000 or answers[1].type ~= r.TYPE_TXT then
            ngx.say("error")
        else
            ngx.say("ok")
        end
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "www.test.com" and query.qtype == server.TYPE_TXT then
            dns:create_txt_answer(query.qname, 3000, "v=spf1 include:_spf.test.com ~all")
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok

--- error_log
stream lua tcp socket read timed out

=== TEST 5: test NS records
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("www.test.com", { qtype = r.TYPE_NS })
        if not answers or #answers ~=2 then
            ngx.say("failed to query: ", err)
            return
        end

        if answers[1].name ~= "www.test.com" or answers[1].ttl ~= 3000 or answers[1].type ~= r.TYPE_NS or
        (answers[1].nsdname ~= "ns1.test.com" and answers[1].nsdname ~= "ns2.test.com") then
            ngx.say("error")
            return
        else
            ngx.say("ok")
        end
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "www.test.com" and query.qtype == server.TYPE_NS then
            dns:create_ns_answer(query.qname, 3000, "ns1.test.com")
            dns:create_ns_answer(query.qname, 3000, "ns1.test.com")
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok

--- error_log
stream lua tcp socket read timed out


=== TEST 6: test SOA records
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("test.com", { qtype = r.TYPE_SOA })
        if not answers then
            ngx.say("failed to query: ", err)
            return
        end

        if answers[1].name ~= "test.com" or answers[1].ttl ~= 60 or answers[1].type ~= r.TYPE_SOA or
        answers[1].mname ~= "ns1.test.com" or answers[1].rname ~= "dns-admin.test.com" or
        answers[1].serial ~= 181394707 or answers[1].refresh ~= 900 or answers[1].retry ~= 900 or
        answers[1].expire ~= 2400 or (answers[1].mininum and answers[1].mininum ~= 61) or (answers[1].minimum and answers[1].minimum ~= 61)  then
            ngx.say("error")
            return
        else
            ngx.say("ok")
        end
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "test.com" and query.qtype == server.TYPE_SOA then
            dns:create_soa_answer(query.qname, 60, "ns1.test.com", "dns-admin.test.com", 181394707, 900, 900, 2400, 61)
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok

--- error_log
stream lua tcp socket read timed out

=== TEST 7: test MX records
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("test.com", { qtype = r.TYPE_MX })
        if not answers then
            ngx.say("failed to query: ", err)
            return
        end

        if answers[1].name ~= "test.com" or answers[1].ttl ~= 60 or answers[1].type ~= r.TYPE_MX or
        answers[1].preference ~= 10 or answers[1].exchange ~= "aspmx.l.test.com" then
            ngx.say("error")
            return
        else
            ngx.say("ok")
        end
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "test.com" and query.qtype == server.TYPE_MX then
            dns:create_mx_answer(query.qname, 60, 10, "aspmx.l.test.com")
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok

--- error_log
stream lua tcp socket read timed out

=== TEST 8: test SRV records
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("_xmpp-server._tcp.test.com", { qtype = r.TYPE_SRV })
        if not answers then
            ngx.say("failed to query: ", err)
            return
        end

        if answers[1].name ~= "_xmpp-server._tcp.test.com" or answers[1].ttl ~= 60 or answers[1].type ~= r.TYPE_SRV or
        answers[1].priority ~= 10 or answers[1].weight ~= 1 or answers[1].port ~= 4343 or answers[1].target ~= "xmpp-server.l.test.com" then
            ngx.say("error")
            return
        else
            ngx.say("ok")
        end
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "_xmpp-server._tcp.test.com" and query.qtype == server.TYPE_SRV then
            dns:create_srv_answer(query.qname, 60, 10, 1, 4343, "xmpp-server.l.test.com")
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok

--- error_log
stream lua tcp socket read timed out

=== TEST 9: test NS and AR section
--- stream_server_config
    content_by_lua_block {
        local resolver = require "resty.dns.resolver"
        local r, err = resolver:new{
            nameservers = {{"127.0.0.1", 1986} }
        }
        if not r then
            ngx.say("failed to instantiate resolver: ", err)
            return
        end

        local answers, err = r:tcp_query("www.test.com", { qtype = r.TYPE_A, authority_section=true, additional_section=true })
        if not answers or #answers ~= 3 then
            ngx.say("failed to query: ", err)
            return
        end

        for _, ans in ipairs(answers) do
            for k, v in pairs(ans) do
                ngx.log(ngx.INFO, "=ans==", k, "=", v)
            end
            if ans.section == r.SECTION_AN then
                if ans.name ~= "www.test.com" or ans.ttl ~= 60 or ans.address ~= "11.11.11.11" then
                    ngx.say("error")
                    return
                end
            elseif ans.section == r.SECTION_NS then
                if ans.name ~= "test.com" or ans.ttl ~= 600 or ans.nsdname ~= "ns1.test.com" then
                    ngx.say("error")
                    return
                end
            elseif ans.section == r.SECTION_AR then
                if ans.name ~= "ns1.test.com" or ans.ttl ~= 300 or ans.address ~= "22.22.22.22" then
                    ngx.say("error")
                    return
                end
            else
                ngx.say("error")
            end
        end
        ngx.say("ok")
    }

--- stream_server_config2
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

        sock:settimeout(1000)
        local buf, err = sock:receive(2)
        if not buf then
            ngx.say(string.format("sock receive error: %s", err))
            return
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
        if query.qname == "www.test.com" and query.qtype == server.TYPE_A then
            dns:create_a_answer(query.qname, 60, "11.11.11.11")
            dns:create_ns_answer("test.com", 600, "ns1.test.com")
            dns:create_a_answer("ns1.test.com", 300, "22.22.22.22")
        else
            dns:create_response_header(server.RCODE_NOT_IMPLEMENTED)
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
--- stream_response_like
ok

--- error_log
stream lua tcp socket read timed out
