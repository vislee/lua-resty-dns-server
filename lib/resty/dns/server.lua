-- Copyright (C) 2018 liwq

local bit    = require "bit"
local byte   = string.byte
local strsub = string.sub
local strlen = string.len
local char   = string.char
local gsub   = string.gsub
local sfmt   = string.format
local lshift = bit.lshift
local rshift = bit.rshift
local band   = bit.band
local concat = table.concat

-- https://www.ietf.org/rfc/rfc2929.txt
-- https://www.ietf.org/rfc/rfc1034.txt
-- https://www.ietf.org/rfc/rfc1035.txt
-- https://www.ietf.org/rfc/rfc2782.txt
-- https://www.ietf.org/rfc/rfc3596.txt
-- https://www.ietf.org/rfc/rfc2671.txt
local TYPE_A      = 1
local TYPE_NS     = 2
local TYPE_CNAME  = 5
local TYPE_SOA    = 6
local TYPE_PTR    = 12
local TYPE_MX     = 15
local TYPE_TXT    = 16
local TYPE_AAAA   = 28
local TYPE_SRV    = 33
local TYPE_OPT    = 41
local TYPE_SPF    = 99
local TYPE_ANY    = 255

local CLASS_IN    = 1

local SECTION_UK  = 0
local SECTION_AN  = 1
local SECTION_NS  = 2
local SECTION_AR  = 3

local CNAME_SENTRY = 'CNAME_SENTRY'

-- rfc2929: 2.3 RCODE Assignment
local RCODE_OK = 0
local RCODE_FORMAT_ERROR = 1
local RCODE_SERVER_FAILURE = 2
local RCODE_NAME_ERROR = 3
local RCODE_NOT_IMPLEMENTED = 4
local RCODE_REFUSED = 5
local RCODE_NOTZONE = 10
local RCODE_BADVERS = 16

-- http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
local ADDR_FAMILY_IP   = 1
local ADDR_FAMILY_IP6  = 2

local _M = {
    _VERSION    = '0.02',
    TYPE_A      = TYPE_A,
    TYPE_NS     = TYPE_NS,
    TYPE_CNAME  = TYPE_CNAME,
    TYPE_SOA    = TYPE_SOA,
    TYPE_PTR    = TYPE_PTR,
    TYPE_MX     = TYPE_MX,
    TYPE_TXT    = TYPE_TXT,
    TYPE_AAAA   = TYPE_AAAA,
    TYPE_SRV    = TYPE_SRV,
    TYPE_SPF    = TYPE_SPF,
    TYPE_ANY    = TYPE_ANY,

    RCODE_FORMAT_ERROR    = RCODE_FORMAT_ERROR,
    RCODE_SERVER_FAILURE  = RCODE_SERVER_FAILURE,
    RCODE_NAME_ERROR      = RCODE_NAME_ERROR,
    RCODE_NOT_IMPLEMENTED = RCODE_NOT_IMPLEMENTED,
    RCODE_REFUSED         = RCODE_REFUSED,
    RCODE_NOTZONE         = RCODE_NOTZONE,
    RCODE_BADVERS         = RCODE_BADVERS,
}

local mt = { __index = _M }

function _M.new(class)
    return setmetatable({
        pos = 0,
        buf = "",
        request = {header = {}, questions = {}, additionals = {}, subnet = {}},
        response = {header = {
                        id = 0,
                        qr = 1,
                        opcode = 0,
                        aa = 0,
                        tc = 0,
                        rd = 0,
                        ra = 0,
                        z  = 0,
                        rcode = 0,
                        qdcount = 0,
                        ancount = 0,
                        nscount = 0,
                        arcount = 0
                    },
                    ansections = {},
                    nssections = {},
                    arsections = {}
        },
        cnames = {count = 0, },
        }, mt)
end


function _M.decode_request(self, req)
    self.buf = self.buf .. req

    -- parse id
    if self.pos + 2 > strlen(self.buf) then
        return nil, "request too short"
    end

    self.pos = self.pos + 2  -- pos=2
    local ident_hi, ident_lo = byte(self.buf, self.pos - 1, self.pos)
    self.request.header.id = lshift(ident_hi, 8) + ident_lo
    self.response.header.id = self.request.header.id
    ngx.log(ngx.DEBUG, "dns server request id: ", self.request.header.id)

    -- parse flags
    if self.pos + 2 > strlen(self.buf) then
        self.response.header.rcode = RCODE_FORMAT_ERROR
        return nil, "request too short"
    end

    self.pos = self.pos + 2  -- pos=4
    local flags_hi, flags_lo = byte(self.buf, self.pos - 1, self.pos)
    local flags = lshift(flags_hi, 8) + flags_lo
    ngx.log(ngx.DEBUG, "dns server request flags: ", flags)

    self.request.header.qr     = rshift(band(flags, 0x8000), 15)
    self.request.header.opcode = rshift(band(flags, 0x7800), 11)
    self.request.header.aa     = rshift(band(flags, 0x0400), 10)
    self.request.header.tc     = rshift(band(flags, 0x0200), 9)
    self.request.header.rd     = rshift(band(flags, 0x0100), 8)
    self.response.header.rd    = self.request.header.rd
    self.request.header.ra     = rshift(band(flags, 0x0080), 7)
    self.request.header.z      = rshift(band(flags, 0x0070), 4)
    self.request.header.rcode  = band(flags, 0x000F)

    if self.request.header.qr ~= 0 then
        self.response.header.rcode = RCODE_FORMAT_ERROR
        ngx.log(ngx.ERR, "bad QR flag in the DNS request")
        return nil, "bad QR flag in the DNS request"
    end

    -- parse qdcount
    if self.pos + 2 > strlen(self.buf) then
        self.response.header.rcode = RCODE_FORMAT_ERROR
        return nil, "request too short"
    end

    self.pos = self.pos + 2  -- pos=6
    local qdc_hi, qdc_lo = byte(self.buf, self.pos - 1, self.pos)
    self.request.header.qdcount = lshift(qdc_hi, 8) + qdc_lo
    ngx.log(ngx.DEBUG, "dns server request qdcount: ", self.request.header.qdcount)

    if self.request.header.qdcount ~= 1 then
        self.response.header.rcode = RCODE_FORMAT_ERROR
        ngx.log(ngx.ERR, "bad qdcount in the DNS request")
        return nil, "bad qdcount in the DNS request"
    end

    -- parse ancount
    if self.pos + 2 > strlen(self.buf) then
        self.response.header.rcode = RCODE_FORMAT_ERROR
        return nil, "request too short"
    end

    self.pos = self.pos + 2  -- pos=8
    local anc_hi, anc_lo = byte(self.buf, self.pos - 1, self.pos)
    self.request.header.ancount = lshift(anc_hi, 8) + anc_lo
    ngx.log(ngx.DEBUG, "dns server request ancount: ", self.request.header.ancount)

    -- parse nscount
    if self.pos + 2 > strlen(self.buf) then
        self.response.header.rcode = RCODE_FORMAT_ERROR
        return nil, "request too short"
    end

    self.pos = self.pos + 2  -- pos=10
    local nsc_hi, nsc_lo = byte(self.buf, self.pos - 1, self.pos)
    self.request.header.nscount = lshift(nsc_hi, 8) + nsc_lo

    -- parse arcount
    if self.pos + 2 > strlen(self.buf) then
        self.response.header.rcode = RCODE_FORMAT_ERROR
        return nil, "request too short"
    end
    self.pos = self.pos + 2  -- pos=12
    local arc_hi, arc_lo = byte(self.buf, self.pos - 1, self.pos)
    self.request.header.arcount = lshift(arc_hi, 8) + arc_lo
    ngx.log(ngx.DEBUG, "dns server request arcount: ", self.request.header.arcount)

    for i = 1, self.request.header.qdcount do
        -- parse qname
        if self.pos + 1 > strlen(self.buf) then
            self.response.header.rcode = RCODE_FORMAT_ERROR
            return nil, "request too short"
        end

        local qnames = {}
        local qname_len = byte(self.buf, self.pos + 1)
        while qname_len > 0 do
            if self.pos + 1 + qname_len > strlen(self.buf) then
                self.response.header.rcode = RCODE_FORMAT_ERROR
                return nil, "request too short"
            end
            self.pos = self.pos + 1
            qnames[#qnames + 1] = strsub(self.buf, self.pos + 1, self.pos + qname_len)
            self.pos = self.pos + qname_len
            qname_len = byte(self.buf, self.pos + 1)
        end
        self.pos = self.pos + 1 -- "\0"

        local qname = concat(qnames, '.')
        ngx.log(ngx.DEBUG, "dns server request qname: ", qname)

        -- parse qtype
        if self.pos + 2 + 2 > strlen(self.buf) then
            self.response.header.rcode = RCODE_FORMAT_ERROR
            return nil, "request too short"
        end

        self.pos = self.pos + 2
        local typ_hi, typ_lo = byte(self.buf, self.pos - 1, self.pos)
        local qtype = lshift(typ_hi, 8) + typ_lo

        -- parse qclass
        self.pos = self.pos + 2
        local class_hi, class_lo = byte(self.buf, self.pos - 1, self.pos)
        local qclass = lshift(class_hi, 8) + class_lo

        self.request.questions[i] = {qname = qname, qtype = qtype, qclass = qclass}
        self.response.header.qdcount = i
    end


    -- EDNS0(rfc1035,rfc2671,rfc7871)
    for i = 1, self.request.header.arcount do
        -- empty name
        self.pos = self.pos + 1
        local qname_len = byte(self.buf, self.pos)

        -- parse TYPE(OPT)
        self.pos = self.pos + 2
        local opt_type_hi, opt_type_lo = byte(self.buf, self.pos - 1, self.pos)
        local opt_type = lshift(opt_type_hi, 8) + opt_type_lo

        -- rfc6891, 6.1.2
        if opt_type == 41 and qname_len == 0 then

            -- parse CLASS(UDP payload size)
            self.pos = self.pos + 2
            local udp_size_hi, udp_size_lo = byte(self.buf, self.pos - 1, self.pos)
            local udp_size = lshift(udp_size_hi, 8) + udp_size_lo

            -- parse TTL(RCODE and flags)
            self.pos = self.pos + 2
            local ext_rcode_hi, ext_rcode_lo = byte(self.buf, self.pos - 1, self.pos)
            local ext_rcode = lshift(ext_rcode_hi, 8) + ext_rcode_lo

            self.pos = self.pos + 2
            local opt_ver_hi, opt_ver_lo = byte(self.buf, self.pos - 1, self.pos)
            local opt_ver = lshift(opt_ver_hi, 8) + opt_ver_lo
            -- if opt_ver ~= 0 then
            --     self.response.header.rcode = RCODE_BADVERS
            --     return nil, "bad EDNS0 opt version(" .. opt_ver .. ")"
            -- end

            -- parse RDLENGTH(describes RDATA)
            self.pos = self.pos + 2
            local rdlen_hi, rdlen_lo = byte(self.buf, self.pos - 1, self.pos)
            local rdlen = lshift(rdlen_hi, 8) + rdlen_lo

            -- parse RDATA(OPTION)
            -- rfc7871, 6. Option Format
  

            local rdata = nil
            if rdlen > 0 then
                -- get whole rdata
                rdata = strsub(self.buf, self.pos +1   , self.pos + rdlen)

                -- parse OPTION-CODE
                self.pos = self.pos + 2
                local opt_code_hi, opt_code_lo = byte(self.buf, self.pos - 1, self.pos)
                local opt_code = lshift(opt_code_hi, 8) + opt_code_lo

                -- parse OPTION-LENGTH
                self.pos = self.pos + 2
                local opt_len_hi, opt_len_lo = byte(self.buf, self.pos - 1, self.pos)
                local opt_len = lshift(opt_len_hi, 8) + opt_len_lo

                -- parse OPTION-DATA
                -- parse FAMILY
                self.pos = self.pos + 2
                local opt_family_hi, opt_family_lo = byte(self.buf, self.pos - 1, self.pos)
                local opt_family = lshift(opt_family_hi, 8) + opt_family_lo

                -- parse SOURCE PREFIX-LENGTH, SCOPE PREFIX-LENGTH
                self.pos = self.pos + 2
                local source_prefix_len, scope_prefix_len = byte(self.buf, self.pos - 1, self.pos)

                -- parse address ...
                -- opt_len include (2B opt_family, 1B source_prefix_len, 1B scope_prefix_len)
                local address
                local addr_len = opt_len - 4
                if opt_family == ADDR_FAMILY_IP then
                    local ipv4 = {0, 0, 0, 0}
                    for i = 1, addr_len do
                        self.pos = self.pos + 1
                        ipv4[i] = byte(self.buf, self.pos)
                    end
                    address = concat(ipv4, ".")

                elseif opt_family == ADDR_FAMILY_IP6 then
                    local ipv6 = {0, 0, 0, 0, 0, 0, 0, 0}
                    local idx = 1
                    for i = 1, addr_len, 2 do
                        self.pos = self.pos + 2
                        local v6_item_hi, v6_item_lo = byte(self.buf, self.pos - 1, self.pos)
                        local v6_item = lshift(v6_item_hi, 8) + v6_item_lo
                        ipv6[idx] = sfmt("%04x", v6_item)
                        idx = idx + 1
                    end
                    address = concat(ipv6, ":")
                end
                self.request.subnet[#self.request.subnet + 1] = {address = address,
                                                                mask = source_prefix_len,
                                                                family = opt_family}
            end
            self.request.additionals[#self.request.additionals + 1] = { name="",
                                                                        type = opt_type, 
                                                                        class = udp_size,
                                                                        ttl = ext_rcode,
                                                                        rdlength = rdlen,
                                                                        rdata = rdata  }
        else
            ngx.log(ngx.WARN, "parse EDNS0 error. qname_len: ",
                qname_len, " opt_type: ", opt_type)
        end
    end

    self.response.header.rcode = RCODE_OK

    return self.request
end


function _M.create_response_header(self, rcode)
    if rcode > RCODE_REFUSED then
        return nil, "rcode error"
    end

    self.response.header.id = self.request.header.id
    self.response.header.qr = 1
    self.response.header.opcode = 0
    self.response.header.aa = 0
    self.response.header.tc = 0
    self.response.header.rd = 1
    self.response.header.ra = 0
    self.response.header.z  = 0
    self.response.header.rcode = rcode

    self.response.header.qdcount = self.request.header.qdcount
    self.response.header.ancount = 0
    self.response.header.nscount = 0
    self.response.header.arcount = 0

    return self.response.header
end


local function _encode_4byt(x)
    local hi_hi = band(rshift(x, 24), 0x00FF)
    local hi_lo = band(rshift(x, 16), 0x00FF)
    local lo_hi = band(rshift(x, 8), 0x00FF)
    local lo_lo = band(x, 0x00FF)

    return char(hi_hi, hi_lo, lo_hi, lo_lo)
end

local function _encode_2byt(x)
    local hi = band(rshift(x, 8), 0x00FF)
    local lo = band(x, 0x00FF)

    return char(hi, lo)
end


local function _encode_name(name)
    return gsub(name, "([^.]+)%.?", function(label) return char(#label) .. label end) .. '\0'
end


local function _encode_a(ipv4)
    return gsub(ipv4, "([^.]+)%.?", function(s) return char(tonumber(s)) end)
end

local function _encode_aaaa(ipv6)
    return gsub(ipv6, "([^:]+)%:?", function(s) return _encode_2byt(tonumber(string.format("0x%s", s)) or 0x00) end)
end


local function _encode_txt(txt)
    return char(#txt) .. txt
end


local function _encode_soa(mname, rname, serial, refresh, retry, expire, minimum)
    return mname .. rname .. _encode_4byt(serial) .. _encode_4byt(tonumber(refresh) or 900) ..
               _encode_4byt(tonumber(retry) or 900) .. _encode_4byt(tonumber(expire) or 1800) ..
               _encode_4byt(tonumber(minimum) or 60)
end


local function _encode_mx(preference, exchange)
    return '\0' .. char(tonumber(preference) or 10) .. exchange
end


local function _encode_srv(priority, weight, port, target)
    return _encode_2byt(priority) .. _encode_2byt(weight) .. _encode_2byt(port) .. target
end


function _M.encode_response(self)
    local buf = ""
    -- id
    buf = buf .. _encode_2byt(self.response.header.id)

    -- flags
    local flags_hi = lshift(self.response.header.qr, 7) + lshift(self.response.header.opcode, 3) +
        lshift(self.response.header.aa, 2) + lshift(self.response.header.tc, 1) + self.response.header.rd
    local flags_lo = lshift(self.response.header.ra, 7) + lshift(self.response.header.z, 4) + self.response.header.rcode
    buf = buf .. char(flags_hi, flags_lo)

    buf = buf .. _encode_2byt(self.response.header.qdcount)
    buf = buf .. _encode_2byt(self.response.header.ancount)
    buf = buf .. _encode_2byt(self.response.header.nscount)
    buf = buf .. _encode_2byt(self.response.header.arcount)

    for i = 1, self.response.header.qdcount do
        buf = buf .. _encode_name(self.request.questions[i].qname)
        buf = buf .. _encode_2byt(self.request.questions[i].qtype)
        buf = buf .. _encode_2byt(self.request.questions[i].qclass)
    end

    for i = 1, self.response.header.ancount do
        buf = buf .. _encode_name(self.response.ansections[i].name)
        buf = buf .. _encode_2byt(self.response.ansections[i].type)
        buf = buf .. _encode_2byt(self.response.ansections[i].class)
        buf = buf .. _encode_4byt(self.response.ansections[i].ttl or 0x258)
        buf = buf .. _encode_2byt(self.response.ansections[i].rdlength)
        buf = buf .. self.response.ansections[i].rdata
    end

    for i = 1, self.response.header.nscount do
        buf = buf .. _encode_name(self.response.nssections[i].name)
        buf = buf .. _encode_2byt(self.response.nssections[i].type)
        buf = buf .. _encode_2byt(self.response.nssections[i].class)
        buf = buf .. _encode_4byt(self.response.nssections[i].ttl or 0x258)
        buf = buf .. _encode_2byt(self.response.nssections[i].rdlength)
        buf = buf .. self.response.nssections[i].rdata
    end

    for i = 1, self.response.header.arcount do
       	buf = buf .. _encode_name(self.response.arsections[i].name)
        buf = buf .. _encode_2byt(self.response.arsections[i].type)
        buf = buf .. _encode_2byt(self.response.arsections[i].class)
        buf = buf .. _encode_4byt(self.response.arsections[i].ttl or 0x258)
        buf = buf .. _encode_2byt(self.response.arsections[i].rdlength)
        if self.response.arsections[i].rdlength > 0 then 
		    buf = buf .. self.response.arsections[i].rdata
	    end
    end

    return buf
end


function _M.create_a_answer(self, name, ttl, ipv4)
    if not name or #name == 0 then
        return "name nil"
    end

    if not ipv4 or #ipv4 == 0 then
        return "ipv4 nil"
    end

    if not ngx.re.match(ipv4, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$') then
        ngx.log(ngx.ERR, "ipv4 format error")
        return "ipv4 format error"
    end

    if self.cnames.count > 0 and self.cnames[name] and self.cnames[name] ~= CNAME_SENTRY then
        return "conflict cname"
    end

    local query = self.request.questions[1]
    local section = SECTION_UK
    if (query.qtype == TYPE_A or query.qtype == TYPE_ANY) and query.qname == name and self.cnames.count == 0 then
        section = SECTION_AN
    end

    if self.cnames.count > 0 and self.cnames[name] == CNAME_SENTRY then
        section = SECTION_AN
    end

    local answer = {}
    answer.name = name
    answer.type = TYPE_A
    answer.class = CLASS_IN
    answer.ttl = ttl
    answer.rdlength = 4
    answer.rdata = _encode_a(ipv4)

    if section == SECTION_AN then
        self.response.header.ancount = self.response.header.ancount + 1
        self.response.ansections[self.response.header.ancount] = answer
    else
        self.response.header.arcount = self.response.header.arcount + 1
        self.response.arsections[self.response.header.arcount] = answer
    end

    return nil
end

function _M.replay_additional_opts(self)

    for i = 1, #self.request.additionals do
        local additional = self.request.additionals[i]
        self.response.header.arcount = self.response.header.arcount + 1
        self.response.arsections[self.response.header.arcount] = additional
    end

    return nil
end


function _M.create_cname_answer(self, name, ttl, cname)
    if not name or #name == 0 then
        return "name nil"
    end

    if not cname or #cname == 0 then
        return "cname nil"
    end

    if self.cnames.count > 0 and not self.cnames[name] then
        return "cname linked error"
    end

    if self.cnames.count > 0 and self.cnames[name] ~= CNAME_SENTRY then
        return "cname conflict"
    end

    local answer = {}
    answer.name = name
    answer.type = TYPE_CNAME
    answer.class = CLASS_IN
    answer.ttl = ttl
    answer.rdlength = strlen(_encode_name(cname))
    answer.rdata = _encode_name(cname)

    self.cnames[name] = cname
    self.cnames[cname] = CNAME_SENTRY
    self.cnames.count = self.cnames.count + 1

    self.response.header.ancount = self.response.header.ancount + 1
    self.response.ansections[self.response.header.ancount] = answer

    return nil
end


function _M.create_txt_answer(self, name, ttl, txt)
    if not name or #name == 0 then
        return "name nil"
    end

    if not txt or #txt == 0 then
        return "txt nil"
    end

    local answer = {}
    answer.name = name
    answer.type = TYPE_TXT
    answer.class = CLASS_IN
    answer.ttl = ttl
    answer.rdlength = strlen(txt) + 1
    answer.rdata = _encode_txt(txt)

    self.response.header.ancount = self.response.header.ancount + 1
    self.response.ansections[self.response.header.ancount] = answer

    return nil
end


function _M.create_ns_answer(self, name, ttl, nsdname)
    if not name or #name == 0 then
        return "name nil"
    end

    if not nsdname or #nsdname == 0 then
        return "nsdname nil"
    end

    local answer = {}
    answer.name = name
    answer.type = TYPE_NS
    answer.class = CLASS_IN
    answer.ttl = ttl
    answer.rdlength = strlen(_encode_name(nsdname))
    answer.rdata = _encode_name(nsdname)

    local query = self.request.questions[1]
    if query.qname == name and (query.qtype == TYPE_NS or query.qtype == TYPE_ANY) then
        self.response.header.ancount = self.response.header.ancount + 1
        self.response.ansections[self.response.header.ancount] = answer
    else
        self.response.header.nscount = self.response.header.nscount + 1
        self.response.nssections[self.response.header.nscount] = answer
    end

    return nil
end


function _M.create_aaaa_answer(self, name, ttl, ipv6)
    if not name or #name == 0 then
        return "name nil"
    end

    if not ipv6 or #ipv6 == 0 then
        return "ipv6 nil"
    end

    if not ngx.re.match(ipv6, "^[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+$") then
        ngx.log(ngx.ERR, "not match ipv6")
        return "ipv6 format error"
    end

    if self.cnames.count > 0 and self.cnames[name] and self.cnames[name] ~= CNAME_SENTRY then
        return "conflict cname"
    end

    local query = self.request.questions[1]
    local section = SECTION_UK
    if (query.qtype == TYPE_AAAA or query.qtype == TYPE_ANY) and query.qname == name and self.cnames.count == 0 then
        section = SECTION_AN
    end

    if self.cnames.count > 0 and self.cnames[name] == CNAME_SENTRY then
        section = SECTION_AN
    end

    local answer = {}
    answer.name = name
    answer.type = TYPE_AAAA
    answer.class = CLASS_IN
    answer.ttl = ttl
    answer.rdlength = 16
    answer.rdata = _encode_aaaa(ipv6)


    if section == SECTION_AN then
        self.response.header.ancount = self.response.header.ancount + 1
        self.response.ansections[self.response.header.ancount] = answer
    else
        self.response.header.arcount = self.response.header.arcount + 1
        self.response.arsections[self.response.header.arcount] = answer
    end

    return nil
end


function _M.create_soa_answer(self, name, ttl, mname, rname, serial, refresh, retry, expire, minimum)
    if not name or #name == 0 then
        return "name nil"
    end

    if not mname or #mname == 0 then
        return "mname nil"
    end

    if not rname or #rname == 0 then
        return "rname nil"
    end

    if not tonumber(serial) then
        return "serial is not number"
    end

    local query = self.request.questions[1]

    local answer = {}
    answer.name = name
    answer.type = TYPE_SOA
    answer.class = CLASS_IN
    answer.ttl = ttl
    answer.rdlength = strlen(_encode_name(mname)) + strlen(_encode_name(rname)) + 5 * 4
    answer.rdata = _encode_soa(_encode_name(mname), _encode_name(rname), serial, refresh , retry, expire, minimum)

    if query.qtype == TYPE_SOA and query.qname == name then
        self.response.header.ancount = self.response.header.ancount + 1
        self.response.ansections[self.response.header.ancount] = answer
    else
        self.response.header.nscount = self.response.header.nscount + 1
        self.response.nssections[self.response.header.nscount] = answer
    end

    return nil
end


function _M.create_mx_answer(self, name, ttl, preference, exchange)
    if not name or #name == 0 then
        return "name nil"
    end

    if not exchange == nil or #exchange == 0 then
        return "exchange nil"
    end

    local answer = {}
    answer.name = name
    answer.type = TYPE_MX
    answer.class = CLASS_IN
    answer.ttl = ttl
    answer.rdlength = strlen(_encode_name(exchange)) + 2
    answer.rdata = _encode_mx(preference, _encode_name(exchange))

    self.response.header.ancount = self.response.header.ancount + 1
    self.response.ansections[self.response.header.ancount] = answer

    return nil
end


function _M.create_srv_answer(self, name, ttl, priority, weight, port, target)
    if not name or #name == 0 then
        return "name nil"
    end

    if not target or #target == 0 then
        return "target nil"
    end

    if not tonumber(port) or tonumber(port) > 65536 or tonumber(port) < 0 then
        return "port error"
    end

    local answer = {}

    answer.name = name
    answer.type = TYPE_SRV
    answer.class = CLASS_IN
    answer.ttl = ttl
    answer.rdlength = 3 * 2 + strlen(_encode_name(target))
    answer.rdata = _encode_srv(priority, weight, port, _encode_name(target))

    self.response.header.ancount = self.response.header.ancount + 1
    self.response.ansections[self.response.header.ancount] = answer

    return nil
end

return _M
