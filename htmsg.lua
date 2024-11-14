-- HTMSG Binary format
--
-- Name  ID  Description
-- Map   1    Sub message of type map
-- S64   2    Signed 64bit integer
-- Str   3    UTF-8 encoded string
-- Bin   4    Binary blob
-- List  5    Sub message of type list
-- Dbl   6    Double precision floating point
-- Bool  7    Boolean
-- UUID  8    64 bit UUID in binary format

htsp_protocol = Proto("HTSP", "HTSP Protocol")

-- Root body
-- Length    4 byte integer    Total length of message (not including this length field itself)
-- Body      HTSMSG-Field * N  Fields in the root body

-- HTSMSG-Field
-- Type        1 byte integer  Type of field (see field type IDs above)
-- Namelength  1 byte integer  Length of name of field. If a field is part of a list message this must be 0
-- Datalength  4 byte integer  Length of field data
-- Name        N bytes         Field name, length as specified by Namelength
-- Data        N bytes         Field payload, for details see below
local message_length = ProtoField.int32("htsp.length", "length", base.DEC)
TYPES = { "Map", "S64", "Str", "Bin", "List", "Dbl", "Bool", "UUID" }
local htmsgfield_type = ProtoField.int8("htmsg.type", "type", base.DEC, TYPES)
-- { "Map", "S64", "Str", "Bin", "List", "Dbl", "Bool", "UUID" }
local htmsgfield_namelength = ProtoField.int8("htmsg.namelength", "namelength", base.DEC)
local htmsgfield_datalength = ProtoField.int32("htmsg.datalength", "datalength", base.DEC)
local htmsgfield_name = ProtoField.string("htmsg.name", "name", base.UNICODE)
local htmsgfield_data = ProtoField.string("htmsg.data", "data")
local htmsgfield_int64data = ProtoField.uint64("htmsg.int64data", "data")
local htmsgfield_guid = ProtoField.guid("htmsg.guid", "uuid")
local htmsgfield_dbl = ProtoField.double("htmsg.dbl", "dbl")
local htmsgfield_bool = ProtoField.bool("htmsg.bool", "bool")

htsp_protocol.fields = {
        message_length,
        htmsgfield_type,
        htmsgfield_namelength,
        htmsgfield_datalength,
        htmsgfield_name,
        htmsgfield_data,
        htmsgfield_int64data,
        htmsgfield_guid,
        htmsgfield_dbl,
        htmsgfield_bool,
}

function htsp_protocol.dissector(buffer, pinfo, tree)
        if buffer:len() == 0 then
                return
        end

        pinfo.cols.protocol = htsp_protocol.name

        local subtree = tree:add(htsp_protocol, buffer(), "HTSP Protocol Data")

        local htsp_msg_len = buffer(0, 4)
        subtree:add(message_length, htsp_msg_len)

        local missing_data = htsp_msg_len:uint() - buffer:len()
        if missing_data > 0 then
                pinfo.desegment_len = missing_data + 4
                return
        end

        local bytes_remaining = buffer:len() - 4
        local start_byte = 4
        while bytes_remaining > 0 do
                local bytes_read = add_htmsg_field(subtree, buffer(start_byte, len))
                bytes_remaining = bytes_remaining - bytes_read
                start_byte = start_byte + bytes_read
        end
end

function add_htmsg_field(subtree, buffer)
        local msgtype = buffer(0, 1):uint()
        local namelength = buffer(1, 1):uint()
        local datalength = buffer(2, 4):uint()
        local htmsgfield = subtree:add(htsp_protocol, buffer(), "Field (" .. TYPES[msgtype] .. ")")
        htmsgfield:add(htmsgfield_type, buffer(0, 1))
        -- htmsgfield:add(htmsgfield_namelength, buffer(1, 1))
        -- htmsgfield:add(htmsgfield_datalength, buffer(2, 4))

        local offset = 6 -- size of msgtype, namelength and datalength
        -- type + namelength (1 + len) + datalength (4 + len)
        local total_bytes = offset + namelength + datalength
        if namelength > 0 then
                local name = buffer(offset, namelength)
                htmsgfield:add(htmsgfield_name, name)
                htmsgfield:append_text(" - " .. name:string())
        end
        if msgtype == 1 or msgtype == 5 then -- Map or List
                -- This is the same as the root message, so call this function again
                local bytes_remaining = datalength
                local start_byte = offset + namelength
                while bytes_remaining > 0 do
                        local bytes_read = add_htmsg_field(htmsgfield, buffer(start_byte, bytes_remaining))
                        bytes_remaining = bytes_remaining - bytes_read
                        start_byte = start_byte + bytes_read
                end
        elseif msgtype == 2 then -- S64
                if datalength > 0 then
                        htmsgfield:add(htmsgfield_int64data, buffer(offset + namelength, datalength))
                end
        elseif msgtype == 3 then -- Str
                if datalength > 0 then
                        htmsgfield:add(htmsgfield_data, buffer(offset + namelength, datalength))
                end
        elseif msgtype == 6 then -- Dbl
                if datalength > 0 then
                        htmsgfield:add(htmsgfield_dbl, buffer(offset + namelength, datalength))
                end
        elseif msgtype == 7 then -- Bool
                if datalength > 0 then
                        htmsgfield:add(htmsgfield_bool, buffer(offset + namelength, datalength))
                end
        elseif msgtype == 8 then -- UUID
                if datalength > 0 then
                        htmsgfield:add(htmsgfield_guid, buffer(offset + namelength, datalength))
                end
        else
                local hexstring = ""
                for i = 0, datalength - 1 do
                        hexstring = hexstring .. string.format("%02x", buffer(offset + namelength + i, 1):uint())
                end
                htmsgfield:add(htmsgfield_data, hexstring)
        end

        return total_bytes
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9982, htsp_protocol)
