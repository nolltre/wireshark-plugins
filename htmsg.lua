--[[ 
Dissector for the HTSP protocol
Version 0.0.1
Author Daniel Karmark
Repository https://github.com/nolltre/wireshark-plugins

HTMSG Binary format
https://docs.tvheadend.org/documentation/development/htsp/htsmsg-binary-format

| Name | ID  | Description                     |
| ---- | --- | ------------------------------- |
| Map  | 1   | Sub message of type map         |
| S64  | 2   | Signed 64bit integer            |
| Str  | 3   | UTF-8 encoded string            |
| Bin  | 4   | Binary blob                     |
| List | 5   | Sub message of type list        |
| Dbl  | 6   | Double precision floating point |
| Bool | 7   | Boolean                         |
| UUID | 8   | 64 bit UUID in binary format    |

Root body
Length    4 byte integer    Total length of message (not including this length field itself)
Body      HTSMSG-Field * N  Fields in the root body

HTSMSG-Field
Type        1 byte integer  Type of field (see field type IDs above)
Namelength  1 byte integer  Length of name of field. If a field is part of a list message this must be 0
Datalength  4 byte integer  Length of field data
Name        N bytes         Field name, length as specified by Namelength
Data        N bytes         Field payload, for details see below 

]]
--

local proto_htsp = Proto("HTSP", "htsp protocol")
local get_tcp_stream = Field.new("frame.number")

-- declare the functions used later (like C forward declarations)
local dissect_htsp, checkHtspLength, dissect_body, dissect_s64

local htsp_field_types = {
	Map = 1,
	S64 = 2,
	Str = 3,
	Bin = 4,
	List = 5,
	Dbl = 6,
	Bool = 7,
	UUID = 8,
}

dissect_s64 = function(s64_buf)
	-- print(tostring(get_tcp_stream()) .. ": datatype_buf:len(): " .. ((s64_buf ~= nil) and s64_buf:len() or "nil"))
	if s64_buf == nil then
		return Int64(0)
	end
	-- A S64 may be shorter than 8 bytes, use the high/low Int64 way of creating a proper Int64
	local s64_len = s64_buf:len()
	-- Extract low bytes, if len > 4 start from 4, else start from pos 0
	local low = s64_buf:range((s64_len > 4) and s64_buf(4, s64_len) or 0):uint()
	-- ... and high bytes
	local high = (s64_len > 4) and s64_buf(0, 4):uint() or 0
	return Int64.new(low, high)
end

dissect_str = function(str_buf)
	if str_buf == nil then
		print(tostring(get_tcp_stream()) .. ": str_buf:len(): " .. ((str_buf ~= nil) and str_buf:len() or "nil"))
		return ""
	else
		return str_buf:string()
	end
end

dissect_list = function(list_buf, tree)
	-- Dissect as any other body
	print(tostring(get_tcp_stream()) .. ": list_buf:len(): " .. ((list_buf ~= nil) and list_buf:len() or "nil"))
	dissect_body(tree, list_buf)
end

dissect_map = function(map_buf, tree)
	-- Dissect as any other body
	print(tostring(get_tcp_stream()) .. ": map_buf:len(): " .. ((map_buf ~= nil) and map_buf:len() or "nil"))
	-- return map_buf
	dissect_body(tree, map_buf)
end
--
--- Dissectors based on type value
---
local dissect_types = {
	Map = dissect_map,
	S64 = dissect_s64,
	Str = dissect_str,
	Bin = dissect_bin,
	List = dissect_list,
	Dbl = dissect_dbl,
	Bool = dissect_bool,
	UUID = dissect_uuid,
}
----------------------------------------
-- a function to convert tables of enumerated types to value-string tables
-- i.e., from { "name" = number } to { number = "name" }
local function makeValString(enumTable)
	local t = {}
	for name, num in pairs(enumTable) do
		t[num] = name
	end
	return t
end

local msgtype_valstr = makeValString(htsp_field_types)

-- Header fields
local proto_htsp_fields = {
	msg_len = ProtoField.uint32("htsp.length", "length", base.DEC, nil, nil, "Length of the payload"),
	body = ProtoField.bytes("htsp.body", "body", base.SPACE, "HTMSG body"),
}

-- HTSMSG fields
local htsmsg_fields = {
	type = ProtoField.uint8("htsmsg.type", "Type", base.DEC, msgtype_valstr, nil, "Type of field"),
	namelength = ProtoField.uint8(
		"htsmsg.namelength",
		"Namelength",
		base.DEC,
		nil,
		nil,
		"Length of name of field. If a field is part of a list message this must be 0"
	),
	datalength = ProtoField.uint32("htsmsg.datalength", "Datalength", base.DEC, nil, nil, "Length of field data"),
	name = ProtoField.string("htsmsg.name", "name", "Field name, length as specified by Namelength"),
	data = ProtoField.bytes("htsmsg.data", "data", base.SPACE, "Field payload"),
}

-- Data types
local data_types = {
	S64 = ProtoField.int64("htmsg.s64", "s64", nil, nil, "Signed 64bit integer"),
	Str = ProtoField.string("htmsg.string", "string", base.UNICODE, "UTF-8 encoded string"),
	Bin = ProtoField.bytes("htmsg.bin", "bin", base.SPACE, "Binary blob"),
	Data = ProtoField.bytes("htmsg.data", "data", base.SPACE, "Binary blob"),
	List = ProtoField.bytes("htmsg.list", "list", base.SPACE, "List"),
	Map = ProtoField.bytes("htmsg.map", "map", base.SPACE, "Map"),
	Dbl = ProtoField.double("htmsg.dbl", "dbl", "Double precision floating point"),
	Bool = ProtoField.bool("htmsg.bool", "bool", nil, nil, "Boolean"),
	UUID = ProtoField.guid("htmsg.uuid", "uuid", "64 bit UUID in binary format"),
}

-- Register the fields
-- Concat the other fields onto proto_htsp_fields
for k, v in pairs(htsmsg_fields) do
	proto_htsp_fields[k] = v
end
for k, v in pairs(data_types) do
	proto_htsp_fields[k] = v
end
proto_htsp.fields = proto_htsp_fields

-- The HTSMG header size is 6 bytes
local HTSMSG_LEN = 4
local HTSMSG_HDR_LEN = 6

function proto_htsp.dissector(tvbuf, pktinfo, root)
	-- length of the packet buffer
	local pktlen = tvbuf:len()

	local bytes_consumed = 0

	-- Do this in a while loop since multiple HTSP messages can appear in the same TCP segment
	while bytes_consumed < pktlen do
		local result = dissect_htsp(tvbuf, pktinfo, root, bytes_consumed)
		if result > 0 then -- Success
			bytes_consumed = bytes_consumed + result
		elseif result == 0 then -- Error
			return 0
		else
			-- Need more bytes
			pktinfo.desegment_offset = bytes_consumed

			-- Invert the result
			result = -result

			pktinfo.desegment_len = result

			-- We still want to go ahead processing, return the entire package length
			return pktlen
		end
	end

	-- Return what we've handled
	return bytes_consumed
end

-- Handle dissection of one HTSP message
dissect_htsp = function(tvbuf, pktinfo, root, offset)
	local length_val, length_tvbr = checkHtspLength(tvbuf, offset)

	if length_val <= 0 then
		return length_val
	end

	-- set the protocol column to show our protocol name
	pktinfo.cols.protocol:set("HTSP")

	-- set the INFO column too, but only if we haven't already set it before
	-- for this frame/packet, because this function can be called multiple
	-- times per packet/Tvb
	if string.find(tostring(pktinfo.cols.info), "^HTSP") == nil then
		pktinfo.cols.info:set("HTSP")
	end

	-- Add the protocol to the dissection tree
	local htsp_buf = tvbuf:range(offset, length_val)
	local tree = root:add(proto_htsp, htsp_buf, "HTSP Protocol")
	-- 0x42 comes from the data output in Wireshark
	tree:append_text(
		", Len: "
			.. length_val
			.. ", Offset: "
			.. string.format("0x%x - 0x%x", offset + 0x42, offset + 0x42 + length_val)
	)

	-- Add the length of this HTSP message to the subtree
	tree:add(proto_htsp_fields.msg_len, length_tvbr, length_val)

	-- Add the body
	local body_tvbr = htsp_buf:range(HTSMSG_LEN)
	local body = tree:add(proto_htsp_fields.body, body_tvbr)
	body:prepend_text("Len: " .. body_tvbr:len() .. " : ")
	dissect_body(body, body_tvbr)
	return length_val
end

checkHtspLength = function(tvbuf, offset)
	-- What's left of the buffer?
	local msglen = tvbuf:len() - offset

	if msglen < HTSMSG_LEN then
		-- Not enough bytes to read the length, request another segment
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	-- We have enough bytes to determine the length of the message
	local length_tvbr = tvbuf:range(offset, HTSMSG_LEN)
	local length_val = length_tvbr:uint() + HTSMSG_LEN

	if msglen < length_val then
		return -(length_val - msglen)
	end

	return length_val, length_tvbr
end

dissect_body = function(tree, tvbuf)
	-- Dissect the body
	local tvb_length = tvbuf:len()

	-- Find the dissector for this data type
	local bytes_consumed = 0
	while bytes_consumed < tvb_length do
		local offset = bytes_consumed
		local datatype_buf = tvbuf(offset, 1)
		local datatype_val = datatype_buf:uint()
		local name_length_buf = tvbuf(offset + 1, 1)
		local name_length = name_length_buf:uint()
		local data_length_buf = tvbuf(offset + 2, 4)
		local data_length = data_length_buf:uint()

		-- Add info to the body tree info
		-- local new_item = tree:add(hdr_fields.type, datatype_buf, datatype_val)

		-- Mark the type + name_length + data_length + name + data for this type (for Wireshark UI)
		-- print(
		-- 	tostring(get_tcp_stream())
		-- 		.. ": "
		-- 		.. (msgtype_valstr[datatype_val] or "Unknown")
		-- 		.. " data_length "
		-- 		.. data_length
		-- 		.. " offset "
		-- 		.. offset
		-- )
		local new_item = tree:add(
			proto_htsp_fields.type,
			tvbuf:range(offset, HTSMSG_HDR_LEN + name_length + data_length),
			datatype_val
		)

		offset = offset + HTSMSG_HDR_LEN

		local type_text = new_item.text

		local name, data_string_val
		-- Add name?
		if name_length > 0 then
			local name_tvbr = tvbuf:range(offset, name_length)
			new_item:add(proto_htsp_fields.name, name_tvbr)
			-- new_item:set_text(name_tvbr:string())
			name = name_tvbr:string()
			offset = offset + name_length
		end

		local str_datatype = msgtype_valstr[datatype_val]
		local field_type = data_types[str_datatype]

		--[[
    Add data, 
     TODO: Handle default values if datalength is 0
		 if data_length > 0 and field_type ~= nil then
    ]]
		if field_type ~= nil then
			local subdissector = dissect_types[str_datatype]
			local data_item
			-- print(
			-- 	tostring(get_tcp_stream())
			-- 		.. ": subdissector: "
			-- 		.. tostring(subdissector)
			-- 		.. " msgtype_valstr[datatype_val]: "
			-- 		.. tostring(msgtype_valstr[datatype_val])
			-- )
			-- Need to understand if we have any data or if we set default values
			local data_buf = (data_length > 0) and tvbuf:range(offset, data_length) or nil
			if subdissector ~= nil then
				-- Send the data buffer as nil if the data_length is 0, this avoids errors as we can check for nil
				local data_value = subdissector(data_buf, new_item)
				data_string_val = data_value and tostring(data_value)
				-- Some sub dissectors do not return any data (e.g. for List and Map)
				if data_value and data_buf then
					data_item = new_item:add(field_type, data_buf, data_value)
				elseif data_value then
					data_item = new_item:add(field_type, data_value)
				else
					data_item = new_item:add(field_type, data_buf)
				end
			else
				data_item = new_item:add(field_type, data_buf)
			end

			-- Some sub dissectors do not return any data
			if data_item then
				new_item:append_text(", " .. data_item.text)
			end
			offset = offset + data_length
		else
			print(
				tostring(get_tcp_stream())
					.. ": [DATALENGTH 0!] "
					.. (msgtype_valstr[datatype_val] or "Unknown")
					.. " data_length "
					.. data_length
					.. " offset "
					.. offset
			)
		end

		-- Format type text
		if name then
			-- Split on the first colon, replace with the name of this item if applicable
			-- local string_val = item.text:match("[^:]+: (.*)")
			data_string_val = data_string_val and (": " .. data_string_val) or ""
			new_item:set_text(name .. data_string_val .. " [" .. type_text .. "]")
		end

		-- We add the length of both name and data + the header length
		bytes_consumed = offset
	end
end

-- print("Package path: " .. package.path .. " Package cpath: " .. package.cpath)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:set(9982, proto_htsp)
