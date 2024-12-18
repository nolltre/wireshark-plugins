--[[ 
Dissector for the HTSP protocol

HTSMSG Binary format
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

-- Visible in Help -> About Wireshark -> Plugins tab
local info = {
	version = "0.0.2",
	description = "Dissector for the Home Tv Streaming Protocol",
	author = "Daniel Karmark",
	repository = "https://github.com/nolltre/wireshark-plugins",
}

set_plugin_info(info)

local proto_htsp = Proto("HTSP", "Home Tv Streaming Protocol")

-- Preferences
-- Enum preference
local DISPLAY_DEC = 1
local DISPLAY_OCT = 2
local DISPLAY_HEX = 3

local BASE_FORMAT = {
	[1] = "%d",
	[2] = "o%o",
	[3] = "0x%x",
}

local output_tab = {
	{ 1, "Decimal", DISPLAY_DEC },
	{ 2, "Octal", DISPLAY_OCT },
	{ 3, "Hex", DISPLAY_HEX },
}
proto_htsp.prefs.base = Pref.enum(
	"Output base", -- label
	DISPLAY_DEC, -- default value
	"Display the calculated date in this number base", -- description
	output_tab, -- enum table
	true -- show as radio buttons
)
--

local get_tcp_stream = Field.new("frame.number")

-- Frame len - TCP len = offset in frame for the HTSP message
local get_frame_len = Field.new("frame.len")
local get_tcp_len = Field.new("tcp.len")

-- declare the functions used later (like C forward declarations)
local dissect_htsp, checkHtspLength, dissect_body, dissect_s64, proto_htsp_fields

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

-- (from https://github.com/wireshark/wireshark/blob/master/test/lua/dissectFPM.lua)
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
-- Root
local proto_htsp_fields = {
	msg_len = ProtoField.uint32(
		"htsp.length",
		"Length",
		base.DEC,
		nil,
		nil,
		"Total length of message (not including this length field itself)"
	),
	body = ProtoField.bytes("htsp.body", "Body", base.SPACE, "Fields in the root body"),
}

-- HTSMSG field
-- FIXME: Remove what we don't use
local htsmsg_fields = {
	htsmsg = ProtoField.bytes("htsp.htsmsg", "HTSMSG", base.SPACE, "HTSMSG"),
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
	name = ProtoField.string("htsmsg.name", "name", base.UNICODE, "Field name, length as specified by Namelength"),
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

dissect_s64 = function(s64_buf)
	if s64_buf == nil then
		return Int64(0)
	end

	local s64_len = s64_buf:len()
	if s64_len == 8 then
		return s64_buf:int64()
	end

	-- A S64 may be shorter than 8 bytes, create a new byte array with a 0 at the start to not get negative values
	local new_s64 = ByteArray.new(string.rep("\0", 8 - s64_len), true)
	new_s64:append(s64_buf:bytes())
	return new_s64:int64()
end

-- All strings are UTF-8 encoded
dissect_str = function(str_buf)
	if str_buf then
		return str_buf:string(ENC_UTF_8)
	else
		return ":daksdsa"
	end
end

-- A map or a list is handled like the root body, except that there's no total message length
dissect_map_or_list = function(field_type, buf, tree)
	local sub_tree
	if buf then
		sub_tree = tree:add(proto_htsp_fields.type, buf, field_type)
	else
		sub_tree = tree:add(proto_htsp_fields.type, field_type)
	end
	local str_datatype = msgtype_valstr[field_type]
	sub_tree:set_text(str_datatype)
	dissect_body(sub_tree, buf)
	return sub_tree
end

dissect_list = function(list_buf, tree)
	-- TODO: A list is not allowed to have items with names, add expert info for the event that there's a name attached
	return nil, dissect_map_or_list(htsp_field_types.List, list_buf, tree)
end

dissect_map = function(map_buf, tree)
	return nil, dissect_map_or_list(htsp_field_types.Map, map_buf, tree)
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
-- The length of this message size is 4 bytes (32 bits)
local HTSMSG_LEN = 4
-- The HTSMG header size is 6 bytes
local HTSMSG_HDR_LEN = 6

function proto_htsp.dissector(tvbuf, pktinfo, root)
	-- length of the packet buffer
	local pktlen = tvbuf:len()

	local bytes_consumed = 0

	-- Create one subtree that we use to put all the dissected HTSMSG fields under
	local tree = root:add(proto_htsp, tvbuf)

	tree:set_text(proto_htsp.description)

	-- Add the number of HTSMSGs processed
	local tree_num_htmsgs = tree:add("#HTSMSG", tvbuf):set_generated(true)
	-- Keep track of the message number
	local htsmsg_num = 0

	-- Do this in a while loop since multiple HTSP messages can appear in the same TCP segment
	-- Note that the length is set before any return statement. This is because
	-- the function may break out before all data is read from multiple segments
	while bytes_consumed < pktlen do
		local result = dissect_htsp(tvbuf, pktinfo, tree, bytes_consumed, htsmsg_num + 1)
		if result > 0 then -- Success
			bytes_consumed = bytes_consumed + result

			if result > HTSMSG_LEN then
				htsmsg_num = htsmsg_num + 1
			end
			tree_num_htmsgs:set_text("Number of HTSMSGs: " .. htsmsg_num)
			-- Makes the top item select the entire buffer
			tree:set_len(bytes_consumed)
		elseif result == 0 then -- Error
			tree:append_text(", Len: " .. bytes_consumed)
			return 0
		else
			-- Need more bytes
			pktinfo.desegment_offset = bytes_consumed

			-- Invert the result
			result = -result

			pktinfo.desegment_len = result

			tree:append_text(", Len: " .. bytes_consumed)
			-- We still want to go ahead processing, return the entire package length
			return pktlen
		end
	end

	tree:append_text(", Len: " .. bytes_consumed)
	-- Return what we've handled
	return bytes_consumed
end

-- Handle dissection of one HTSP message
dissect_htsp = function(tvbuf, pktinfo, root, offset, htsmsg_num)
	local length_val, length_tvbr = checkHtspLength(tvbuf, offset)

	if length_val <= 0 then
		return length_val
	end

	-- set the protocol column to show our protocol name
	pktinfo.cols.protocol:set(proto_htsp.name)

	-- set the INFO column too, but only if we haven't already set it before
	-- for this frame/packet, because this function can be called multiple
	-- times per packet/Tvb
	if string.find(tostring(pktinfo.cols.info), "^" .. proto_htsp.description) == nil then
		pktinfo.cols.info:set(proto_htsp.description)
	end

	-- The user's preferred output format for numbers
	local number_base_format = BASE_FORMAT[proto_htsp.prefs.base]

	-- Add the protocol to the dissection tree, as a tab, only if the length is greater than the # of length bytes
	if length_val > HTSMSG_LEN then
		local htsp_total_buf = tvbuf:range(offset, length_val)
		local htsp_buf = ByteArray.tvb(htsp_total_buf:bytes(), "HTSMSG #" .. htsmsg_num)

		local tree = root:add(proto_htsp_fields.htsmsg, htsp_total_buf)
			:set_text("HTSMSG #" .. htsmsg_num .. ", Len: " .. string.format(number_base_format, length_val))

		-- Calculate the offset for this message in the frame. Get the entire frame length and subtract the TCP length.
		-- What we are left with is the payload offset in the TCP packet
		local frame_len = get_frame_len().value
		local tcp_len = get_tcp_len().value
		local tcp_payload_offset = frame_len - tcp_len
		tcp_payload_offset = offset + tcp_payload_offset

		-- Add the length of this HTSP message to the subtree
		tree:add(proto_htsp_fields.msg_len, htsp_buf:range(0, length_tvbr:len()), length_val)

		-- Add the body if we have it
		local body_tvbr = htsp_buf:len() and htsp_buf:range(HTSMSG_LEN) or nil
		local body = tree:add(proto_htsp_fields.body, body_tvbr)
			:set_text("Root body, Len: " .. string.format(number_base_format, body_tvbr:len()))
		dissect_body(body, body_tvbr)
	end
	return length_val
end

checkHtspLength = function(tvbuf, offset)
	-- What's left of the buffer?
	local msglen = tvbuf:len() - offset

	if msglen < HTSMSG_LEN then
		-- Not enough bytes to read the length, request another segment
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	-- Check if capture was only capturing a partial packet
	if msglen ~= tvbuf:reported_length_remaining(offset) then
		-- Packets are sliced/cut-off, don't desegment/reassemble
		return 0
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
	-- Handle nil value
	if not tvbuf then
		return 0
	end
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

		local str_datatype = msgtype_valstr[datatype_val]
		local field_type = data_types[str_datatype]

		offset = offset + HTSMSG_HDR_LEN

		-- Set name if available in the buffer
		local name
		if name_length > 0 then
			local name_tvbr = tvbuf:range(offset, name_length)
			name = name_tvbr:string()
		end

		offset = offset + name_length

		if field_type ~= nil then
			local subdissector = dissect_types[str_datatype]
			local data_item

			-- Need to understand if we have any data or if we set default values
			local data_buf = (data_length > 0) and tvbuf:range(offset, data_length) or nil
			local sub_tree
			if subdissector ~= nil then
				-- Some dissectors create a sub_tree that we can add to the tree
				local data_value
				data_value, sub_tree = subdissector(data_buf, tree)
				if sub_tree then
					data_item = sub_tree
				elseif data_value and data_buf then
					data_item = tree:add(field_type, data_buf, data_value)
				elseif data_value then
					data_item = tree:add(field_type, data_value)
				else
					data_item = tree:add(field_type, data_buf)
				end
			else
				data_item = tree:add(field_type, data_buf)
			end

			-- Split on the first colon, replace with the name of this item if applicable
			-- TODO: Is this the best way doing this?
			local string_val = data_item.text:match("[^:]+: (.*)") or ""

			-- Add name?
			if name then
				string_val = (string_val:len() > 0) and ": " .. string_val or string_val
				data_item:set_text(name .. string_val)
			elseif not sub_tree then
				data_item:set_text(string_val)
			end

			offset = offset + data_length
		else
			-- FIXME: Add to the expert info
			-- This is for an unknown data type. Mark as error
			print(
				tostring(get_tcp_stream())
					.. ": "
					.. (msgtype_valstr[datatype_val] or "Unknown")
					.. " data_length "
					.. data_length
					.. " offset "
					.. offset
			)
		end

		-- We add the length of both name and data + the header length
		bytes_consumed = offset
	end
end

-- If you want to debug, make sure that the package path and package cpath are set correctly
-- print("Package path: " .. package.path .. " Package cpath: " .. package.cpath)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:set(9982, proto_htsp)
