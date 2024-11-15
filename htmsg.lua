-- Dissector for the HTSP protocol
-- Version 0.0.1
-- Author Daniel Karmark
-- Repository https://github.com/nolltre/wireshark-plugins

-- HTMSG Binary format
-- https://docs.tvheadend.org/documentation/development/htsp/htsmsg-binary-format
--
--| Name | ID  | Description                     |
--| ---- | --- | ------------------------------- |
--| Map  | 1   | Sub message of type map         |
--| S64  | 2   | Signed 64bit integer            |
--| Str  | 3   | UTF-8 encoded string            |
--| Bin  | 4   | Binary blob                     |
--| List | 5   | Sub message of type list        |
--| Dbl  | 6   | Double precision floating point |
--| Bool | 7   | Boolean                         |
--| UUID | 8   | 64 bit UUID in binary format    |

-- Root body
-- Length    4 byte integer    Total length of message (not including this length field itself)
-- Body      HTSMSG-Field * N  Fields in the root body

-- HTSMSG-Field
-- Type        1 byte integer  Type of field (see field type IDs above)
-- Namelength  1 byte integer  Length of name of field. If a field is part of a list message this must be 0
-- Datalength  4 byte integer  Length of field data
-- Name        N bytes         Field name, length as specified by Namelength
-- Data        N bytes         Field payload, for details see below

local htsp_protocol = Proto("HTSP", "htsp protocol")

local htsp_field_types = {
	[1] = "Map",
	[2] = "S64",
	[3] = "Str",
	[4] = "Bin",
	[5] = "List",
	[6] = "Dbl",
	[7] = "Bool",
	[8] = "UUID",
}

-- Fields
local htmsgfield_length = ProtoField.uint32("htsp.length", "length", base.DEC, nil, nil, "Length of the payload")
local htmsgfield_s64 = ProtoField.int64("htmsg.s64", "data", nil, nil, "Signed 64bit integer")
local htmsgfield_str = ProtoField.string("htmsg.string", "string", base.UNICODE, "UTF-8 encoded string")
local htmsgfield_data = ProtoField.bytes("htmsg.data", "data", base.SPACE, "Binary blob")
local htmsgfield_dbl = ProtoField.double("htmsg.dbl", "dbl", "Double precision floating point")
local htmsgfield_bool = ProtoField.bool("htmsg.bool", "bool", nil, nil, "Boolean")
local htmsgfield_guid = ProtoField.guid("htmsg.uuid", "uuid", "64 bit UUID in binary format")

local type_to_field = {
	[2] = htmsgfield_s64,
	[3] = htmsgfield_str,
	[4] = htmsgfield_data,
	[6] = htmsgfield_dbl,
	[7] = htmsgfield_bool,
	[8] = htmsgfield_guid,
}

-- Register the fields
htsp_protocol.fields = {
	htmsgfield_length,
	htmsgfield_data,
	htmsgfield_str,
	htmsgfield_s64,
	htmsgfield_guid,
	htmsgfield_dbl,
	htmsgfield_bool,
}

local add_htmsg_field
add_htmsg_field = function(subtree, buffer)
	local msgtype = buffer(0, 1):uint()
	local namelength = buffer(1, 1):uint()
	local datalength = buffer(2, 4):uint()

	local offset = 6 -- size of msgtype, namelength and datalength
	local total_bytes = offset + namelength + datalength
	local items_added = 0

	if msgtype == 1 or msgtype == 5 then -- Map or List
		-- NOTE: This is handled in the same way as with the root message so the function runs recursively

		-- Add a subtree
		local htmsgfield = subtree:add(htsp_protocol, buffer(), htsp_field_types[msgtype])
		if namelength > 0 then
			local name = buffer(offset, namelength)
			htmsgfield:set_text(name:string())
		end

		-- Call this function again, on the data in the buffer that is associated with this field
		local bytes_remaining = datalength
		local start_offset = offset + namelength
		-- Add a generated value with the type of this field
		local item = htmsgfield:add(htsp_field_types[msgtype])
		item:set_generated(true)
		while bytes_remaining > 0 do
			local bytes_read, fields_added = add_htmsg_field(htmsgfield, buffer(start_offset, bytes_remaining))
			bytes_remaining = bytes_remaining - bytes_read
			start_offset = start_offset + bytes_read
			items_added = items_added + fields_added
		end
		item:append_text(", Items: " .. items_added)
		items_added = items_added + 1
	-- msgtype 2-8 bar 5
	elseif msgtype >= 2 and msgtype <= 8 then
		if datalength > 0 then
			local name = buffer(offset, namelength)
			local value = buffer(offset + namelength, datalength)
			local item = subtree:add(type_to_field[msgtype], value)
			items_added = items_added + 1
			-- Split on the first colon, replace with the name of this item if applicable
			local string_val = item.text:match("[^:]+: (.*)")

			-- NOTE: This is a workaround for when an item is marked as S64, but in
			-- reality is less than that. We assume to NOT have the value signed
			if htsp_field_types[msgtype] == "S64" and datalength ~= 8 then
				string_val = value:uint64()
			end

			-- Concat name if we have it
			if namelength > 0 then
				item:set_text(name:string() .. ": " .. string_val)
			else
				item:set_text(string_val)
			end
		end
	end

	return total_bytes, items_added
end

function htsp_protocol.dissector(buffer, pinfo, tree)
	if buffer:len() == 0 then
		return
	end

	pinfo.cols.protocol = htsp_protocol.name

	local subtree = tree:add(htsp_protocol, buffer(), "HTSP Protocol Data")

	local htsp_msg_len_bytes = 4
	local htsp_msg_len = buffer(0, htsp_msg_len_bytes)
	subtree:add(htmsgfield_length, htsp_msg_len)
	subtree:append_text(", Len: " .. htsp_msg_len:uint())
	local items_added = 1

	-- Take care of reassembling the HTSP data if split over multiple TCP packets
	-- We need to add the 4 bytes that make up the total message length. It is not included.
	local missing_data = (htsp_msg_len_bytes + htsp_msg_len:uint()) - buffer:len()
	if missing_data > 0 then
		pinfo.desegment_len = missing_data
		return
	end

	local bytes_remaining = buffer:len() - htsp_msg_len_bytes
	local offset = htsp_msg_len_bytes
	while bytes_remaining > 0 do
		local bytes_read, fields_added = add_htmsg_field(subtree, buffer(offset))
		bytes_remaining = bytes_remaining - bytes_read
		offset = offset + bytes_read
		items_added = items_added + fields_added
	end

	subtree:append_text(", Items: " .. items_added)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9982, htsp_protocol)
