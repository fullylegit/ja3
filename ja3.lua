local md5 = require "md5" -- https://github.com/kikito/md5.lua

TYPE_CLIENT_HELLO = 1
TYPE_SERVER_HELLO = 2

-- source: https://tools.ietf.org/html/draft-ietf-tls-grease-02
GREASE_VALUES = {
    [0x0A0A] = true,
    [0x1A1A] = true,
    [0x2A2A] = true,
    [0x3A3A] = true,
    [0x4A4A] = true,
    [0x5A5A] = true,
    [0x6A6A] = true,
    [0x7A7A] = true,
    [0x8A8A] = true,
    [0x9A9A] = true,
    [0xAAAA] = true,
    [0xBABA] = true,
    [0xCACA] = true,
    [0xDADA] = true,
    [0xEAEA] = true,
    [0xFAFA] = true
}

function remove_grease(list)
    local clean_list = {}
    for i, entry in ipairs(list) do
        if GREASE_VALUES[entry.value] == nil then
            table.insert(clean_list, entry.value)
        end
    end
    return clean_list
end

-- https://tools.ietf.org/html/draft-ietf-tls-padding-04
function remove_padding(list)
    local clean_list = {}
    for k, v in pairs(list) do
        if v ~= 21 then
            table.insert(clean_list, v)
        end
    end
    return clean_list
end

-- wireshark v3 changes ssl to tls
if
    pcall(
        function()
            Field.new("tls.handshake.type")
        end
    )
 then
    f_handshake_type = Field.new("tls.handshake.type")
    f_ssl_version = Field.new("tls.handshake.version")
    f_ciphers = Field.new("tls.handshake.ciphersuite")
    f_extensions = Field.new("tls.handshake.extension.type")
    f_ec = Field.new("tls.handshake.extensions_supported_group")
    f_ec_point_format = Field.new("tls.handshake.extensions_ec_point_format")
else
    f_handshake_type = Field.new("ssl.handshake.type")
    f_ssl_version = Field.new("ssl.handshake.version")
    f_ciphers = Field.new("ssl.handshake.ciphersuite")
    f_extensions = Field.new("ssl.handshake.extension.type")
    f_ec = Field.new("ssl.handshake.extensions_supported_group")
    f_ec_point_format = Field.new("ssl.handshake.extensions_ec_point_format")
end

field_ja3_full = ProtoField.string("ja3.full", "ja3 full")
field_ja3_hash = ProtoField.string("ja3.hash", "ja3 hash")
field_ja3_hash_ignored_padding = ProtoField.string("ja3.hash_ignored_padding", "ja3 hash_ignored_padding")
field_ja3_full_ignored_padding = ProtoField.string("ja3.full_ignored_padding", "ja3 full_ignored_padding")
field_ja3s_full = ProtoField.string("ja3s.full", "ja3s full")
field_ja3s_hash = ProtoField.string("ja3s.hash", "ja3s hash")
proto_ja3 = Proto("ja3", "ja3/ja3s TLS/SSL fingerprint")
proto_ja3.fields = {
    field_ja3_full,
    field_ja3_hash,
    field_ja3_full_ignored_padding,
    field_ja3_hash_ignored_padding,
    field_ja3s_full,
    field_ja3s_hash
}

function proto_ja3.dissector(buffer, pkt_info, tree)
    local handshake_type = f_handshake_type()
    if not handshake_type or (handshake_type.value ~= TYPE_CLIENT_HELLO and handshake_type.value ~= TYPE_SERVER_HELLO) then
        return
    end

    local version = f_ssl_version()
    local cipher_list = {f_ciphers()}
    local extension_list = {f_extensions()}
    local ec_curve_list = {f_ec()}
    local ec_curve_point_list = {f_ec_point_format()}

    if not version then
        return
    end

    clean_cipher_list = remove_grease(cipher_list)
    clean_extension_list = remove_grease(extension_list)

    if handshake_type.value == TYPE_CLIENT_HELLO then
        clean_ec_curve_list = remove_grease(ec_curve_list)
        clean_ec_curve_point_list = remove_grease(ec_curve_point_list)
    end

    local ciphers_string = table.concat(clean_cipher_list, "-")
    local extensions_string = table.concat(clean_extension_list, "-")

    clean_extension_list_nopadding = remove_padding(clean_extension_list)
    local extensions_string_no_padding = table.concat(clean_extension_list_nopadding, "-")
    local curves_string = table.concat(clean_ec_curve_list, "-")
    local ec_curve_point_format_string = table.concat(clean_ec_curve_point_list, "-") or ""

    local subtree = tree:add(proto_ja3, buffer)
    if handshake_type.value == TYPE_CLIENT_HELLO then
        local ja3_string =
            table.concat(
            {version.value, ciphers_string, extensions_string, curves_string, ec_curve_point_format_string},
            ","
        )
        local ja3_hash = md5.sumhexa(ja3_string)
        local ja3_string_no_padding =
            table.concat(
            {version.value, ciphers_string, extensions_string_no_padding, curves_string, ec_curve_point_format_string},
            ","
        )
        local ja3_hash_no_padding = md5.sumhexa(ja3_string_no_padding)

        subtree:add(field_ja3_full, buffer(), ja3_string)
        subtree:add(field_ja3_hash, buffer(), ja3_hash)
        subtree:add(field_ja3_hash_ignored_padding, buffer(), ja3_hash_no_padding)
        subtree:add(field_ja3_full_ignored_padding, buffer(), ja3_string_no_padding)
    elseif handshake_type.value == TYPE_SERVER_HELLO then
        local ja3s_string = table.concat({version.value, ciphers_string, extensions_string}, ",")
        local ja3s_hash = md5.sumhexa(ja3s_string)

        subtree:add(field_ja3s_full, buffer(), ja3s_string)
        subtree:add(field_ja3s_hash, buffer(), ja3s_hash)
    end
end

register_postdissector(proto_ja3)
