local md5 = require 'md5' -- https://github.com/kikito/md5.lua

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
    [0xFAFA] = true,
}
-- source: https://tools.ietf.org/html/draft-ietf-tls-grease-02
TYPE_CLIENT = 1

function remove_grease( list )
    local clean_list = {}
    for i, entry in ipairs( list ) do
        if GREASE_VALUES[entry.value] == nil then
            table.insert( clean_list, entry.value )
        end
    end
    return clean_list
end

-- wireshark v3 changes ssl to tls
if pcall( function() Field.new( 'tls.handshake.type' ) end ) then
    f_handshake_type  = Field.new( 'tls.handshake.type' )
    f_ssl_version     = Field.new( 'tls.handshake.version' )
    f_ciphers         = Field.new( 'tls.handshake.ciphersuite' )
    f_extensions      = Field.new( 'tls.handshake.extension.type' )
    f_ec              = Field.new( 'tls.handshake.extensions_supported_group' )
    f_ec_point_format = Field.new( 'tls.handshake.extensions_ec_point_format' )
else
    f_handshake_type  = Field.new( 'ssl.handshake.type' )
    f_ssl_version     = Field.new( 'ssl.handshake.version' )
    f_ciphers         = Field.new( 'ssl.handshake.ciphersuite' )
    f_extensions      = Field.new( 'ssl.handshake.extension.type' )
    f_ec              = Field.new( 'ssl.handshake.extensions_supported_group' )
    f_ec_point_format = Field.new( 'ssl.handshake.extensions_ec_point_format' )
end

field_full = ProtoField.string( 'ja3.full', 'full' )
field_hash = ProtoField.string( 'ja3.hash', 'hash' )
proto_ja3 = Proto( 'ja3', 'ja3 TLS/SSL fingerprint' )
proto_ja3.fields = { field_full, field_hash }

local orig_ssl_dissector
function proto_ja3.dissector( buffer, pkt_info, tree )
    orig_ssl_dissector:call( buffer, pkt_info, tree )
    local handshake_type = f_handshake_type()
    if not handshake_type or handshake_type.value ~= TYPE_CLIENT then
        return
    end

    local version = f_ssl_version()
    local cipher_list = { f_ciphers() }
    local extension_list = { f_extensions() }
    local ec_curve_list = { f_ec() }
    local ec_curve_point_list = { f_ec_point_format() }

    if version then
        clean_cipher_list = remove_grease( cipher_list )
        clean_extension_list = remove_grease( extension_list )
        clean_ec_curve_list = remove_grease( ec_curve_list )
        clean_ec_curve_point_list = remove_grease( ec_curve_point_list )

        local ciphers_string = table.concat( clean_cipher_list, '-' )
        local extensions_string = table.concat( clean_extension_list, '-' )
        local curves_string = table.concat( clean_ec_curve_list, '-' )
        local ec_curve_point_format_string = table.concat( clean_ec_curve_point_list, '-' ) or ''

        local ja3_string = table.concat( { version.value, ciphers_string, extensions_string, curves_string, ec_curve_point_format_string }, ',' )
        local ja3_hash = md5.sumhexa( ja3_string )

        local subtree = tree:add( proto_ja3, buffer )
        subtree:add( field_full, buffer(), ja3_string )
        subtree:add( field_hash, buffer(), ja3_hash )
    end
end

tcp_dissector_table = DissectorTable.get( 'tcp.port' )
orig_ssl_dissector = tcp_dissector_table:get_dissector( 443 )
tcp_dissector_table:add( 443, proto_ja3 )
