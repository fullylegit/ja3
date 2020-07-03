# JA3 - Wireshark/tshark plugin

An implementation of the [JA3](https://github.com/salesforce/ja3) TLS client fingerprinting algorithm for wireshark/tshark.

## Installation

1. Copy [ja3.lua](ja3.lua) to the [plugin folder](https://www.wireshark.org/docs/wsug_html/#ChPluginFolders)
1. Download a copy of [md5.lua](https://github.com/kikito/md5.lua/blob/master/md5.lua) and copy it to the plugin folder
   - Alternatively Ubuntu users can install a compatible library by running `apt install lua-md5`

## Usage
In Wireshark, for TLS or SSL packets, this plugin will display additional information.
JA3 information in form of full info and MD5-hash for client handshake packets.
JA3S information will be displayed for server hello packets.
