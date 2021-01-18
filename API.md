# PCAPScript API

## Basic functions

|function|description|
|:--|:--|
|BEGIN (version, scriptFile, pcapFile)|"BEGIN" is called firstly|
|TCP (n, ts, tcp, ip, eth)|"TCP" is called when packet is TCP segment|
|UDP (n, ts, udp, ip, eth)|"UDP" is called when packet is UDP segment|
|ICMP (n, ts, icmp, ip, eth)|"ICMP" is called when packet is ICMPv4 packet|
|IP (n, ts, ip, eth)|"IP" is called when packet is IPv4 packet|
|ARP (n, ts, arp, eth)|"ARP" is called when packet is ARP packet|
|Eth (n, ts, eth)|"Eth" is called when packet is Ethernet frame|
|END (count)|"END" is called finally|count: the count of packets|

## Parameters

|parameter|type|description|reference url|
|:--|:--|:--|:--|
|version|string|version of pcapscript.exe|-|
|scriptFile|string|the path of script|-|
|pcapFile|string|the path of PCAP file|-|
|count|int|the count of packets|-|
|n|int|the n-th packet|-|
|ts|object|timestamp of packet|https://godoc.org/time#Time|
|tcp|object|the object of TCP segment|https://godoc.org/github.com/google/gopacket/layers#TCP|
|udp|object|the object of UDP segment|https://godoc.org/github.com/google/gopacket/layers#UDP|
|icmp|object|the object of ICMPv4 packet|https://godoc.org/github.com/google/gopacket/layers#ICMPv4|
|arp|object|the object of ARP packet|https://godoc.org/github.com/google/gopacket/layers#ARP|
|ip|object|the object of IPv4 packet|https://godoc.org/github.com/google/gopacket/layers#IPv4|
|eth|object|the object of Ethernet frame|https://godoc.org/github.com/google/gopacket/layers#Ethernet|

## Built-in functions (Golang)

|function|description|
|:--|:--|
|func ipaddr(bb []byte) string|converts byte sequence to IP Address format|
|func hwaddr (bb []byte) string|converts byte sequence to MAC Address format|
|func str (bb []byte) string|converts byte sequence to string|
|func hex (bb []byte) string|converts byte sequence to hex string|
|func save (filename string, bb []byte)|saves byte sequence to file under outdir|
|func isUTF8(bb [] byte) bool|tests whether bytes are in UTF8 encoding|
|func isASCII(bb []byte) bool|tests whether bytes are ASCII codes|
|func isBASE64(bb []byte) bool|tests whether bytes are in BASE64 encoding|
|func BASE64Encode(bb []byte)string|encodes bytes to string in BASE64|
|func BASE64Decode(s string)[]byte|decodes string in BASE64 to bytes|
|func bytesFromHexStr(s string)[]byte|converts hex string to bytes|
|func HexStr(bb []byte)string|converts bytes to hex string|
|func MD5(bb [\]byte)[]byte|calulates MD5 of bytes|
|func SHA1(bb [\]byte)[]byte|calulates SHA1 of bytes|
|func ROT13(bb [\]byte)[]byte|converts bytes in ROT13|
