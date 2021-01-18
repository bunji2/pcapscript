# Examples

## Ethernet

eth.js displays timestamp, SrcMac, and DstMac of each ethernet frame.

```javascript
// eth.js
function Eth(n, ts, eth) {
    console.log(ts.String());
    console.log("#"+n, hwaddr(eth.SrcMAC), "->", hwaddr(eth.DstMAC));
}
```

```
C:\work> pcapscript.exe eth.js sample/http.pcap
2004-05-13 19:17:07.311224 +0900 JST
#0 00:00:01:00:00:00 -> fe:ff:20:00:01:00
2004-05-13 19:17:08.222534 +0900 JST
#1 fe:ff:20:00:01:00 -> 00:00:01:00:00:00
2004-05-13 19:17:08.222534 +0900 JST
#2 00:00:01:00:00:00 -> fe:ff:20:00:01:00
2004-05-13 19:17:08.222534 +0900 JST
#3 00:00:01:00:00:00 -> fe:ff:20:00:01:00
2004-05-13 19:17:08.78334 +0900 JST
#4 fe:ff:20:00:01:00 -> 00:00:01:00:00:00
2004-05-13 19:17:08.993643 +0900 JST
#5 fe:ff:20:00:01:00 -> 00:00:01:00:00:00
2004-05-13 19:17:09.12383 +0900 JST
#6 00:00:01:00:00:00 -> fe:ff:20:00:01:00
2004-05-13 19:17:09.12383 +0900 JST
#7 fe:ff:20:00:01:00 -> 00:00:01:00:00:00
2004-05-13 19:17:09.324118 +0900 JST
#8 00:00:01:00:00:00 -> fe:ff:20:00:01:00
2004-05-13 19:17:09.754737 +0900 JST
#9 fe:ff:20:00:01:00 -> 00:00:01:00:00:00
2004-05-13 19:17:09.864896 +0900 JST
...
```

## IP1

ip1.js displays SrcIP and DstIP of each IPv4 packet.
 
```javascript
// ip1.js
function IP(n, ts, ip, eth) {
    console.log("#"+n, ipaddr(ip.SrcIP), "->", ipaddr(ip.DstIP));
}
```

```
C:\work> pcapscript.exe ip1.js sample/http.pcap
#0 145.254.160.237 -> 65.208.228.223
#1 65.208.228.223 -> 145.254.160.237
#2 145.254.160.237 -> 65.208.228.223
#3 145.254.160.237 -> 65.208.228.223
#4 65.208.228.223 -> 145.254.160.237
#5 65.208.228.223 -> 145.254.160.237
#6 145.254.160.237 -> 65.208.228.223
#7 65.208.228.223 -> 145.254.160.237
#8 145.254.160.237 -> 65.208.228.223
#9 65.208.228.223 -> 145.254.160.237
...
```

## IP2

ip2.js counts up SrcIP of each IPv4 packet.
 
```javascript
// ip2.js

var ipaddrs = {};
function add(ipaddr) {
    if (ipaddrs[ipaddr] == undefined) {
            ipaddrs[ipaddr] = 0;
    }
    ipaddrs[ipaddr] = ipaddrs[ipaddr] + 1;
}

function END (count) {
    for (var ipaddr in ipaddrs) {
        console.log(ipaddr, "=", ipaddrs[ipaddr]);
    }
}

function IP (n, ts, ip, eth) {
    add(ipaddr(ip.SrcIP));
}
```

```
C:\work> pcapscript.exe ip2.js sample/http.pcap
145.254.160.237 = 20
65.208.228.223 = 18
145.253.2.203 = 1
216.239.59.99 = 4
```

## TCP1

tcp1.js displays SrcIP+SrcPort and DstIP+DstPort of each TCP segment.
 
```javascript
// tcp1.js
function TCP(n, ts, tcp, ip, eth) {
    console.log(
        "#"+n, 
        ipaddr(ip.SrcIP) +":"+ tcp.SrcPort, 
        "->", 
        ipaddr(ip.DstIP) + ":" + tcp.DstPort);
}
```

```
C:\work> pcapscript.exe tcp1.js sample/http.pcap
#0 145.254.160.237:3372 -> 65.208.228.223:80
#1 65.208.228.223:80 -> 145.254.160.237:3372
#2 145.254.160.237:3372 -> 65.208.228.223:80
#3 145.254.160.237:3372 -> 65.208.228.223:80
#4 65.208.228.223:80 -> 145.254.160.237:3372
#5 65.208.228.223:80 -> 145.254.160.237:3372
#6 145.254.160.237:3372 -> 65.208.228.223:80
#7 65.208.228.223:80 -> 145.254.160.237:3372
#8 145.254.160.237:3372 -> 65.208.228.223:80
#9 65.208.228.223:80 -> 145.254.160.237:3372
...
```

## TCP2

tcp2.js displays SrcIP+SrcPort, DstIP+DstPort, and TCP flags of each TCP segment.
 
```javascript
// tcp2.js

function TCP(n, ts, tcp, ip, eth) {
    var flags = [];
    if (tcp.SYN) {
	    flags.push("SYN");
    }
    if (tcp.ACK) {
	    flags.push("ACK");
    }
    if (tcp.PSH) {
	    flags.push("PSH");
    }
    if (tcp.FIN) {
	    flags.push("FIN");
    }

    console.log(
        "#"+n, 
        ipaddr(ip.SrcIP) +":"+ tcp.SrcPort, 
        "->", 
        ipaddr(ip.DstIP) + ":" + tcp.DstPort, 
        flags.join(","));
}
```

```
C:\work> pcapscript.exe tcp2.js sample/http.pcap
#0 145.254.160.237:3372 -> 65.208.228.223:80 SYN
#1 65.208.228.223:80 -> 145.254.160.237:3372 SYN,ACK
#2 145.254.160.237:3372 -> 65.208.228.223:80 ACK
#3 145.254.160.237:3372 -> 65.208.228.223:80 ACK,PSH
#4 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#5 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#6 145.254.160.237:3372 -> 65.208.228.223:80 ACK
#7 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#8 145.254.160.237:3372 -> 65.208.228.223:80 ACK
#9 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#10 65.208.228.223:80 -> 145.254.160.237:3372 ACK,PSH
#11 145.254.160.237:3372 -> 65.208.228.223:80 ACK
...
```

## TCP3

tcp3.js displays SrcIP+SrcPort, DstIP+DstPort, TCP flags, and payload of each TCP segment.
 
```javascript
// tcp3.js

function TCP(n, ts, tcp, ip, eth) {
    var flags = [];
    if (tcp.SYN) {
	    flags.push("SYN");
    }
    if (tcp.ACK) {
	    flags.push("ACK");
    }
    if (tcp.PSH) {
	    flags.push("PSH");
    }
    if (tcp.FIN) {
	    flags.push("FIN");
    }

    console.log(
        "#"+n, 
        ipaddr(ip.SrcIP) +":"+ tcp.SrcPort, 
        "->", 
        ipaddr(ip.DstIP) + ":" + tcp.DstPort, 
        flags.join(","));
    
    if (tcp.Payload.length>0) {
        console.log(hex(tcp.Payload))
    }
}
```

```
C:\work> pcapscript.exe tcp3.js sample/http.pcap
#0 145.254.160.237:3372 -> 65.208.228.223:80 SYN
#1 65.208.228.223:80 -> 145.254.160.237:3372 SYN,ACK
#2 145.254.160.237:3372 -> 65.208.228.223:80 ACK
#3 145.254.160.237:3372 -> 65.208.228.223:80 ACK,PSH
00000000  47 45 54 20 2f 64 6f 77  6e 6c 6f 61 64 2e 68 74  |GET /download.ht|
00000010  6d 6c 20 48 54 54 50 2f  31 2e 31 0d 0a 48 6f 73  |ml HTTP/1.1..Hos|
00000020  74 3a 20 77 77 77 2e 65  74 68 65 72 65 61 6c 2e  |t: www.ethereal.|
00000030  63 6f 6d 0d 0a 55 73 65  72 2d 41 67 65 6e 74 3a  |com..User-Agent:|
00000040  20 4d 6f 7a 69 6c 6c 61  2f 35 2e 30 20 28 57 69  | Mozilla/5.0 (Wi|
00000050  6e 64 6f 77 73 3b 20 55  3b 20 57 69 6e 64 6f 77  |ndows; U; Window|
00000060  73 20 4e 54 20 35 2e 31  3b 20 65 6e 2d 55 53 3b  |s NT 5.1; en-US;|
00000070  20 72 76 3a 31 2e 36 29  20 47 65 63 6b 6f 2f 32  | rv:1.6) Gecko/2|
00000080  30 30 34 30 31 31 33 0d  0a 41 63 63 65 70 74 3a  |0040113..Accept:|
00000090  20 74 65 78 74 2f 78 6d  6c 2c 61 70 70 6c 69 63  | text/xml,applic|
000000a0  61 74 69 6f 6e 2f 78 6d  6c 2c 61 70 70 6c 69 63  |ation/xml,applic|
000000b0  61 74 69 6f 6e 2f 78 68  74 6d 6c 2b 78 6d 6c 2c  |ation/xhtml+xml,|
000000c0  74 65 78 74 2f 68 74 6d  6c 3b 71 3d 30 2e 39 2c  |text/html;q=0.9,|
000000d0  74 65 78 74 2f 70 6c 61  69 6e 3b 71 3d 30 2e 38  |text/plain;q=0.8|
000000e0  2c 69 6d 61 67 65 2f 70  6e 67 2c 69 6d 61 67 65  |,image/png,image|
000000f0  2f 6a 70 65 67 2c 69 6d  61 67 65 2f 67 69 66 3b  |/jpeg,image/gif;|
00000100  71 3d 30 2e 32 2c 2a 2f  2a 3b 71 3d 30 2e 31 0d  |q=0.2,*/*;q=0.1.|
00000110  0a 41 63 63 65 70 74 2d  4c 61 6e 67 75 61 67 65  |.Accept-Language|
00000120  3a 20 65 6e 2d 75 73 2c  65 6e 3b 71 3d 30 2e 35  |: en-us,en;q=0.5|
00000130  0d 0a 41 63 63 65 70 74  2d 45 6e 63 6f 64 69 6e  |..Accept-Encodin|
00000140  67 3a 20 67 7a 69 70 2c  64 65 66 6c 61 74 65 0d  |g: gzip,deflate.|
00000150  0a 41 63 63 65 70 74 2d  43 68 61 72 73 65 74 3a  |.Accept-Charset:|
00000160  20 49 53 4f 2d 38 38 35  39 2d 31 2c 75 74 66 2d  | ISO-8859-1,utf-|
00000170  38 3b 71 3d 30 2e 37 2c  2a 3b 71 3d 30 2e 37 0d  |8;q=0.7,*;q=0.7.|
00000180  0a 4b 65 65 70 2d 41 6c  69 76 65 3a 20 33 30 30  |.Keep-Alive: 300|
00000190  0d 0a 43 6f 6e 6e 65 63  74 69 6f 6e 3a 20 6b 65  |..Connection: ke|
000001a0  65 70 2d 61 6c 69 76 65  0d 0a 52 65 66 65 72 65  |ep-alive..Refere|
000001b0  72 3a 20 68 74 74 70 3a  2f 2f 77 77 77 2e 65 74  |r: http://www.et|
000001c0  68 65 72 65 61 6c 2e 63  6f 6d 2f 64 65 76 65 6c  |hereal.com/devel|
000001d0  6f 70 6d 65 6e 74 2e 68  74 6d 6c 0d 0a 0d 0a     |opment.html....|

#4 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#5 65.208.228.223:80 -> 145.254.160.237:3372 ACK
...
```

## TCP4

tcp4.js displays SrcIP+SrcPort, DstIP+DstPort, and TCP flags of each TCP segment and saves each payload.
 
```javascript
// tcp4.js

function TCP(n, ts, tcp, ip, eth) {
    var flags = [];
    if (tcp.SYN) {
	    flags.push("SYN");
    }
    if (tcp.ACK) {
	    flags.push("ACK");
    }
    if (tcp.PSH) {
	    flags.push("PSH");
    }
    if (tcp.FIN) {
	    flags.push("FIN");
    }

    console.log(
        "#"+n, 
        ipaddr(ip.SrcIP) +":"+ tcp.SrcPort, 
        "->", 
        ipaddr(ip.DstIP) + ":" + tcp.DstPort, 
        flags.join(","));
    
    if (tcp.Payload.length>0) {
        save(n+".dat", tcp.Payload);
    }
}
```

```
C:\work> mkdir out
C:\work> pcapscript.exe tcp4.js sample/http.pcap out
#0 145.254.160.237:3372 -> 65.208.228.223:80 SYN
#1 65.208.228.223:80 -> 145.254.160.237:3372 SYN,ACK
#2 145.254.160.237:3372 -> 65.208.228.223:80 ACK
#3 145.254.160.237:3372 -> 65.208.228.223:80 ACK,PSH
#4 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#5 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#6 145.254.160.237:3372 -> 65.208.228.223:80 ACK
#7 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#8 145.254.160.237:3372 -> 65.208.228.223:80 ACK
#9 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#10 65.208.228.223:80 -> 145.254.160.237:3372 ACK,PSH
...

C:\work> ls out
10.dat  15.dat  19.dat  22.dat  26.dat  3.dat   31.dat  35.dat  5.dat  9.dat
13.dat  17.dat  20.dat  25.dat  28.dat  30.dat  33.dat  37.dat  7.dat

C:\work>cat out/3.dat
GET /download.html HTTP/1.1
Host: www.ethereal.com
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Connection: keep-alive
Referer: http://www.ethereal.com/development.html
...
```

## TCP+UDP+ICMP+ARP

dump.js displays each packet fully and saves each payload.

```javascript
// dump.js

function BEGIN (version, scriptFile, pcapFile) {
    console.log("[BEGIN]");
    console.log("\tversion:", version);
    console.log("\tscriptFile:", scriptFile);
    console.log("\tpcapFile:", pcapFile);
}

function END(count) {
    console.log("[END]", count, "packets processed");
}

function UDP(n, ts, udp, ip, eth) {
    console.log("#"+n, "[UDP]", ipaddr(ip.SrcIP)+":"+udp.SrcPort, "->", 
        ipaddr(ip.DstIP) + ":" + udp.DstPort);
    if (udp.Payload.length>0) {
        console.log(hex(udp.Payload));
        save(n + ".udp.dat", udp.Payload)
    }
}

function TCP(n, ts, tcp, ip, eth) {
    console.log("#"+n, "[TCP]", ipaddr(ip.SrcIP) +":"+ tcp.SrcPort, "->", 
        ipaddr(ip.DstIP) + ":" + tcp.DstPort);
    console.log("\tSeq:", tcp.Seq, "Ack:", tcp.Ack);
    var flags = [];
    if (tcp.SYN) {
	    flags.push("SYN");
    }
    if (tcp.ACK) {
	    flags.push("ACK");
    }
    if (tcp.PSH) {
	    flags.push("PSH");
    }
    if (tcp.FIN) {
	    flags.push("FIN");
    }
    console.log("\tFlags:", flags.join(","));
    if (tcp.Payload.length>0) {
        console.log(hex(tcp.Payload));
        save(n + ".tcp.dat", tcp.Payload)
    }
}

function ICMP(n, ts, icmp, ip, eth) {
    console.log("#"+n, "[ICMPv4]", ipaddr(ip.SrcIP), "->", ipaddr(ip.DstIP));
	console.log("TypeCode:", icmp.TypeCode);
	if (icmp.Payload.length > 0) {
		console.log(hex(icmp.Payload));
        save(n + ".icmp.dat", icmp.Payload)
	}
}

function ARP(n, ts, arp, eth) {
    console.log("#"+n, "[ARP] AddrType:", arp.AddrType, "Protocol:", arp.Protocol);
	console.log("\tOperation:", arp.Operation);
	console.log("\tSrcHWAddr:", hwaddr(arp.SourceHwAddress));
	console.log("\tSrcProtAddr:", ipaddr(arp.SourceProtAddress));
	console.log("\tDstHWAddr:", hwaddr(arp.DstHwAddress));
	console.log("\tDstProtAddr:", ipaddr(arp.DstProtAddress));
}
```

```
C:\work> mkdir out2
C:\work> pcapscript.exe dump.js sample/http.pcap out2
[BEGIN]
	version: PCAPScript/0.2; WinPcap version 4.1.3 (packet.dll version 10, 2, 0, 5002), based on libpcap version 1.0 branch 1_0_rel0b (20091008)
	scriptFile: example6.js
	pcapFile: sample/http.pcap
#0 [TCP] 145.254.160.237:3372 -> 65.208.228.223:80
	Seq: 951057939 Ack: 0
	Flags: SYN
#1 [TCP] 65.208.228.223:80 -> 145.254.160.237:3372
	Seq: 290218379 Ack: 951057940
	Flags: SYN,ACK
#2 [TCP] 145.254.160.237:3372 -> 65.208.228.223:80
	Seq: 951057940 Ack: 290218380
	Flags: ACK
#3 [TCP] 145.254.160.237:3372 -> 65.208.228.223:80
	Seq: 951057940 Ack: 290218380
	Flags: ACK,PSH
00000000  47 45 54 20 2f 64 6f 77  6e 6c 6f 61 64 2e 68 74  |GET /download.ht|
00000010  6d 6c 20 48 54 54 50 2f  31 2e 31 0d 0a 48 6f 73  |ml HTTP/1.1..Hos|
00000020  74 3a 20 77 77 77 2e 65  74 68 65 72 65 61 6c 2e  |t: www.ethereal.|
00000030  63 6f 6d 0d 0a 55 73 65  72 2d 41 67 65 6e 74 3a  |com..User-Agent:|
00000040  20 4d 6f 7a 69 6c 6c 61  2f 35 2e 30 20 28 57 69  | Mozilla/5.0 (Wi|
00000050  6e 64 6f 77 73 3b 20 55  3b 20 57 69 6e 64 6f 77  |ndows; U; Window|
00000060  73 20 4e 54 20 35 2e 31  3b 20 65 6e 2d 55 53 3b  |s NT 5.1; en-US;|
00000070  20 72 76 3a 31 2e 36 29  20 47 65 63 6b 6f 2f 32  | rv:1.6) Gecko/2|
00000080  30 30 34 30 31 31 33 0d  0a 41 63 63 65 70 74 3a  |0040113..Accept:|
00000090  20 74 65 78 74 2f 78 6d  6c 2c 61 70 70 6c 69 63  | text/xml,applic|
000000a0  61 74 69 6f 6e 2f 78 6d  6c 2c 61 70 70 6c 69 63  |ation/xml,applic|
000000b0  61 74 69 6f 6e 2f 78 68  74 6d 6c 2b 78 6d 6c 2c  |ation/xhtml+xml,|
000000c0  74 65 78 74 2f 68 74 6d  6c 3b 71 3d 30 2e 39 2c  |text/html;q=0.9,|
000000d0  74 65 78 74 2f 70 6c 61  69 6e 3b 71 3d 30 2e 38  |text/plain;q=0.8|
000000e0  2c 69 6d 61 67 65 2f 70  6e 67 2c 69 6d 61 67 65  |,image/png,image|
000000f0  2f 6a 70 65 67 2c 69 6d  61 67 65 2f 67 69 66 3b  |/jpeg,image/gif;|
00000100  71 3d 30 2e 32 2c 2a 2f  2a 3b 71 3d 30 2e 31 0d  |q=0.2,*/*;q=0.1.|
00000110  0a 41 63 63 65 70 74 2d  4c 61 6e 67 75 61 67 65  |.Accept-Language|
00000120  3a 20 65 6e 2d 75 73 2c  65 6e 3b 71 3d 30 2e 35  |: en-us,en;q=0.5|
00000130  0d 0a 41 63 63 65 70 74  2d 45 6e 63 6f 64 69 6e  |..Accept-Encodin|
00000140  67 3a 20 67 7a 69 70 2c  64 65 66 6c 61 74 65 0d  |g: gzip,deflate.|
00000150  0a 41 63 63 65 70 74 2d  43 68 61 72 73 65 74 3a  |.Accept-Charset:|
00000160  20 49 53 4f 2d 38 38 35  39 2d 31 2c 75 74 66 2d  | ISO-8859-1,utf-|
00000170  38 3b 71 3d 30 2e 37 2c  2a 3b 71 3d 30 2e 37 0d  |8;q=0.7,*;q=0.7.|
00000180  0a 4b 65 65 70 2d 41 6c  69 76 65 3a 20 33 30 30  |.Keep-Alive: 300|
00000190  0d 0a 43 6f 6e 6e 65 63  74 69 6f 6e 3a 20 6b 65  |..Connection: ke|
000001a0  65 70 2d 61 6c 69 76 65  0d 0a 52 65 66 65 72 65  |ep-alive..Refere|
000001b0  72 3a 20 68 74 74 70 3a  2f 2f 77 77 77 2e 65 74  |r: http://www.et|
000001c0  68 65 72 65 61 6c 2e 63  6f 6d 2f 64 65 76 65 6c  |hereal.com/devel|
000001d0  6f 70 6d 65 6e 74 2e 68  74 6d 6c 0d 0a 0d 0a     |opment.html....|
...
#41 [TCP] 145.254.160.237:3372 -> 65.208.228.223:80
        Seq: 951058419 Ack: 290236745
        Flags: ACK,FIN
#42 [TCP] 65.208.228.223:80 -> 145.254.160.237:3372
        Seq: 290236745 Ack: 951058420
        Flags: ACK
[END] 43 packets processed

C:\work> ls out2
10.tcp.dat  16.udp.dat  22.tcp.dat  3.tcp.dat   35.tcp.dat  9.tcp.dat
12.udp.dat  17.tcp.dat  25.tcp.dat  30.tcp.dat  37.tcp.dat
13.tcp.dat  19.tcp.dat  26.tcp.dat  31.tcp.dat  5.tcp.dat
15.tcp.dat  20.tcp.dat  28.tcp.dat  33.tcp.dat  7.tcp.dat
```
