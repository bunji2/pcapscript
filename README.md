# PCAPScript

This tool handles packets in pcapfile with JavaScript.

## Requirement

+ [Win10pcap](http://www.win10pcap.org/download/)
+ [GoPacket](https://github.com/google/gopacket)

## How to build

```
go get github.com/google/gopacket
go get github.com/bunji2/pcapscript
go build github.com/bunji2/pcapscript
```

## Usage

```
C:\work>pcapscript.exe
Usage: pcapscript.exe script.js file.pcap [outdir]
```

## [Examples](examples/README.md)


Following script displays SrcIP+SrcPort, DstIP+DstPort, TCP flags, and payload of each TCP segment.
 
```javascript
// sample.js

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
        "#"+n, ts.Format("2006/01/02 15:04:05.000"),
        "\n\t",
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
C:\work> pcapscript.exe sample.js sample.pcap
#0 2004/05/13 19:17:07.311 
	 145.254.160.237:3372 -> 65.208.228.223:80 SYN
#1 2004/05/13 19:17:08.222 
	 65.208.228.223:80 -> 145.254.160.237:3372 SYN,ACK
#2 2004/05/13 19:17:08.222 
	 145.254.160.237:3372 -> 65.208.228.223:80 ACK
#3 2004/05/13 19:17:08.222 
	 145.254.160.237:3372 -> 65.208.228.223:80 ACK,PSH
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

#4 2004/05/13 19:17:08.783 
	 65.208.228.223:80 -> 145.254.160.237:3372 ACK
#5 2004/05/13 19:17:08.993 
	 65.208.228.223:80 -> 145.254.160.237:3372 ACK
00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
00000010  0a 44 61 74 65 3a 20 54  68 75 2c 20 31 33 20 4d  |.Date: Thu, 13 M|
00000020  61 79 20 32 30 30 34 20  31 30 3a 31 37 3a 31 32  |ay 2004 10:17:12|
00000030  20 47 4d 54 0d 0a 53 65  72 76 65 72 3a 20 41 70  | GMT..Server: Ap|
00000040  61 63 68 65 0d 0a 4c 61  73 74 2d 4d 6f 64 69 66  |ache..Last-Modif|
00000050  69 65 64 3a 20 54 75 65  2c 20 32 30 20 41 70 72  |ied: Tue, 20 Apr|
00000060  20 32 30 30 34 20 31 33  3a 31 37 3a 30 30 20 47  | 2004 13:17:00 G|
00000070  4d 54 0d 0a 45 54 61 67  3a 20 22 39 61 30 31 61  |MT..ETag: "9a01a|
00000080  2d 34 36 39 36 2d 37 65  33 35 34 62 30 30 22 0d  |-4696-7e354b00".|
00000090  0a 41 63 63 65 70 74 2d  52 61 6e 67 65 73 3a 20  |.Accept-Ranges: |
000000a0  62 79 74 65 73 0d 0a 43  6f 6e 74 65 6e 74 2d 4c  |bytes..Content-L|
000000b0  65 6e 67 74 68 3a 20 31  38 30 37 30 0d 0a 4b 65  |ength: 18070..Ke|
...
```

Other examples are [here](examples/README.md).

----

## Extracting MSC from PCAP

[Extracting MSC from PCAP](msc/README.md)

----

## Reference

[PCAPScript API](API.md)