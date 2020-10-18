# PCAPScript

## Requirement

+ [Win10pcap](http://www.win10pcap.org/download/)
+ [gopacket](https://github.com/google/gopacket)

## Usage
```
C:\work\pcapscript>pcapscript
Usage: pcapscript file.pcap script.js
```

## Sample
sample.js
```
// sample.js
// 
// packet data:
//   arp --- layers.ARP
//   eth --- layers.Ethernet
//   ip ---- layers.IPv4
//   icmp -- layers.ICMPv4
//   tcp --- layers.TCP
//   udp --- layers.UDP
//   Refernce: https://godoc.org/github.com/google/gopacket/layers
//
// built-in functions:
//   ipaddr(x) --- IP Address
//   hwaddr(x) --- MAC Address
//   save(filename, data) --- saves byte sequence to file
//
// other:
//   count - count of packet

console.log("--------", count, "--------");
console.log("[Ethernet]", hwaddr(eth.SrcMAC), "->", hwaddr(eth.DstMAC));

if (tcp != null) {
    // TCP
    console.log("[TCP]", ipaddr(ip.SrcIP) +":"+ tcp.SrcPort, "->", ipaddr(ip.DstIP) + ":" + tcp.DstPort);
    console.log("\tSeq:", tcp.Seq, "Ack:", tcp.Ack);
    flags = [];
    if (tcp.SYN) {
	    flags.push("SYN");
    }
    if (tcp.ACK) {
	    flags.push("ACK");
    }
    if (tcp.PSH) {
	    flags.push("PSH");
    }
    console.log("\tFlags:", flags.join(","));
    if (tcp.Payload.length>0) {
        console.log(hex(tcp.Payload));
        save("out_"+count+"_tcp.dat", tcp.Payload)
    } else {
        console.log("");
    }

} else if (udp != null) {
    // UDP
    console.log("[UDP]", ipaddr(ip.SrcIP)+":"+udp.SrcPort, "->", ipaddr(ip.DstIP) + ":" + udp.DstPort);
    if (udp.Payload.length>0) {
        console.log(hex(udp.Payload));
        save("out_"+count+"_udp.dat", udp.Payload)
    } else {
        console.log("");
    }

} else if (arp != null) {
    // ARP
    console.log("[ARP] AddrType:", arp.AddrType, "Protocol:", arp.Protocol);
	console.log("\tOperation:", arp.Operation);
	console.log("\tSrcHWAddr:", hwaddr(arp.SourceHwAddress));
	console.log("\tSrcProtAddr:", ipaddr(arp.SourceProtAddress));
	console.log("\tDstHWAddr:", hwaddr(arp.DstHwAddress));
	console.log("\tDstProtAddr:", ipaddr(arp.DstProtAddress));

} else if (icmp != null) {
    // icmp
    console.log("[IPv4]", ipaddr(ip.SrcIP), "->", ipaddr(ip.DstIP));
	console.log("[ICMPv4] TypeCode:", icmp.TypeCode);//.GoString())
	if (icmp.Payload.length > 0) {
		console.log(hex(icmp.Payload));
        save("out_"+count+"_icmp.dat", icmp.Payload)
	} else {
        console.log("");
    }

} else {
    // other
    console.log("unknown")
}
```
