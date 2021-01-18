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
    console.log(ts.String());
    console.log("#"+n, "[UDP]", ipaddr(ip.SrcIP)+":"+udp.SrcPort, "->", 
        ipaddr(ip.DstIP) + ":" + udp.DstPort);
    if (udp.Payload.length>0) {
        console.log(hex(udp.Payload));
        save(n + ".udp.dat", udp.Payload)
    }
}

function TCP(n, ts, tcp, ip, eth) {
    console.log(ts.String());
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
    console.log(ts.String());
    console.log("#"+n, "[ICMPv4]", ipaddr(ip.SrcIP), "->", ipaddr(ip.DstIP));
	console.log("TypeCode:", icmp.TypeCode);
	if (icmp.Payload.length > 0) {
		console.log(hex(icmp.Payload));
        save(n + ".icmp.dat", icmp.Payload)
	}
}

function ARP(n, ts, arp, eth) {
    console.log(ts.String());
    console.log("#"+n, "[ARP] AddrType:", arp.AddrType, "Protocol:", arp.Protocol);
	console.log("\tOperation:", arp.Operation);
	console.log("\tSrcHWAddr:", hwaddr(arp.SourceHwAddress));
	console.log("\tSrcProtAddr:", ipaddr(arp.SourceProtAddress));
	console.log("\tDstHWAddr:", hwaddr(arp.DstHwAddress));
	console.log("\tDstProtAddr:", ipaddr(arp.DstProtAddress));
}
