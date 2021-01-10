// dump.js

function UDP(n, udp, ip, eth) {
    console.log("#"+n, "[UDP]", ipaddr(ip.SrcIP)+":"+udp.SrcPort, "->", 
        ipaddr(ip.DstIP) + ":" + udp.DstPort);
    if (udp.Payload.length>0) {
        console.log(hex(udp.Payload));
    }
}

function TCP(n, tcp, ip, eth) {
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
    }
}

function ICMP(n, icmp, ip, eth) {
    console.log("#"+n, "[ICMPv4]", ipaddr(ip.SrcIP), "->", ipaddr(ip.DstIP));
    console.log("TypeCode:", icmp.TypeCode);
    if (icmp.Payload.length > 0) {
        console.log(hex(icmp.Payload));
    }
}
