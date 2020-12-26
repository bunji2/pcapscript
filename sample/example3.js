// example3.js
function TCP(n, tcp, ip, eth) {
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

    console.log("#"+n, ipaddr(ip.SrcIP) +":"+ tcp.SrcPort, "->", ipaddr(ip.DstIP) + ":" + tcp.DstPort,  flags.join(","));
}
