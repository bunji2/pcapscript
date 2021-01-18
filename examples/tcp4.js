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
