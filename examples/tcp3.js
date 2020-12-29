// tcp3.js

function TCP(n, tcp, ip, eth) {
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