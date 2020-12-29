// tcp1.js
function TCP(n, tcp, ip, eth) {
    console.log(
        "#"+n,
        ipaddr(ip.SrcIP) +":"+ tcp.SrcPort,
        "->",
        ipaddr(ip.DstIP) + ":" + tcp.DstPort);
}
