// payload.js

function ICMP(n, icmp, ip, eth) {
    console.log("#"+n, ipaddr(ip.SrcIP), "->", ipaddr(ip.DstIP), "TypeCode:"+icmp.TypeCode);
	if (icmp.Payload.length > 0) {
		console.log(hex(icmp.Payload));
	}
}
