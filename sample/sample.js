// sample.js
// 
// パケットデータ：
//   arp --- layers.ARP
//   eth --- layers.Ethernet
//   ip ---- layers.IPv4
//   icmp -- layers.ICMPv4
//   tcp --- layers.TCP
//   udp --- layers.UDP
//   Refernce: https://godoc.org/github.com/google/gopacket/layers
//
// 組み込み関数：
//   ipaddr(x) --- IPアドレス表記
//   hwaddr(x) --- MACアドレス表記
//   save(filename, data) --- バイト列をファイルに保存
//
// その他：
//   count - パケットの番号

console.log("--------", count, "--------");
console.log("[Ethernet]", hwaddr(eth.SrcMAC), "->", hwaddr(eth.DstMAC));

if (tcp != null) {
    // TCP の場合の処理
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
    // UDP の場合の処理
    console.log("[UDP]", ipaddr(ip.SrcIP)+":"+udp.SrcPort, "->", ipaddr(ip.DstIP) + ":" + udp.DstPort);
    if (udp.Payload.length>0) {
        console.log(hex(udp.Payload));
        save("out_"+count+"_udp.dat", udp.Payload)
    } else {
        console.log("");
    }

} else if (arp != null) {
    // ARP の場合の処理
    console.log("[ARP] AddrType:", arp.AddrType, "Protocol:", arp.Protocol);
	console.log("\tOperation:", arp.Operation);
	console.log("\tSrcHWAddr:", hwaddr(arp.SourceHwAddress));
	console.log("\tSrcProtAddr:", ipaddr(arp.SourceProtAddress));
	console.log("\tDstHWAddr:", hwaddr(arp.DstHwAddress));
	console.log("\tDstProtAddr:", ipaddr(arp.DstProtAddress));

} else if (icmp != null) {
    // ARP の場合の処理
    console.log("[IPv4]", ipaddr(ip.SrcIP), "->", ipaddr(ip.DstIP));
	console.log("[ICMPv4] TypeCode:", icmp.TypeCode);//.GoString())
	if (icmp.Payload.length > 0) {
		console.log(hex(icmp.Payload));
        save("out_"+count+"_icmp.dat", icmp.Payload)
	} else {
        console.log("");
    }

} else {
    // その他の場合
    console.log("unknown")
}
