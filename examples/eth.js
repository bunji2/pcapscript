// eth.js
function Eth(n, ts, eth) {
    console.log(ts.String());
    console.log("#"+n, hwaddr(eth.SrcMAC), "->", hwaddr(eth.DstMAC));
}
