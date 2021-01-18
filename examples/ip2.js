// ip2.js

var ipaddrs = {};
function add(ipaddr) {
    if (ipaddrs[ipaddr] == undefined) {
            ipaddrs[ipaddr] = 0;
    }
    ipaddrs[ipaddr] = ipaddrs[ipaddr] + 1;
}

function END (count) {
    for (var ipaddr in ipaddrs) {
        console.log(ipaddr, "=", ipaddrs[ipaddr]);
    }
}

function IP (n, ts, ip, eth) {
    add(ipaddr(ip.SrcIP));
}