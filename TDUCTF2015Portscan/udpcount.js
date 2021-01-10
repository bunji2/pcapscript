// udpcount.js

var bytes = {};
function add(b) {
    if (bytes[b] == undefined) {
        bytes[b] = 0;
    }
    bytes[b] = bytes[b] + 1;
}
function END(count) {
    for (k in bytes) {
        console.log(k + ":", bytes[k]);
    }
}

function UDP(n, udp, ip, eth) {
    if (udp.Payload.length>0) {
        for (i in udp.Payload) {
            add(udp.Payload[i]);
        }
    }
}