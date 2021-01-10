// portscan.js

// スキャンしたポート番号を格納。
var scaned = {};

function END(count) {
    // オープンしているポート番号のリストを取得
    var ports = [];
    for (k in scaned) {
        //console.log(k+":", scaned[k]);
        if (scaned[k] == "open?") {
          ports.push(k);
        }
    }

    console.log("open ports:", ports.join(","));
}

function UDP(n, udp, ip, eth) {
    // スキャンしたポート番号を記録。
    scaned[udp.DstPort] = "open?";
}

function ICMP(n, icmp, ip, eth) {
    // TypeCode == 0x0303 は宛先到達不可能通知でポート到達不能の場合
    if (icmp.TypeCode == 0x0303 && icmp.Payload.length > 0) {
        // スキャンしたポート番号はペイロードの 22,23 番目の2バイト。
        var port = icmp.Payload[22]*256 + icmp.Payload[23];
        // スキャンしたポート番号が閉じていることを記録。
        scaned[port] = "close";
    }
}
