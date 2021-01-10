// solve.js
// https://ctf.mzyy94.com/q/TDUCTF2015-NW500/
// TDUCTF 2015 "Portscan"
// 
// 解法：UDP パケットのペイロードにメッセージが隠されている
// ようなので、すべての UDP パケットのペイロードを取得する。

var msg=[];

function END(count) {
    // 最後にバイト列を文字列に変換して表示
    console.log(str(msg));
}

function UDP(n, udp, ip, eth) {
    if (udp.Payload.length>0) {
        // ペイロードのバイト列を変数 msg に結合して格納
        msg = msg.concat(udp.Payload);
    }
}
