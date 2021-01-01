// 2020/09/25 ゼロから始めるCTF入門 Network の問題の解法

var flag = "";

function END(count) {
  console.log(flag);
}

function ICMP(n, icmp, ip, eth) {
  // Echoリクエストかつペイロードがあるとき
  if (icmp.TypeCode == 2048 && icmp.Payload.length>0) {
    //ペイロードの１バイト目のみ抽出
    flag = flag + str(icmp.Payload)[0];
  }
}