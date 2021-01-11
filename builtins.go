// builtins.go
// 組み込み関数

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"
)

// BuiltIns は組み込み関数を格納する変数
var BuiltIns = map[string]interface{}{
	"hex": hex.Dump,
	"hwaddr": func(bb []byte) string {
		return net.HardwareAddr(bb).String()
	},
	"ipaddr": func(bb []byte) string {
		return net.IP(bb).String()
	},
	"str": func(bb []byte) string {
		return string(bb)
	},
	"bytes": func(s string) []byte {
		return []byte(s)
	},
	"isUTF8":          isUTF8,
	"isASCII":         isASCII,
	"isBASE64":        isBASE64,
	"BASE64Encode":    BASE64Encode,
	"BASE64Decode":    BASE64Decode,
	"bytesFromHexStr": bytesFromHexStr,
	"HexStr":          hexStrFromBytes,
	"MD5":             MD5,
	"SHA1":            SHA1,
	"ROT13":           ROT13,
	//
	"readHTTPRequest":     readHTTPRequest,
	"readHTTPResponse":    readHTTPResponse,
	"readWwwAuthenticate": readWwwAuthenticate,
}

func addBuiltIn(name string, value interface{}) {
	BuiltIns[name] = value
}

//

/*
// dumpCode は与えられたバイト列の DecodeRune の結果をダンプする
func dumpCode(b []byte) {
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError {
			fmt.Println("==> RuneError")
			break
		}
		fmt.Printf("rune = '%c', size = %v\n", r, size)
		b = b[size:]
	}
}
*/

// isUTF8 は与えられたバイト列が UTF8 エンコードされているかどうかを検査する
func isUTF8(bb []byte) (r bool) {
	for len(bb) > 0 {
		// 与えられたバイト列の先頭の UTF8 エンコードされた文字とそのバイト数を取り出す
		rn, size := utf8.DecodeRune(bb)
		if rn == utf8.RuneError {
			// 一つでも UTF8 エンコードが不適切なものがあったらそこで終了
			return
		}
		bb = bb[size:] // UTF8 エンコードされていたバイト数だけ進める
	}
	// 最後まで検査が完了
	r = true
	return
}

// isASCII は与えられたバイト列がすべてアスキー文字かどうかを検査する
func isASCII(bb []byte) (r bool) {
	for len(bb) > 0 {
		rn, size := utf8.DecodeRune(bb)
		// 与えられたバイト列の先頭の UTF8 エンコードされた文字とそのバイト数を取り出す
		if rn == utf8.RuneError || size > 1 {
			// 一つでも UTF8 エンコードが不適切なもの、あるいは、
			// バイト数が１より大きいものがあったらそこで終了
			// （アスキー文字は常に１バイトなので）
			return
		}
		bb = bb[size:] // UTF8 エンコードされていたバイト数だけ進める
	}
	// 最後まで検査が完了
	r = true
	return
}

// isBASE64 は与えられたバイト列が BASE64 エンコードされているかどうかを検査する
func isBASE64(bb []byte) (r bool) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(bb)))
	n, err := base64.StdEncoding.Decode(dst, bb)
	if err == nil && n > 0 {
		r = true
	}
	return
}

// BASE64Encode は与えられたバイト列を BASE64 エンコードした文字列に変換する
func BASE64Encode(src []byte) (dst string) {
	dst = base64.StdEncoding.EncodeToString(src)
	return
}

// BASE64Decode は与えられた文字列を BASE64 デコードしたバイト列に変換する
func BASE64Decode(src string) (dst []byte) {
	tmp, err := base64.StdEncoding.DecodeString(src)
	if err == nil {
		dst = tmp
	}
	return
}

func bytesFromHexStr(s string) (bb []byte) {
	var err error
	bb, err = hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return
}

func hexStrFromBytes(bb []byte) string {
	return hex.EncodeToString(bb)
}

// MD5 は与えられたバイト列の MD5 ハッシュ値を計算する
func MD5(bb []byte) []byte {
	h := md5.New()
	h.Write(bb)
	return h.Sum(nil)
}

// SHA1 は与えられたバイト列の SHA1 ハッシュ値を計算する
func SHA1(bb []byte) []byte {
	h := sha1.New()
	h.Write(bb)
	return h.Sum(nil)
}

// ROT13 は与えられたバイト列をシーザー暗号で暗号化する
func ROT13(bb []byte) (r []byte) {
	for _, b := range bb {
		r = append(r, subRot13(b))
	}
	return
}

func subRot13(b byte) (r byte) {
	if b >= 'a' && b <= 'z' {
		r = (b-'a'+13)%26 + 'a'
	} else if b >= 'A' && b <= 'Z' {
		r = (b-'A'+13)%26 + 'A'
	} else {
		r = b
	}
	return
}

// HTTP

// https://golang.org/pkg/net/http/#Request
func readHTTPRequest(bb []byte) (r *http.Request) {
	var err error
	r, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(bb)))

	if err != nil {
		panic(err)
	}

	return
}

// https://golang.org/pkg/net/http/#Response
func readHTTPResponse(bb []byte, req *http.Request) (r *http.Response) {
	var err error
	r, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(bb)), req)

	if err != nil {
		panic(err)
	}

	return
}

// Digest realm="secret", nonce="bbKtsfbABAA=5dad3cce7a7dd2c3335c9b400a19d6ad02df299b", algorithm=MD5, qop="auth"
func readWwwAuthenticate(line string) (r map[string]string) {
	cols := strings.Split(line, ",")
	r = readTypeRealm(cols[0])
	for _, col := range cols[1:] {
		k, v := readKV(strings.TrimSpace(col))
		if k != "" {
			r[k] = v
		}
	}
	return
}

func readTypeRealm(line string) (r map[string]string) {
	cols := strings.Split(line, " ")
	if len(cols) == 0 {
		return
	}
	r = map[string]string{"type": cols[0]}
	k, v := readKV(cols[1])
	if k != "" {
		r[k] = v
	}
	return
}

// k=v のフォーマットの k と v を読み出す
func readKV(line string) (k, v string) {
	/*
		// 以下のようにすると、v の 中に = が入ってるとうまくいかない
		cols := strings.Split(line, "=")
		k = strings.TrimSpace(cols[0])
		v = stripDoubleQuote(strings.TrimSpace(cols[1]))
	*/
	// まず = の出現位置を調べて
	pos := strings.Index(line, "=")
	if pos > 0 {
		// = の前までを k、
		k = strings.TrimSpace(line[0:pos])
		// = の後以降を v とする。
		v = stripDoubleQuote(strings.TrimSpace(line[pos+1:]))
	}

	return
}

func stripDoubleQuote(line string) (r string) {
	r = line

	if line[0] == '"' && line[len(line)-1] == '"' {
		r = line[1 : len(line)-1]
	}
	return
}
