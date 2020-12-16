package main

import (
	"BTCAddress/BTCaddress"
	"BTCAddress/base58"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

func main() {
	pri,pub :=BTCaddress.GenerateECCPriKeyAndPubKey()
	fmt.Println("生成的私钥是：",pri)
	pubHash :=BTCaddress.Sha256Hash(pub)
	pubRipmd :=BTCaddress.Ripemd160(pubHash,[]byte{0X00})
	hash1 :=BTCaddress.Sha256Hash(pubRipmd)
	hash2 :=BTCaddress.Sha256Hash(hash1)
	check :=hash2[:4]
	add :=BTCaddress.NewAddress(pubRipmd,check)
	fmt.Println("地址是：",add)
	fmt.Println(BTCaddress.Verify(add))
}
func main1() {
	fmt.Println("go")
		curve := elliptic.P256()
		pri,x,y,err:=elliptic.GenerateKey(curve,rand.Reader)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println(pri)

		pubKey :=append(x.Bytes(),y.Bytes()...)

		sha256hash :=sha256.New()
		sha256hash.Write(pubKey)
		pubSha256hash :=sha256hash.Sum(nil)

		ripmed160:=ripemd160.New()
		ripmed160.Write(pubSha256hash)
		pubrpmd160 :=ripmed160.Sum(nil)
		//fmt.Println(len(pubrpmd160))


		versionPubRpmd160 := append([]byte{0X00},pubrpmd160...)

		sha256hash.Reset()//重置
		sha256hash.Write(versionPubRpmd160)
		hash1:=sha256hash.Sum(nil)

		sha256hash.Reset()
		sha256hash.Write(hash1)
		hash2 := sha256hash.Sum(nil)

		check :=hash2[:4]
		//fmt.Println(string(check))

		addByte := append(versionPubRpmd160,check...)
		//fmt.Println(string(addByte))
		fmt.Println(len(addByte))
		add:=base58.Encode(addByte)
		fmt.Println(add)
		fmt.Println(len(add))

		fmt.Println(BTCaddress.Verify(add))
}

