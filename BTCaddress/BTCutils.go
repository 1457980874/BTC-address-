package BTCaddress

import (
	"BTCAddress/base58"
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

//生成椭圆曲线加密算法的私钥和公钥
func GenerateECCPriKeyAndPubKey()(pri, pub []byte){
	curve :=elliptic.P256()
	pri, x, y, err := elliptic.GenerateKey(curve,rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		return nil,nil
	}
	pubKey := append(x.Bytes(),y.Bytes()...)
	return pri, pubKey
}

//sha2计算
func Sha256Hash(input []byte)[]byte{
	sha256hash :=sha256.New()
	sha256hash.Write(input)
	hashByte :=sha256hash.Sum(nil)
	return hashByte
}

//ripemd160 计算
func Ripemd160(pub []byte,version []byte)[]byte{
	if pub ==nil {
		fmt.Println("传入值为空，请重试！")
		return nil
	}
	ripmd :=ripemd160.New()
	ripmd.Write(pub)
	pubRipmd :=ripmd.Sum(nil)
	return append(version,pubRipmd...)
}

//生成地址
func NewAddress(versionPubRipemd []byte,checkCode []byte) string{
	return base58.Encode(append(versionPubRipemd,checkCode...))
}

//校验地址
func Verify(add string)bool{
	if add == "" {
		return false
	}
	deAddBytes :=base58.Decode(add)
	check2 :=deAddBytes[len(deAddBytes)-4:len(deAddBytes)]
	deAddByteExpelCheck :=deAddBytes[:len(deAddBytes)-4]
	sha256 :=sha256.New()
	sha256.Write(deAddByteExpelCheck)
	deHash1 := sha256.Sum(nil)
	sha256.Reset()
	sha256.Write(deHash1)
	deHash2 := sha256.Sum(nil)
	deCheck :=deHash2[:4]
	if bytes.Compare(check2,deCheck) == 0 {
		fmt.Println("验证通过")
		return true
	}
	return false
}