package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/ripemd160"
)

func GeneratePriKey()(*ecdsa.PrivateKey,error){
	curve := elliptic.P256()
	return ecdsa.GenerateKey(curve,rand.Reader)
}

func GeneratePubKey(pri *ecdsa.PrivateKey) []byte{
	return append(pri.PublicKey.X.Bytes(),pri.PublicKey.Y.Bytes()...)
}

func PubHash(pub []byte)[]byte{
	sha := Sha256Hash(pub)
	return Ripemd160Hsh(sha)
}

func Sha256Hash(msg []byte)[]byte{
	sha256Hash := sha256.New()
	sha256Hash.Write(msg)
	return sha256Hash.Sum(nil)
}

func Ripemd160Hsh(msg []byte)[]byte{
	ripemdHash := ripemd160.New()
	ripemdHash.Write(msg)
	return ripemdHash.Sum(nil)
}
