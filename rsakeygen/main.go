// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func rsaGenKey(bits int) error {
	privateKey,err:=rsa.GenerateKey(rand.Reader,bits)
	if err!=nil {
		return err
	}

	privateKeyStream:=x509.MarshalPKCS1PrivateKey(privateKey)
	block:=pem.Block{
		Type:"RSA Private Key",
		Bytes:privateKeyStream,
	}

	privateKeyFile,err:=os.Create("private.pem")
	if err!=nil {
		return err
	}

	defer privateKeyFile.Close()
	err=pem.Encode(privateKeyFile,&block)
	if err!=nil {
		return err
	}

	publicKey:=privateKey.PublicKey
	publicKeyStream:=x509.MarshalPKCS1PublicKey(&publicKey)
	block=pem.Block{
		Type:"RSA Public Key",
		Bytes:publicKeyStream,
	}

	publicKeyFile,err:=os.Create("public.pem")
	if err!=nil {
		return err
	}

	defer publicKeyFile.Close()
	err=pem.Encode(publicKeyFile,&block)
	if err!=nil {
		return err
	}
	return nil
}

func encryptRSAPublic(src []byte,path string) ([]byte,error) {
	file,err:=os.Open(path)
	if err!=nil {
		return nil,err
	}
	defer file.Close()
	fileinfo,err:=os.Stat(path)
	if err!=nil {
		return nil,err
	}
	fileStream:=make([]byte,fileinfo.Size())
	file.Read(fileStream)
	block,_:=pem.Decode(fileStream)
	key,err:=x509.ParsePKCS1PublicKey(block.Bytes)
	if err!=nil {
		return nil,err
	}
	dst,err:=rsa.EncryptPKCS1v15(rand.Reader,key,src)
	if err!=nil {
		return nil,err
	}
	return dst,nil
}

func decryptRSAPrivate(src []byte,path string) ([]byte,error) {
	file,err:=os.Open(path)
	if err!=nil {
		return nil,err
	}
	defer file.Close()
	fileinfo,err:=os.Stat(path)
	if err!=nil {
		return nil,err
	}
	fileStream:=make([]byte,fileinfo.Size())
	file.Read(fileStream)
	block,_:=pem.Decode(fileStream)
	key,err:=x509.ParsePKCS1PrivateKey(block.Bytes)
	dst,err:=rsa.DecryptPKCS1v15(rand.Reader,key,src)
	if err!=nil {
		return nil,err
	}
	return dst,nil
}

func main()  {
	err:=rsaGenKey(4096)
	if err!=nil {
		fmt.Print(err)
		return
	}
	x:=[]byte("反美的都没有好下场")
	x1,err:=encryptRSAPublic(x,"public.pem")
	if err!=nil {
		fmt.Print(err)
		return
	}
	x2,err:=decryptRSAPrivate(x1,"private.pem")
	if err!=nil {
		fmt.Print(err)
		return
	}
	fmt.Print(string(x2))
}
