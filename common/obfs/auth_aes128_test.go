package obfs

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
	"github.com/sirupsen/logrus"
	"net"
	"reflect"
	"strings"
	"testing"
)

func ExampleTest() {
	fmt.Println(reflect.ValueOf(md5.New).Pointer() == reflect.ValueOf(md5.New).Pointer())
	//Output:
}

func TestAuthAes128(t *testing.T){
	logrus.SetLevel(logrus.DebugLevel)
	client := GetAuthAes128()
	server := GetAuthAes128()
	data := []byte(strings.Repeat("hello",100))
	clientCipherData,err := client.ClientPreEncrypt(data)
	if err != nil{
		t.Error(err)
	}

	serverClearData,_,err := server.ServerPostDecrypt(clientCipherData)
	if err != nil{
		t.Error(err)
	}

	if !bytes.Equal(serverClearData,data){
		t.Fatal("serverClearData compare error")
	}
	fmt.Print(serverClearData)


	serverCipherData,err := server.ServerPreEncrypt(data)
	if err != nil{
		t.Fatal(err)
	}
	clientClearData,err := client.ClientPostDecrypt(serverCipherData)
	if err != nil{
		t.Fatal(err)
	}

	if !bytes.Equal(clientClearData,data){
		t.Error("clientClearData compare error")
	}
	fmt.Print(clientClearData)

}


func GetAuthAes128() Plain{
	auth, _ := AuthAes128Md5Factory("auth_aes128_md5")
	serverInfo := NewServerInfo()
	serverInfo.GetUsers()[string(binaryx.LEUint32ToBytes(1024))] = "killer"
	serverInfo.SetClient(net.ParseIP("127.0.0.1"))
	serverInfo.SetPort(8080)
	serverInfo.SetProtocolParam("1024:killer")
	serverInfo.SetIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
	serverInfo.SetRecvIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
	serverInfo.SetKeyStr("killer")
	serverInfo.SetKey(MustHexDecode("b36d331451a61eb2d76860e00c347396"))
	serverInfo.SetHeadLen(30)
	serverInfo.SetTCPMss(1460)
	serverInfo.SetBufferSize(32*1024 - 5 - 4)
	serverInfo.SetOverhead(9)
	serverInfo.SetUpdateUserFunc(UpdateUser)
	auth.SetServerInfo(serverInfo)
	return auth
}