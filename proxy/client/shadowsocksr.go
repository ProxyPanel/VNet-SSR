package client

type ShadowsocksClient struct {
	Host          string
	Port          int
	Passwd        string
	Method        string
	Protocol      string
	ProtocolParam string
	Obfs          string
	ObfsParam     string
}

func (s *ShadowsocksClient) Proxy(host string,port int){

}

