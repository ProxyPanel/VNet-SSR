package rsax

import (
	"fmt"
)

func ExampleRSA(){
	publicKey := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJuoMtHAg3HJS39kRdMFt1TOa4
L4pVegG3886Glv9Ndp2fsH5sEqpG4M9sxOi4etlo77J8CousYfDZsM/oLs66KwQ2
YHLJII6LnLatoW7/lXS2woCrEmHoLepHJVZ6P/mbV42+DL1WWzm9jaXSq5nTFekD
hpR9OkauiT/VwVkMmwIDAQAB
-----END PUBLIC KEY-----`
	privateKey := `-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMm6gy0cCDcclLf2
RF0wW3VM5rgvilV6AbfzzoaW/012nZ+wfmwSqkbgz2zE6Lh62WjvsnwKi6xh8Nmw
z+guzrorBDZgcskgjouctq2hbv+VdLbCgKsSYegt6kclVno/+ZtXjb4MvVZbOb2N
pdKrmdMV6QOGlH06Rq6JP9XBWQybAgMBAAECgYAv5SCP7T/mFdsZclb46SpNx1xg
DqmBcd5GlpRKUD99XNQ/vd/GOQhEm8ujv3yhkEleKMrvuHFBFF/iz6ANOE/MZ3MV
FpTlLtdlng6I9TnbqeFj1K/0EraGEVejIQI5O2ykhpKJPC77p3ff1Ax2CrHyCgkj
teRzhRN9L0NC0zaNQQJBAPbKad0F+ER0m8mpo+Z7Z9mOe6TL2+XywfPbHx+VHo31
Y8MrkvhhJYUFgmEbKIHNuGl/JGqgnJK6Kvh03x1XJt0CQQDRQZ8Tx3CVnAkBcb5A
GqtIpit8JZg+jhErfLjLGLd5D2fUwse6VComTWHOO0ODj+BM7+W0wqDs7b5asJrt
S/3XAkEAqiyjWSRPsKyT7DgM69Z2ot8MRXPJO0PtGAEl8fo6qnrmguNeIeWjIJnO
8LTwdqlrm1tvuhLsRIUZMmAspae+BQJALbAbMHFaJoA0Aym3dT2dajZFxkxbCkVw
gEMyAb36ySbQ78Y7X3Zi4YwBr8qGuiHewk2apLXd9v0Nk7V9jhQKbwJADOu6RS45
92FrcCuJvvxjMsW9cLWd22xcwnyJXRZSgI7jwef7/rTPtrhFVv/AjLisl4E8SKiC
I10Obt912YV2zA==
-----END PRIVATE KEY-----`
	fmt.Println("aa")
	rsaInstance,err := NewXRsa([]byte(publicKey),[]byte(privateKey))
	if err != nil{
		fmt.Printf("%v\n",err)
		return
	}
	clearData,err := rsaInstance.PrivateDecrypt("UQqPOeIZ9qX3zEX-no0dI5rs-PJ9uRfCS36SkNvPNDJ0XOxuYv_CwEdggkuyJLFVYzkQgallqTUBqd8xWp_Xt3FjnyW9lX4SG_6usWWQ6rZH7tg9fIQozR34sGpDPAr9JYJil-JsRPjLtCGqnEDWlV6sbwe9FGk6nw8HBd_0shhbydCLCLASI4uuKLy2-xgK9oNft-vhJ8ApuQrRuvQ_RAaEtwc_QxttUl2xw-IYdkelcU5GN6hAptALYFkZQ4yerMEQanB7wDNypKdiHaDNifv6P2_wk_V8hMBfoJZagILZG8MJ5nuCzVsijlLdY03btHtT8A92UvikSul-fGLSzKZG2VpDQpDL8NPcIyZ00nPXlsLjNtLW8xEcTH4xyn4J7RBuMcD9AHVmk91qWEGx1VnIBo41phFqpWerFgA5S3oqDtK1bwmIt3Zp094DKTfYM0bMlCyby6VkBAU0i1bU19kCd9qbwLGM-XjNppzgj5QBWKWTqQdmlXCC2fwOQnrW")
	if err != nil{
		fmt.Printf("%v\n",err)
		return
	}
	fmt.Println(clearData)
	fmt.Println(len(clearData))
	//Output:
}

