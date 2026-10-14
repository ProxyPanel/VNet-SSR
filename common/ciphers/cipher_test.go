package ciphers

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/utils/bytesx"
	"strings"
	"testing"
)

func BenchmarkDecrypto(t *testing.B) {
	for i := 0; i < t.N; i++ {
		key, _ := hex.DecodeString("b36d331451a61eb2d76860e00c347396")
		iv, _ := hex.DecodeString("3b272b460e99f22a314d5f7335c00e6e")
		cipher, _ := NewCipher(OP_DECRYPT, "aes-128-gcm", key, iv)
		data, _ := hex.DecodeString("b1c5a0097220c3db3e0b23b98c8b3cddd292fd9ddf769e8b7494de52f6d958b19712f10f08a096878b")
		cipher.Decrypt(data)
	}
}

func ExampleNewCipher_decrypt() {
	key, _ := hex.DecodeString("b36d331451a61eb2d76860e00c347396")
	iv, _ := hex.DecodeString("3b272b460e99f22a314d5f7335c00e6e")
	cipher, _ := NewCipher(OP_DECRYPT, "aes-128-gcm", key, iv)
	data, _ := hex.DecodeString("b1c5a0097220c3db3e0b23b98c8b3cddd292fd9ddf769e8b7494de52f6d958b19712f10f08a096878b")
	result, err := cipher.Decrypt(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(hex.EncodeToString(result))
	//Output:
	//6675636b796f75
}

func ExampleNewCipher_encrypt() {
	key, _ := hex.DecodeString("b36d331451a61eb2d76860e00c347396")
	iv, _ := hex.DecodeString("3b272b460e99f22a314d5f7335c00e6e")
	encipher, _ := NewCipher(OP_ENCRYPT, "aes-128-gcm", key, iv)
	result, err := encipher.Encrypt([]byte("fuckyou"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(hex.EncodeToString(result))

	decipher, _ := NewCipher(OP_DECRYPT, "aes-128-gcm", key, iv)
	result, err = decipher.Decrypt(result)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(hex.EncodeToString(result))
	//Output:
	//b1c5a0097220c3db3e0b23b98c8b3cddd292fd9ddf769e8b7494de52f6d958b19712f10f08a096878b
	//6675636b796f75
}

func TestEncryptorEncryptForStream(t *testing.T) {
	encryptor, err := NewEncryptor("aes-128-cfb", "killer")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := bytesx.MustHexDecode("7ae0cd7ede4f99f5f51d0d52cd3026c3bb266241305dc4f8f968fe55703006fcd456724001c7dcebd4f5af51df89ab9921173a0f60735922d3ce52f58e8fb0aceb65fa834425eb3826961e5034bca64d1d7ccb8485cea8cfcdb011f3cef766f8275f83609cd844b658877ed79cd3612f26f6449494d660dc9039175e627af2d224363e8262796738064fdf3e53e42546d5b3cf32bea66dac7015b6c87967d2fd954d85d8cf8dfaa70330dbd98029e86ae30ac820f60496ab0a5e8a357c634183d640e9362445eaaec9e3d682c037889b539e1cedf9843cd152bd169c0d2fc55e88747773434240cb0686735251eb46317e7e31b504a253d9e2d15ef8ec0e61f515ec7a3d4ed57691e1fc0f109d9415919a7e2d642b188c522facae4bbf8853e1a02fe060d1a14b33b2e5a24b8ef74f30053feb45603fee1eece2416d2d457dd3f24cb1d5143a7a523f20e4c75912ae1c8774595f64fac73031010677137f9a9306b4f40dbdcdf997a52fdea60c863f71cc88ffaafa8bb2a561356e05fff673f72f48088303e8f39a03b0e1b7ab0423a4974209f996b6c0fbd9c885a3e36899873828e0a9b9bfda795f57fa4511edd6371f42e8fddb7c11df3ae2c167f27d53550532a5847b4d90fbb680f4a5931f503ebf866bbc760f2fb377aa1a9ac81df09c60a84a70c4699c2c9c7ecbce3ec834c9b9ef7ccdd9adc41f693f4c27d048c9ccbef447fef98e6350a9934174b327ed92167b3a15718581e5e0ea5701e13135c245ca50be11753f54538106d649f70a3044940d80d455e0b00696931454f0e5e5f135e5cf37d332f07a8907fc592da8adf5d9056a506dd819e556802c19487ae01a2c276754af3012b3dccf8e53fce4810faf4d56c5aeb0f2d114b18a025527b5504a655c3268c60ce21f8c")
	cleartext, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	a, err := aes.NewCipher(encryptor.Key)
	if err != nil {
		t.Fatal(err)
	}
	cfb := cipher.NewCFBDecrypter(a, ciphertext[:16])
	buf := make([]byte, len(ciphertext)-16)
	cfb.XORKeyStream(buf, ciphertext[16:])
	// 前 16 字节是这条密文自带的 IV：与标准库同 IV、同 key 的 CFB 必须逐字节一致
	if !bytes.Equal(cleartext, buf) {
		t.Fatalf("encryptor 与标准库 CFB 结果不一致\n encryptor: %x\n stdlib:    %x", cleartext, buf)
	}
}

// 一次握手两侧各持一个 Encryptor：加密侧首包自带 IV/salt，解密侧从密文前缀取 IV。
// 这条路径就是线上形状，rc4 与分组模式都由 auth 层直接依赖；明文按整块取，避开分组模式的尾巴
func TestEncryptorRoundTrip(t *testing.T) {
	for _, method := range []string{"aes-128-cfb", "aes-128-cbc", "rc4", "aes-128-gcm", "chacha20-ietf"} {
		t.Run(method, func(t *testing.T) {
			plain := []byte(strings.Repeat("a", 16) + strings.Repeat("b", 16))
			encryptor, err := NewEncryptor(method, "killer")
			if err != nil {
				t.Fatalf("%s 构造失败: %v", method, err)
			}
			decryptor, err := NewEncryptor(method, "killer")
			if err != nil {
				t.Fatalf("%s 构造失败: %v", method, err)
			}
			ciphertext, err := encryptor.Encrypt(plain)
			if err != nil {
				t.Fatalf("%s 加密失败: %v", method, err)
			}
			if !bytes.HasPrefix(ciphertext, encryptor.IVOut) {
				t.Fatalf("%s 首包没有带 IV/salt 前缀: %x (IVOut=%x)", method, ciphertext, encryptor.IVOut)
			}
			cleartext, err := decryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("%s 解密失败: %v", method, err)
			}
			if !bytes.Equal(cleartext, plain) {
				t.Fatalf("%s 往返不一致\n want: %x\n got:  %x", method, plain, cleartext)
			}
		})
	}
}

// 分组模式没有字节粒度：不足一块的尾巴留到下一次写出，既不丢也不提前 emit
func TestEncryptorCBCcarriesSubBlockTail(t *testing.T) {
	encryptor, err := NewEncryptor("aes-128-cbc", "killer")
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := NewEncryptor("aes-128-cbc", "killer")
	if err != nil {
		t.Fatal(err)
	}
	first := bytes.Repeat([]byte("a"), 30)
	second := []byte("bc")
	out1, err := encryptor.Encrypt(first)
	if err != nil {
		t.Fatal(err)
	}
	// 首包带 16 字节 IV，其余只发整块：30 字节明文这一趟只能出 16 字节密文
	if len(out1) != 32 {
		t.Fatalf("首包应为 IV(16)+整块(16)，实得 %d", len(out1))
	}
	out2, err := encryptor.Encrypt(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(out2) != 16 {
		t.Fatalf("第二段应为凑成的整块 16，实得 %d", len(out2))
	}
	got, err := decryptor.Decrypt(out1)
	if err != nil {
		t.Fatal(err)
	}
	tail, err := decryptor.Decrypt(out2)
	if err != nil {
		t.Fatal(err)
	}
	want := bytesx.ContactSlice(first, second)
	if all := bytesx.ContactSlice(got, tail); !bytes.Equal(all, want) {
		t.Fatalf("分段往返不一致\n want: %x\n got:  %x", want, all)
	}
}

// AEAD 的认证标签要真挡住篡改：改一字节就必须报错，否则加密层等于不设防
func TestEncryptorAEADrejectsTamperedChunk(t *testing.T) {
	encryptor, err := NewEncryptor("aes-128-gcm", "killer")
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := NewEncryptor("aes-128-gcm", "killer")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptor.Encrypt(bytes.Repeat([]byte("a"), 16))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xFF
	if _, err := decryptor.Decrypt(ciphertext); err == nil {
		t.Fatal("被篡改的 AEAD 包不应通过解密")
	}
}

func TestEncryptor_Dulpx_CBC(t *testing.T) {
	encrypt, err := NewEncryptorWithIv("aes-128-cbc", "@123", bytes.Repeat([]byte{0x00}, 16))
	if err != nil {
		t.Fatal(err)
	}
	decrypt, err := NewEncryptorWithIv("aes-128-cbc", "@123", bytes.Repeat([]byte{0x00}, 16))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(strings.Repeat("a", 16))
	ciphertext, err := encrypt.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	cleartext, err := decrypt.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cleartext, data) {
		t.Fatalf("同 IV 两侧的 CBC 往返不一致\n want: %x\n got:  %x", data, cleartext)
	}
}
