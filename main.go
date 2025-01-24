package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
	// "io/ioutil"
	"os"
	"encoding/hex"
)

func ShowUsage() {
	fmt.Println("\n")
	fmt.Println("Go encryption app - Application encrypts text data. ")

	fmt.Println("Usage:")
	fmt.Println("    go-encypt-app-0.1-windows-amd64.exe --encode KEY \"text to encode\"")
	fmt.Println("    go-encypt-app-0.1-windows-amd64.exe --decode KEY ENCODED_DATA_TEXT")

	fmt.Println("\nAll aguments you provided: ")
	fmt.Println(os.Args)

}

func Decode(skey string, hexString string) string {

	if (len(skey) != 32) {
		fmt.Println("    Encryption key must be 32 characters !!!");
		return "";
	}

	fmt.Println("Hex String: ", hexString)

	dataToDecodeByteArray, err := hex.DecodeString(hexString)
	
	if err != nil {
		fmt.Println("Unable to convert hex to byte. ", err)
	}

	ciphertext := dataToDecodeByteArray;

    key := []byte(skey)
	

	c, err := aes.NewCipher(key)
    if err != nil {
        fmt.Println(err)
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        fmt.Println(err)
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        fmt.Println(err)
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        fmt.Println(err)
    }
    fmt.Println(string(plaintext))

	return string(plaintext)

}


func Encode(skey string, stext string) string {
	if (len(skey) != 32) {
		fmt.Println("    Encryption key must be 32 characters !!!");
		return "";
	}

	text := []byte(stext)
    key := []byte(skey)

	// generate a new aes cipher using our 32 byte long key
    c, err := aes.NewCipher(key)
    // if there are any errors, handle them
    if err != nil {
        fmt.Println(err)
    }

    // gcm or Galois/Counter Mode, is a mode of operation
    // for symmetric key cryptographic block ciphers
    // - https://en.wikipedia.org/wiki/Galois/Counter_Mode
    gcm, err := cipher.NewGCM(c)
    // if any error generating new GCM
    // handle them
    if err != nil {
        fmt.Println(err)
    }

    // creates a new byte array the size of the nonce
    // which must be passed to Seal
    nonce := make([]byte, gcm.NonceSize())
    // populates our nonce with a cryptographically secure
    // random sequence
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        fmt.Println(err)
    }

    // here we encrypt our text using the Seal function
    // Seal encrypts and authenticates plaintext, authenticates the
    // additional data and appends the result to dst, returning the updated
    // slice. The nonce must be NonceSize() bytes long and unique for all
    // time, for a given key.
	encodedByteArray := gcm.Seal(nonce, nonce, text, nil)
    //fmt.Println(encodedByteArray)
	str := hex.EncodeToString(encodedByteArray)
	fmt.Println(str)
	return str
}

func main() {
    fmt.Println("Go Encryption App v0.1")

	argsWithProgramName := os.Args
	argsWithoutProgramName := os.Args[1:]
	fmt.Println("Application and arguments: ",argsWithProgramName)
	fmt.Println("only arguments: ",argsWithoutProgramName)
	fmt.Println("\n");
	fmt.Println("-------------------------------------------------------");
	if len(os.Args) > 3 {
		
		if ("--encode" == os.Args[1]){
			fmt.Println("Encoding: ", os.Args[3], " with key: ", os.Args[2])
			encoded := Encode(os.Args[2], os.Args[3])
			fmt.Println("\n");
			fmt.Println("Encoded in HEX: ", encoded);
			fmt.Println("\n");
		} else if ("--decode" == os.Args[1]){
			fmt.Println("Decoding: ", os.Args[3], " with key: ", os.Args[2])
			// encoded := Encode(os.Args[2], os.Args[3])
			decoded := Decode(os.Args[2], os.Args[3])
			fmt.Println("\n");
			fmt.Println("Decoded: ", decoded);
			fmt.Println("\n");
		}
	} else {
		ShowUsage();
	}

    // text := []byte("My Super Secret Code Stuff")
    // key := []byte("passphrasewhichneedstobe32bytes!")

    
}
