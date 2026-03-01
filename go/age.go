package main

/*
#include <stdlib.h>

typedef struct {
    char* data;
    int   len;
    char* error;
} age_result_t;

typedef struct {
    char* public_key;
    char* secret_key;
    char* error;
} age_keypair_t;
*/
import "C"
import (
	"bytes"
	"io"
	"strings"
	"unsafe"

	"filippo.io/age"
)

//export age_free
func age_free(ptr unsafe.Pointer) {
	C.free(ptr)
}

//export age_keygen
func age_keygen() C.age_keypair_t {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return C.age_keypair_t{
			error: C.CString(err.Error()),
		}
	}

	return C.age_keypair_t{
		public_key: C.CString(identity.Recipient().String()),
		secret_key: C.CString(identity.String()),
	}
}

//export age_encrypt
func age_encrypt(data unsafe.Pointer, data_len C.int, public_key *C.char) C.age_result_t {
	pubKeyStr := C.GoString(public_key)

	recipient, err := age.ParseX25519Recipient(pubKeyStr)
	if err != nil {
		return C.age_result_t{error: C.CString(err.Error())}
	}

	input := C.GoBytes(data, data_len)

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return C.age_result_t{error: C.CString(err.Error())}
	}
	if _, err := w.Write(input); err != nil {
		return C.age_result_t{error: C.CString(err.Error())}
	}
	if err := w.Close(); err != nil {
		return C.age_result_t{error: C.CString(err.Error())}
	}

	ciphertext := buf.Bytes()
	ptr := C.CBytes(ciphertext)
	return C.age_result_t{
		data: (*C.char)(ptr),
		len:  C.int(len(ciphertext)),
	}
}

//export age_decrypt
func age_decrypt(data unsafe.Pointer, data_len C.int, secret_key *C.char) C.age_result_t {
	secretKeyStr := C.GoString(secret_key)

	identity, err := age.ParseX25519Identity(secretKeyStr)
	if err != nil {
		return C.age_result_t{error: C.CString(err.Error())}
	}

	ciphertext := C.GoBytes(data, data_len)

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return C.age_result_t{error: C.CString(err.Error())}
	}

	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		return C.age_result_t{error: C.CString(err.Error())}
	}

	plaintext := []byte(buf.String())
	ptr := C.CBytes(plaintext)
	return C.age_result_t{
		data: (*C.char)(ptr),
		len:  C.int(len(plaintext)),
	}
}

func main() {}
