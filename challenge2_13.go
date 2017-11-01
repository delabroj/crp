package crp

import (
	"fmt"
	"strings"
)

type QueryString string

func (q QueryString) Parse() map[string]string {
	ret := make(map[string]string)

	entries := strings.Split(string(q), "&")

	for _, e := range entries {
		kv := strings.Split(e, "=")
		if _, ok := ret[kv[0]]; ok {
			continue
		}
		if len(kv) >= 2 {
			ret[kv[0]] = kv[1]
		} else {
			ret[kv[0]] = ""
		}
	}

	return ret
}

func GenerateProfile(e string) string {
	e = strings.Replace(e, "=", "", -1)
	e = strings.Replace(e, "&", "", -1)
	uid := 10
	role := "user"

	return fmt.Sprintf("email=%v&uid=%v&role=%v", e, uid, role)
}

// Structure is 'email=' + input stripped of & and = characters + '&uid=10&role=user'
func CreateAdminProfile(generateEncryptedProfile func(string) (Bytes, error)) (Bytes, error) {
	var email string
	var cipher Bytes
	var err error

	// Capture 'admin&uid=10&rol'
	email = "j@mail.comadmin"
	cipher, err = generateEncryptedProfile(email)
	if err != nil {
		return Bytes{}, err
	}
	suffix := cipher[16:32]

	// Capture 'email=joe@gmail.' + 'com&uid=10&role='
	email = "joe@gmail.com" // email=joe@gmail. com&uid=10&role= user
	cipher, err = generateEncryptedProfile(email)
	if err != nil {
		return Bytes{}, err
	}
	prefix := cipher[:32]

	// Return admin profile 'email=joe@gmail.com&uid=10&role=admin&uid=10&rol'
	adminProfile := append(prefix, suffix...)
	return adminProfile, nil
}
