package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"image/png"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type TotpKey struct {
	url *url.URL
}

type TotpOptions struct {
	Issuer string
	AccountName string
}

func NewTotpKey(opts *TotpOptions) (*TotpKey, error) {
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	v := url.Values{}
	secret, err := GenerateRandomBytes(20)
	if err != nil {
		return nil, err
	}

	v.Set("secret", strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "="))
	v.Set("issuer", opts.Issuer)
	v.Set("period", strconv.FormatUint(30, 10))
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     fmt.Sprintf("/%s:%s", opts.Issuer, opts.AccountName),
		RawQuery: v.Encode(),
	}

	return &TotpKey{
		url:  &u,
	}, nil
}

func (key *TotpKey) Secret() string {
	q := key.url.Query()
	return q.Get("secret")
}

func (key *TotpKey) Image() ([]byte, error) {
	b, err := qr.Encode(strings.TrimSpace(key.url.String()), qr.M, qr.Auto)

	if err != nil {
		return nil, err
	}

	b, err = barcode.Scale(b, 256, 256)

	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	err = png.Encode(buf, b)

	return buf.Bytes(), nil
}

func ValidateTotp(passcode string, secret string) bool {
	passcode = strings.TrimSpace(passcode)

	if len(passcode) != 6 {
		return false
	}

	counter := int64(math.Floor(float64(time.Now().UTC().Unix()) / float64(30)))
	counters := []uint64{
		uint64(counter),
		uint64(counter + 1),
		uint64(counter - 1),
	}

	for _, counter := range counters {
		rv, err := ValidateHotp(passcode, counter, secret)
		if err != nil {
			return false
		}
		if rv == true {
			return true
		}
	}

	return false
}

func ValidateHotp(passcode string, counter uint64, secret string) (bool, error) {
	passcode = strings.TrimSpace(passcode)

	if len(passcode) != 6 {
		return false, nil
	}

	generatedOtp, err := GenerateHotpOtp(secret, counter)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(generatedOtp), []byte(passcode)) == 1, nil
}

func GenerateHotpOtp(secret string, counter uint64) (passcode string, err error) {

	// reference: https://github.com/pquerna/otp

	secret = strings.TrimSpace(strings.ToUpper(secret))
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8 - n)
	}

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	hmacHash := hmac.New(sha1.New, secretBytes)
	hmacHash.Write(buf)
	sum := hmacHash.Sum(nil)

	// "Dynamic truncation" in RFC 4226
	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	mod := int32(value % int64(math.Pow10(6)))

	return fmt.Sprintf("%06d", mod), nil
}
