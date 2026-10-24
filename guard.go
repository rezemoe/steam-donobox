package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
)

type MaFile struct {
	AccountName    string `json:"account_name"`
	SharedSecret   string `json:"shared_secret"`
	IdentitySecret string `json:"identity_secret"`
	Session        struct {
		SteamID uint64 `json:"SteamID"`
	} `json:"Session"`
}

func loadMaFile(path string) (*MaFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var mf MaFile
	if err := json.Unmarshal(data, &mf); err != nil {
		return nil, fmt.Errorf("parse maFile: %w", err)
	}
	if mf.AccountName == "" || mf.SharedSecret == "" {
		return nil, fmt.Errorf("maFile is missing account_name or shared_secret")
	}
	return &mf, nil
}

const guardChars = "23456789BCDFGHJKMNPQRTVWXY"

func generateAuthCode(sharedSecret string, unixTime int64) (string, error) {
	key, err := base64.StdEncoding.DecodeString(sharedSecret)
	if err != nil {
		return "", fmt.Errorf("decode shared_secret: %w", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(unixTime/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	off := sum[19] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff

	out := make([]byte, 5)
	for i := range out {
		out[i] = guardChars[code%uint32(len(guardChars))]
		code /= uint32(len(guardChars))
	}
	return string(out), nil
}
