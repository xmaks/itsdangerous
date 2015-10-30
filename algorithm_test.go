package itsdangerous

import (
    "crypto/sha1"
    "testing"
)

var (
    key = []byte("key")
    val = []byte("value")
    sig = []byte{
        0x57, 0x44, 0x3a, 0x4c, 0x05,
        0x23, 0x50, 0xa4, 0x46, 0x38,
        0x83, 0x5d, 0x64, 0xfd, 0x66,
        0x82, 0x2f, 0x81, 0x33, 0x19,
    }
    bad = []byte{
        0x56, 0x44, 0x3a, 0x4c, 0x05,
        0x23, 0x50, 0xa4, 0x46, 0x38,
        0x83, 0x5d, 0x64, 0xfd, 0x66,
        0x82, 0x2f, 0x81, 0x33, 0x19,
    }
)

func TestNoneSigningAlgorithm(t *testing.T) {
    algorithm := NewNoneSignatureAlgorithm()
    if err := algorithm.VerifySignature(key, val, sig); err != nil {
        t.Errorf("unexpected: err == %v", err)
    }
    if err := algorithm.VerifySignature(key, val, bad); err != nil {
        t.Errorf("unexpected: err == %v", err)
    }
}

func TestHmacSigningAlgorithm(t *testing.T) {
    algorithm := NewHmacSignatureAlgorithm(sha1.New)
    if err := algorithm.VerifySignature(key, val, sig); err != nil {
        t.Errorf("unexpected: err == %v", err)
    }
    if err := algorithm.VerifySignature(key, val, bad); err == nil {
        t.Errorf("unexpected: err == %v", err)
    }
}
