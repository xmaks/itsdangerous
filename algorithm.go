package itsdangerous

import (
    "crypto/hmac"
    "hash"
)

type SignatureAlgorithm interface {
    GetSignature(key, value []byte) ([]byte, error)
    VerifySignature(key, value, signature []byte) error
}

type noneSignatureAlgorithm struct {
}

func NewNoneSignatureAlgorithm() SignatureAlgorithm {
    return &noneSignatureAlgorithm{}
}

func (this *noneSignatureAlgorithm) GetSignature([]byte, []byte) ([]byte, error) {
    return []byte{}, nil
}

func (this *noneSignatureAlgorithm) VerifySignature([]byte, []byte, []byte) error {
    return nil
}

type hmacSignatureAlgorithm struct {
    hashType func() hash.Hash
}

func NewHmacSignatureAlgorithm(hashType func() hash.Hash) SignatureAlgorithm {
    return &hmacSignatureAlgorithm{hashType}
}

func (this *hmacSignatureAlgorithm) GetSignature(key, value []byte) ([]byte, error) {
    mac := hmac.New(this.hashType, key)
    if _, err := mac.Write(value); err != nil {
        return nil, err
    }
    return mac.Sum(nil), nil
}

func (this *hmacSignatureAlgorithm) VerifySignature(key, value, signature []byte) error {
    expectedSignature, err := this.GetSignature(key, value)
    if err != nil {
        return err
    }
    if !hmac.Equal(expectedSignature, signature) {
        return NewBadSignatureError(signature)
    }
    return nil
}
