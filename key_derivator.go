package itsdangerous

import (
    "hash"
)

type KeyDerivator interface {
    DeriveKey([]byte, []byte) ([]byte, error)
}

type noneKeyDerivator struct {
}

func NewNoneKeyDerivator() KeyDerivator {
    return &noneKeyDerivator{}
}

func (this *noneKeyDerivator) DeriveKey(key, salt []byte) ([]byte, error) {
    return key, nil
}

type concatKeyDerivator struct {
    hashType func() hash.Hash
}

func NewConcatKeyDerivator(hashType func() hash.Hash) KeyDerivator {
    return &concatKeyDerivator{hashType}
}

func (this *concatKeyDerivator) DeriveKey(key, salt []byte) ([]byte, error) {
    b := make([]byte, len(key) + len(salt))

    n := copy(b, key)
    n += copy(b[n:], salt)

    h := this.hashType()
    if _, err := h.Write(b); err != nil {
        return nil, err
    }

    return h.Sum(nil), nil
}

type djangoConcatKeyDerivator struct {
    hashType func() hash.Hash
}

func NewDjangoConcatKeyDerivator(hashType func() hash.Hash) KeyDerivator {
    return &djangoConcatKeyDerivator{hashType}
}

func (this *djangoConcatKeyDerivator) DeriveKey(key, salt []byte) ([]byte, error) {
    b := make([]byte, len(key) + len([]byte("signer")) + len(salt))

    n := copy(b, key)
    n += copy(b[n:], []byte("signer"))
    n += copy(b[n:], salt)

    h := this.hashType()
    if _, err := h.Write(b); err != nil {
        return nil, err
    }

    return h.Sum(nil), nil
}

type hmacKeyDerivator struct {
    signatureAlgorithm SignatureAlgorithm
}

func NewHmacKeyDerivator(hashType func() hash.Hash) KeyDerivator {
    return &hmacKeyDerivator{NewHmacSignatureAlgorithm(hashType)}
}

func (this *hmacKeyDerivator) DeriveKey(key, salt []byte) ([]byte, error) {
    return this.signatureAlgorithm.GetSignature(key, salt)
}
