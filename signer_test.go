package itsdangerous

import (
    "bytes"
    "crypto/sha1"
    "testing"
    "time"
)


func TestSimpleSigner(t *testing.T) {
    key := []byte("itsdangerous.Key")
    options := SignerOptions{
        Separator:[]byte("###"),
        Salt: []byte("itsdangerous.Salt"),
        HashType: sha1.New,
    }
    signer := NewSimpleSigner(key, &options)

    for _, signatureAlgorithm := range []SignatureAlgorithm{
        NewNoneSignatureAlgorithm(),
        NewHmacSignatureAlgorithm(sha1.New),
    } {
        options.SignatureAlgorithm = signatureAlgorithm

        value := []byte("itsdangetous.Signer")

        signed, err := signer.Sign(value)
        if err != nil {
            t.Errorf("%s", err.Error())
        }

        unsigned, err := signer.Unsign(signed)
        if err != nil {
            t.Errorf("%s", err.Error())
        }

        if bytes.Compare(value, unsigned) != 0 {
            t.Errorf("%s != %s", value, string(unsigned))
        }

        if err = signer.Validate(signed); err != nil {
            t.Errorf("%s", err.Error())
        }
    }

    for _, keyDerivator := range []KeyDerivator{
        NewNoneKeyDerivator(),
        NewConcatKeyDerivator(sha1.New),
        NewDjangoConcatKeyDerivator(sha1.New),
        NewHmacKeyDerivator(sha1.New),
    } {
        options.KeyDerivator = keyDerivator

        value := []byte("itsdangetous.Signer")

        signed, err := signer.Sign(value)
        if err != nil {
            t.Errorf("%s", err.Error())
        }

        unsigned, err := signer.Unsign(signed)
        if err != nil {
            t.Errorf("%s", err.Error())
        }

        if bytes.Compare(value, unsigned) != 0 {
            t.Errorf("%s != %s", value, string(unsigned))
        }

        if err = signer.Validate(signed); err != nil {
            t.Errorf("%s", err.Error())
        }
   }
}

func TestTimestampSigner(t *testing.T) {
    key := []byte("itsdangerous.Key")
    options := SignerOptions{
        Separator:[]byte("|"),
        Salt: []byte("itsdangerous.Salt"),
        HashType: sha1.New,
        SignatureAlgorithm: NewHmacSignatureAlgorithm(sha1.New),
        KeyDerivator: NewNoneKeyDerivator(),
    }
    maxAge := time.Duration(60 * time.Second)
    signer := NewTimestampSigner(key, &options, &maxAge)

    for _, signatureAlgorithm := range []SignatureAlgorithm{
        NewNoneSignatureAlgorithm(),
        NewHmacSignatureAlgorithm(sha1.New),
    } {
        options.SignatureAlgorithm = signatureAlgorithm

        value := []byte("itsdangetous.Value")

        signed, err := signer.Sign(value)
        if err != nil {
            t.Errorf("%s", err.Error())
        }

        unsigned, err := signer.Unsign(signed)
        if err != nil {
            t.Errorf("%s", err.Error())
        }

        if bytes.Compare(value, unsigned) != 0 {
            t.Errorf("%s != %s", value, string(unsigned))
        }

        if err = signer.Validate(signed); err != nil {
            t.Errorf("%s", err.Error())
        }
    }

    for _, keyDerivator := range []KeyDerivator{
        NewNoneKeyDerivator(),
        NewConcatKeyDerivator(sha1.New),
        NewDjangoConcatKeyDerivator(sha1.New),
        NewHmacKeyDerivator(sha1.New),
    } {
        options.KeyDerivator = keyDerivator

        value := []byte("itsdangetous.Value")

        signed, err := signer.Sign(value)
        if err != nil {
            t.Errorf("%s", err.Error())
        }

        unsigned, err := signer.Unsign(signed)
        if err != nil {
            t.Errorf("%s", err.Error())
        }

        if bytes.Compare(value, unsigned) != 0 {
            t.Errorf("%s != %s", value, string(unsigned))
        }

        if err = signer.Validate(signed); err != nil {
            t.Errorf("%s", err.Error())
        }
    }

    maxAge = time.Duration(0 * time.Second)
    signer = NewTimestampSigner(key, &options, &maxAge)

    value := []byte("itsdangetous.Value")

    signed, err := signer.Sign(value)
    if err != nil {
        t.Errorf("%s", err.Error())
    }

    if err = signer.Validate(signed); err == nil {
        t.Errorf("unexpected: err == %v", err)
    } else {
        switch err.(type) {
        case *BadTimestampSignatureError:
        default:
            t.Errorf("unexpected: err == %v", err)
        }
    }
}
