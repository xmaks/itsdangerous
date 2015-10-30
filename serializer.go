package itsdangerous

import (
    "encoding/json"
    "time"
)

type Serializer interface {
    Marshal(interface{}) ([]byte, error)
    Unmarshal([]byte, interface{}) error
}

type simpleSerializer struct {
    signer Signer
}

func NewSimpleSerializer(secretKey []byte, signerOptions *SignerOptions) Serializer {
    return &simpleSerializer{NewSimpleSigner(secretKey, signerOptions)}
}

func (this *simpleSerializer) Marshal(value interface{}) ([]byte, error) {
    unsignedValue, err := json.Marshal(value)
    if err != nil {
        return nil, err
    }
    return this.signer.Sign(unsignedValue)
}

func (this *simpleSerializer) Unmarshal(signedValue []byte, value interface{}) error {
    unsignedValue, err := this.signer.Unsign(signedValue)
    if err != nil {
        return err
    }
    return json.Unmarshal(unsignedValue, value)
}

type timedSerializer struct {
    *simpleSerializer
}

func NewTimedSerializer(secretKey []byte, signerOptions *SignerOptions, maxAge *time.Duration) Serializer {
    return &timedSerializer{&simpleSerializer{NewTimestampSigner(secretKey, signerOptions, maxAge)}}
}
