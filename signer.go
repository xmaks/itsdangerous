package itsdangerous

import (
    "bytes"
    "crypto/sha1"
    "encoding/base64"
    "hash"
    "time"
)

const (
    EPOCH = 1293840000
)

type Signer interface {
    Sign([]byte) ([]byte, error)
    Unsign([]byte) ([]byte, error)
    Validate([]byte) error
}

type SignerOptions struct {
    Separator []byte
    Salt []byte
    HashType func() hash.Hash
    SignatureAlgorithm SignatureAlgorithm
    KeyDerivator KeyDerivator
}

type simpleSigner struct {
    secretKey []byte
    options *SignerOptions
}

func NewSimpleSigner(secretKey []byte, options *SignerOptions) Signer {
    if options == nil {
        options = &SignerOptions{}
    }

    if options.Separator == nil || len(options.Separator) == 0 {
        options.Separator = []byte{'.'}
    }

    if options.Salt == nil || len(options.Salt) == 0 {
        options.Salt = []byte("itsdangerous.Signer")
    }

    if options.HashType == nil {
        options.HashType = sha1.New
    }

    if options.SignatureAlgorithm == nil {
        options.SignatureAlgorithm = NewHmacSignatureAlgorithm(options.HashType)
    }

    if options.KeyDerivator == nil {
        options.KeyDerivator = NewDjangoConcatKeyDerivator(options.HashType)
    }

    return &simpleSigner{secretKey, options}
}

func (this *simpleSigner) Sign(unsignedValue []byte) ([]byte, error) {
    signature, err := this.getSignature(unsignedValue)
    if err != nil {
        return nil, err
    }
    return this.bytesJoin(unsignedValue, signature), nil
}

func (this *simpleSigner) Unsign(signedValue []byte) ([]byte, error) {
    unsignedValue, signature := this.bytesSplit(signedValue)
    if signature == nil {
        return nil, NewBadDataError("no signature found")
    }

    if err := this.verifySignature(unsignedValue, signature); err != nil {
        return nil, err
    }

    return unsignedValue, nil
}

func (this *simpleSigner) Validate(signedValue []byte) error {
    _, err := this.Unsign(signedValue)
    return err
}

func (this *simpleSigner) getSignature(value []byte) ([]byte, error) {
    key, err := this.options.KeyDerivator.DeriveKey(this.secretKey, this.options.Salt)
    if err != nil {
        return nil, err
    }

    signatureBytes, err := this.options.SignatureAlgorithm.GetSignature(key, value)
    if err != nil {
        return nil, err
    }

    return this.base64Encode(signatureBytes)
}

func (this *simpleSigner) verifySignature(unsignedValue, signature []byte) error {
    key, err := this.options.KeyDerivator.DeriveKey(this.secretKey, this.options.Salt)
    if err != nil {
        return err
    }

    signatureBytes, err := this.base64Decode(signature)
    if err != nil {
        return err
    }

    return this.options.SignatureAlgorithm.VerifySignature(key, unsignedValue, signatureBytes)
}

func (this *simpleSigner) base64Encode(value []byte) ([]byte, error) {
    result := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
    base64.RawURLEncoding.Encode(result, value)
    return result, nil
}

func (this *simpleSigner) base64Decode(value []byte) ([]byte, error) {
    result := make([]byte, base64.RawURLEncoding.DecodedLen(len(value)))
    n, err := base64.RawURLEncoding.Decode(result, value)
    if err != nil {
        return nil, err
    }
    return result[:n], nil
}

func (this *simpleSigner) bytesJoin(value... []byte) []byte {
    return bytes.Join(value, this.options.Separator)
}

func (this *simpleSigner) bytesSplit(value []byte) ([]byte, []byte) {
    idx := bytes.LastIndex(value, this.options.Separator)
    if idx == -1 {
        return value, nil
    }
    return value[:idx], value[idx + len(this.options.Separator):]
}

type timestampSigner struct {
    *simpleSigner
    maxAge *time.Duration
}

func NewTimestampSigner(secretKey []byte, options *SignerOptions, maxAge *time.Duration) Signer {
    return &timestampSigner{NewSimpleSigner(secretKey, options).(*simpleSigner), maxAge}
}

func (this *timestampSigner) Sign(unsignedValue []byte) ([]byte, error) {
    timestamp, err := this.simpleSigner.base64Encode(IntToBytes(this.getTimestamp()))
    if err != nil {
        return nil, err
    }

    return this.simpleSigner.Sign(this.simpleSigner.bytesJoin(unsignedValue, timestamp))
}

func (this *timestampSigner) Unsign(signedValue []byte) ([]byte, error) {
    timestampedValue, err := this.simpleSigner.Unsign(signedValue)
    if err != nil {
        return nil, err
    }

    unsignedValue, timestampSignature := this.simpleSigner.bytesSplit(timestampedValue)
    if timestampSignature == nil {
        return nil, NewBadTimestampSignatureError("no timestamp found")
    }

    timestampBytes, err := this.base64Decode(timestampSignature)
    if err != nil {
        return nil, err
    }

    timestamp := this.timestampToTime(BytesToInt(timestampBytes))
    if this.maxAge != nil && time.Since(*timestamp).Seconds() > this.maxAge.Seconds() {
        return nil, NewBadTimestampSignatureError("signature expired")
    }

    return unsignedValue, nil
}

func (this *timestampSigner) Validate(signedValue []byte) error {
    _, err := this.Unsign(signedValue)
    return err
}

func (this *timestampSigner) getTimestamp() int64 {
    return time.Now().Unix() - EPOCH
}

func (this *timestampSigner) timestampToTime(timestamp int64) *time.Time {
    time := time.Unix(timestamp + EPOCH, 0)
    return &time
}
