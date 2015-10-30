package itsdangerous

import (
    "fmt"
)

type BadDataError struct {
    Message string
}

func NewBadDataError(message string) error {
    return &BadDataError{message}
}

func (this *BadDataError) Error() string {
    return fmt.Sprintf("itsdangerous: bad data - %s", this.Message)
}

type BadSignatureError struct {
    Signature []byte
}

func NewBadSignatureError(signature []byte) error {
    return &BadSignatureError{signature}
}

func (this *BadSignatureError) Error() string {
    return fmt.Sprintf("itsdangerous: bad signature - %v", this.Signature)
}

type BadTimestampSignatureError struct {
    Message string
}

func NewBadTimestampSignatureError(message string) error {
    return &BadTimestampSignatureError{message}
}

func (this *BadTimestampSignatureError) Error() string {
    return fmt.Sprintf("itsdangerous: bad timestamp signature - %s", this.Message)
}
