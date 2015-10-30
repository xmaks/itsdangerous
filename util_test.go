package itsdangerous

import (
    "bytes"
    "math"
    "testing"
)

func TestIntToBytes(t *testing.T) {
    var i int64

    i = BytesToInt(IntToBytes(0))
    if i != 0 {
        t.Errorf("%d != %d", i, 0)
    }

    i = BytesToInt(IntToBytes(math.MaxInt64 / 2))
    if i != math.MaxInt64 / 2 {
        t.Errorf("%d != %d", i, math.MaxInt64 / 2)
    }

    i = BytesToInt(IntToBytes(math.MaxInt64))
    if i != math.MaxInt64 {
        t.Errorf("%d != %d", i, math.MaxInt64)
    }
}

func TestBytesToInt(t *testing.T) {
    b1 := []byte{127, 255, 255, 255, 255, 255, 255, 255}
    b2 := IntToBytes(BytesToInt(b1))
    if bytes.Compare(b1, b2) != 0 {
        t.Errorf("%d != %d", b1, b2)
    }
}
