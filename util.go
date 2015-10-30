package itsdangerous

func IntToBytes(num int64) []byte {
    buf := make([]byte, 0, 8)
    for num > 0 {
        buf = append(buf, byte(num))
        num >>= 8
    }
    for i, j := 0, len(buf) - 1; i < j; i, j = i + 1, j - 1 {
        buf[i], buf[j] = buf[j], buf[i]
    }
    return buf
}

func BytesToInt(buf []byte) int64 {
    var num int64
    for _, b := range buf {
        num <<= 8
        num |= int64(b)
    }
    return num
}
