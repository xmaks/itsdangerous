package itsdangerous

import (
    "crypto/sha1"
    "testing"
    "time"
)

func TestSimpleSerializer(t *testing.T) {
    key := []byte("itsdangerous.Key")
    options := SignerOptions{
        Separator:[]byte("."),
        Salt: []byte("itsdangerous.Salt"),
        HashType: sha1.New,
        KeyDerivator: NewHmacKeyDerivator(sha1.New),
        SignatureAlgorithm: NewHmacSignatureAlgorithm(sha1.New),
    }
    serializer := NewSimpleSerializer(key, &options)

    value := struct{
        UserId int `json:"user_id"`
        UserName string `json:"user_name"`
    }{2015, "itsdangorous"}

    serialized, err := serializer.Marshal(&value)
    if err != nil {
        t.Errorf(err.Error())
    }

    loadedValue := struct{
        UserId int `json:"user_id"`
        UserName string `json:"user_name"`
    }{}

    err = serializer.Unmarshal(serialized, &loadedValue)
    if err != nil {
        t.Errorf(err.Error())
    }

    if loadedValue.UserId != value.UserId || loadedValue.UserName != loadedValue.UserName {
        t.Errorf("%v != %v", loadedValue, value)
    }
}


func TestTimedSerializer(t *testing.T) {
    key := []byte("itsdangerous.Key")
    options := SignerOptions{
        Separator:[]byte("."),
        Salt: []byte("itsdangerous.Salt"),
        HashType: sha1.New,
        KeyDerivator: NewHmacKeyDerivator(sha1.New),
        SignatureAlgorithm: NewHmacSignatureAlgorithm(sha1.New),
    }
    maxAge := time.Duration(60 * time.Second)
    serializer := NewTimedSerializer(key, &options, &maxAge)

    value := struct{
        UserId int `json:"user_id"`
        UserName string `json:"user_name"`
    }{2015, "itsdangorous"}

    serialized, err := serializer.Marshal(&value)
    if err != nil {
        t.Errorf(err.Error())
    }

    loadedValue := struct{
        UserId int `json:"user_id"`
        UserName string `json:"user_name"`
    }{}

    err = serializer.Unmarshal(serialized, &loadedValue)
    if err != nil {
        t.Errorf(err.Error())
    }

    if loadedValue.UserId != value.UserId || loadedValue.UserName != loadedValue.UserName {
        t.Errorf("%v != %v", loadedValue, value)
    }
}
