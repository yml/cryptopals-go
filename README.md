# cryptopals crypto challenges

This is my attempt to solve this crypto challenge in go.

http://cryptopals.com/

## Run the challenges

The challenges are implemented as tests. They are automatically verified when the result is given else I am printing out the solution that can be interpreted by the reader.

*Running all the challenges*

```
~/gopath/src/github.com/yml/cryptopals-go master 
yml@carbon$ go test -v . 
```

*Running one challenge*

```
yml@carbon$ go test -v . -run Test_challenge8_DetectAESInECBMode
=== RUN   Test_challenge8_DetectAESInECBMode
guessed line (0 based) =  132
--- PASS: Test_challenge8_DetectAESInECBMode (0.00s)
PASS
ok  	github.com/yml/cryptopals-go	0.006s
```

