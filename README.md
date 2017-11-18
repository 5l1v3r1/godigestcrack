# godigestcrack

Golang implementation to assist in cracking captured digest headers. Example usage:

```
echo "Circle Of Life" | .\godigestcrack -resp 6629fae49393a05397450978507c4ef1 -usr Mufasa -realm testrealm@host.com -nonce dcd98b7102dd2f0e8b11d0f600bfb0c093 -uri /dir/index.html -cnonce 0a4f113b -workers 7

```