ngx_cipher
=========
# cipher library
```lua
	require "cipher"
```
## md5
```lua
	cipher.md5('data')
```
## sha1
```lua
	cipher.sha1('data')
```
## sha256
```lua
	cipher.sha256('data')
```
## sha512
```lua
	cipher.sha512('data')
```
# Testing
```bash
curl -g "http://127.0.0.1:8000/cipher?data=123&t=md5"
curl -g "http://127.0.0.1:8000/cipher?data=123&t=sha1"
curl -g "http://127.0.0.1:8000/cipher?data=123&t=hmac_sha1"
curl -g "http://127.0.0.1:8000/cipher?data=123&t=hmac_sha1"
curl -g "http://127.0.0.1:8000/cipher?data=123&t=md5"
curl -g "http://127.0.0.1:8000/cipher?data=123&t=sha1"
curl -g "http://127.0.0.1:8000/cipher?data=123&t=sha256"
curl -g "http://127.0.0.1:8000/cipher?data=123&t=sha512"
curl -g "http://127.0.0.1:8000/cipher?data=123&key=key&t=hmac_md5"
```
