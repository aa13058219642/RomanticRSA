# RomanticRSA

RomanticRSA allow you make a RSA key  by two string as password

## Usage
### Make a key
`newKey()` can make a key about the two password you give, the function like you use openSSL make Public Key and Private Key. Usually, it will take some minutes.


Example:
``` python

pw1 = 'password A'
pw2 = 'password B'
key = RomanticRSA.newKey(pw1, pw2)
print("key:", key)

>>>key: 190953634317571134441538613190194888593022
```

### Encrypt and decrypt
When you get the key, you can use this encrypt and decrypt you data.
- use password1 encrypt and use password2 decrypt
- use password2 encrypt and use password1 decrypt

Example:
``` python

    key = 190953634317571134441538613190194888593022
    msg = "hello world"
    print("message：", msg)

    en_msg = RomanticRSA.encrypt(msg, 'password A', key)
    print_byte(en_msg, "encrypted: ")

    de_msg = RomanticRSA.decrypt(en_msg, 'password B', key)
    print("decrypted: ", de_msg)

>>>message：hello world
>>>encrypted: b'lwmD2jj2JnzhPJ5pRcv3YgQ5gh7/X96voPkgpkhupp4='
>>>decrypted: hello world
```

## Algorithm description
### General RSA key

1. choose two big Prime number `p` and `q`
2. calculate `N=p*q`, `r=(p-1)*(q-1)`
3. set `e=65537`
4. calculate inverse(e^-1 (mod n)): `d=extended_gcd(e, N)`

Finally:
- (e, N) as password1 called Public Key.
- (d, N) as password2 called Private Key.


### Romantic RSA
In Romantic RSA, we reverse generation of RSA.

1. choose two prime number `e` and `d`
2. calculate `k = e*d-1`
3. get all divisors of k as set r
4. find a couple `p` and `q` fulfil follow conditions:
 - `p-1` and `q-1` include in r
 - `(p-1)*(q-1)=r`
 - `p` and `q` is prime number
5. calculate `N = p*q`

Finally:
- (e, N) as password1 called Public Key.
- (d, N) as password2 called Private Key.
Now, you know how to make key by two prime number `e` and `d`.

### Password to e, string to number
I use a simple way do this:
1. Calculate md5 of string
2. md5 is a hex number string, so its can convert to decimal number
3. find the first prime greater than this number

### Encrypt and decrypt
rsa only can encrypt few byte data. Encrypt long message always make a key encrypted message by AES and use RSA encrypted the key

### Warnning
In the RSA algorithm, asymmetry is based on the practical difficulty of the factorization of the product of two large prime numbers, this is the reason for RSA is safety.
This leads a big problem, the Romantic RSA is a NOT safety algorithm, when reverse generation of RSA key, we must get all divisors of k. For do this, we have to factorization `k`, if the `k` is big number, This will take a long time, so we just only choose two smaller numbers as `e` and `d`
For fast to make the key, I just choosed the 16 bytes number as key, but in RSA algorithm, the key usual 256 bytes and more.



