import binascii
import sys
import random
import hashlib
import base64

from sympy import divisors
from sympy.ntheory import isprime
from sympy import nextprime, sqrt, ceiling
from struct import pack
from Crypto.Cipher import AES


class RomanticRSA:
    _KEY_LENGTH = 16
    isDebug = False

    @staticmethod
    def newKey(password1, password2):
        if RomanticRSA.isDebug is True:
            print('start make key, it will take some minutes...')

        _, _, n, _, _, t = RomanticRSA._makeRSA(str(password1), str(password2))
        s = ''.join([str(1+int(i)) for i in oct(t)[2:]])
        key = n*10**(len(s)+1) + int(s)

        if RomanticRSA.isDebug is True:
            print('key=%d' % key)
        return key

    @staticmethod
    def encrypt(message, password, key):
        e, n = RomanticRSA._makeKey(password, key)

        kl = RomanticRSA._byte_size(n)
        if kl != RomanticRSA._KEY_LENGTH: raise OverflowError("kl=%d not 16" % kl)

        k = random.randint(n//2, n)
        encrypted = pow(k, e, n)
        encrypted_msg1 = RomanticRSA._int2bytes((~encrypted) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, kl)

        m = str(k)
        ak = m[:8*min(max(len(m)//8, 2), 4)].encode()
        msg = RomanticRSA._pad(message, AES.block_size).encode()
        aes = AES.new(ak, AES.MODE_CBC, encrypted_msg1)
        encrypted_msg2 = aes.encrypt(msg)
        en_msg = base64.b64encode(encrypted_msg1 + encrypted_msg2)

        if RomanticRSA.isDebug is True:
            print("# encrypt ------------------------------------")
            print("encrypt message:", message)
            print("e:", e)
            print("n:", n)
            print("k:", k)
            print("asekey:", ak)
            print_byte(encrypted_msg1, "rsa part:")
            print_byte(encrypted_msg2, "aes part:")
            print("en_msg:", en_msg)
            print("-------------------------------------")
        return en_msg

    @staticmethod
    def decrypt(encrypted_message, password, key):
        d, n = RomanticRSA._makeKey(password, key)

        encrypted_message = base64.b64decode(encrypted_message)
        encrypted_msg1 = encrypted_message[:RomanticRSA._KEY_LENGTH]
        encrypted_msg2 = encrypted_message[RomanticRSA._KEY_LENGTH:]

        encrypted = (~int(binascii.hexlify(encrypted_msg1), 16)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        k = pow(encrypted, d, n)
        m = str(k)
        ak = m[:8*min(max(len(m)//8, 2), 4)].encode()
        aes = AES.new(ak, AES.MODE_CBC, encrypted_msg1)
        msg = aes.decrypt(encrypted_msg2)
        message = RomanticRSA._unpad(msg)

        if RomanticRSA.isDebug is True:
            print("# decrypt ------------------------------------")
            print_byte(encrypted_msg1, "rsa part:")
            print_byte(encrypted_msg2, "aes part:")
            print("d:", d)
            print("n:", n)
            print("k:", k)
            print("asekey:", ak)
            print_byte(message, "decrypt message:")
            print("-------------------------------------")
        return message.decode()

    @staticmethod
    def _md5(s, times=1):
        m = s
        while times > 0:
            md5 = hashlib.md5()
            md5.update(m.encode())
            m = md5.hexdigest()[:RomanticRSA._KEY_LENGTH]
            times -= 1
        return m

    @staticmethod
    def _makeRSA(password1, password2):
        times = 0
        m1 = password1
        m2 = password2

        while 1:
            times = times + 1

            m1 = RomanticRSA._md5(m1)
            m2 = RomanticRSA._md5(m2)
            e = nextprime(int(m1, 16))
            d = nextprime(int(m2, 16))

            k = e*d - 1
            if RomanticRSA.isDebug is True: print("#%d k=%d" % (times, k))

            r = divisors(k)[1:][::-1][1:]
            k_sqrt = ceiling(sqrt(k))
            r1 = [i for i in r if i < k_sqrt and isprime(i + 1)]
            r2 = [(i + 1, k // i + 1) for i in r1 if isprime(k // i + 1)]
            if len(r2) == 0:
                continue

            p = r2[0][0]
            q = r2[0][1]
            N = p * q

            if RomanticRSA.isDebug is True:
                print("-------------------------------------")
                print("e: %s-> md5()*%d=%s-> int=%d-> nextprime=%d" % (password1, times, m1, int(m1, 16), e))
                print("d: %s-> md5()*%d=%s-> int=%d-> nextprime=%d" % (password2, times, m2, int(m2, 16), d))
                print("-------------------------------------")
                print("k=%d\nr=%s\nr1=%s\nr2=%s" % (k, r, r1, r2))
                print("p=%d\nq=%d\nn=%d" % (p, q, N))
                print("-------------------------------------")
            return p, q, N, e, d, times
        pass  # exit while

    @staticmethod
    def _makeKey(password, key):
        t = 0
        k = key
        while k % 10 != 0:
            t = t * 10 + k % 10 - 1
            k = k // 10
        e = nextprime(int(RomanticRSA._md5(password, int(str(t)[::-1], 8)), 16))
        n = k // 10
        return e, n

    @staticmethod
    def _pad(s, blick_size):
        return s + (blick_size - len(s) % blick_size) * chr(blick_size - len(s) % blick_size)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    @staticmethod
    def _byte_size(number):
        if number == 0:
            ret = 1
        else:
            try:
                num = number.bit_length()
            except AttributeError:
                raise TypeError('bit_size(num) only supports integers, not %r' % type(number))

            quanta, mod = divmod(num, 8)
            if mod:
                quanta += 1
            ret = quanta
        return ret

    @staticmethod
    def _int2bytes(number, fill_size=None, chunk_size=None):
        if number < 0: raise ValueError("Number must be an unsigned integer: %d" % number)
        if fill_size and chunk_size: raise ValueError("You can either fill or pad chunks, but not both")

        # Ensure these are integers.
        number & 1
        raw_bytes = b''

        # Pack the integer one machine word at a time into bytes.
        num = number
        word_bits, _, max_uint, pack_type = RomanticRSA._get_word_alignment(num)
        pack_format = ">%s" % pack_type
        while num > 0:
            raw_bytes = pack(pack_format, num & max_uint) + raw_bytes
            num >>= word_bits
        return raw_bytes

    @staticmethod
    def _get_word_alignment(num, force_arch=64, _machine_word_size=-1):
        MAX_INT = sys.maxsize
        MAX_INT64 = (1 << 63) - 1
        MAX_INT32 = (1 << 31) - 1
        MAX_INT16 = (1 << 15) - 1

        # Determine the word size of the processor.
        if _machine_word_size == -1:
            if MAX_INT == MAX_INT64: _machine_word_size = 64  # 64-bit processor.
            elif MAX_INT == MAX_INT32: _machine_word_size = 32  # 32-bit processor.
            else: _machine_word_size = 64 # Else we just assume 64-bit processor keeping up with modern times.

        max_uint64 = 0xffffffffffffffff
        max_uint32 = 0xffffffff
        max_uint16 = 0xffff
        max_uint8 = 0xff

        if force_arch == 64 and _machine_word_size >= 64 and num > max_uint32:
            # 64-bit unsigned integer.
            return 64, 8, max_uint64, "Q"
        elif num > max_uint16:
            # 32-bit unsigned integer
            return 32, 4, max_uint32, "L"
        elif num > max_uint8:
            # 16-bit unsigned integer.
            return 16, 2, max_uint16, "H"
        else:
            # 8-bit unsigned integer.
            return 8, 1, max_uint8, "B"


def print_byte(b, text=''):
    li = [hex(int(i)).replace('0x', '').zfill(2) + ' ' for i in b]
    print(text, "(%d Byte)" % len(li), "".join(li).upper())


if __name__ == '__main__':
    pw1 = 'password A'
    pw2 = 'password B'
    key = RomanticRSA.newKey(pw1, pw2)
    print("key:", key)

    msg = "hello world"
    print("message", msg)

    en_msg = RomanticRSA.encrypt(msg, pw1, key)
    print("encrypted:", en_msg)

    de_msg = RomanticRSA.decrypt(en_msg, pw2, key)
    print("decrypted:", de_msg)
