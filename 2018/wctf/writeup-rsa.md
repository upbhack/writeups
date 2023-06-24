# Writeup rsa from WCTF 2018

## Challenge

Challenge was available at https://drive.google.com/open?id=17DOV0-3_TH3YPbMRSXpxugiHvHeTDQnn  (password: wctf2018, SHA1 HASH: 7efe988b1f9fe283e4f3d9bd073d1a97a93f51ee).

Readme:

```
Description:
Encrypted message for user "admin":

<<<320881698662242726122152659576060496538921409976895582875089953705144841691963343665651276480485795667557825130432466455684921314043200553005547236066163215094843668681362420498455007509549517213285453773102481574390864574950259479765662844102553652977000035769295606566722752949297781646289262341623549414376262470908749643200171565760656987980763971637167709961003784180963669498213369651680678149962512216448400681654410536708661206594836597126012192813519797526082082969616915806299114666037943718435644796668877715954887614703727461595073689441920573791980162741306838415524808171520369350830683150672985523901>>>

admin public key:

n = 483901264006946269405283937218262944021205510033824140430120406965422208942781742610300462772237450489835092525764447026827915305166372385721345243437217652055280011968958645513779764522873874876168998429546523181404652757474147967518856439439314619402447703345139460317764743055227009595477949315591334102623664616616842043021518775210997349987012692811620258928276654394316710846752732008480088149395145019159397592415637014390713798032125010969597335893399022114906679996982147566245244212524824346645297637425927685406944205604775116409108280942928854694743108774892001745535921521172975113294131711065606768927
e = 65537

Service: http://36.110.234.253
```
<!--more-->

## Obtaining the binary

The IP leads to a website where we can register and download some RSA key generator software.
The software is different for each user and requests a license file parameter.
However, the license functionality on the website was "disabled".
We can get the admin's version of the software by logging in as admin with an arbitary passwords since the website does not seem to actually check the password.

## Decrypting the binary

Analysis of the (stripped) binary reveals that it decrypts static data using the license key (32 bytes) and saves the result as `out.exe`.
Decryption is done using a stream cipher where the keystream is generated using repeated sha256, i.e. `k[0:32] == sha256(license), k[32:64] == sha256(k[0:32]), ...`.
Afterwards, `out.exe` is started with the license file as parameter.

The tool [`sigsrch`](http://aluigi.altervista.org/mytoolz.htm) was helpful in identifying the hash algorithm and its functions in the binary.

Since a binary is generated, we can expect the first 32 bytes to be equal to those of the first binary.
Then we get the first block of the keystream from which we can calculate all following blocks.

```python
from pwn import *
from hashlib import sha256

# extraced in debugger
encrypted_start = 0x3e09
encrypted_size = 0x14200

with open("ga.exe", "rb") as f:
    gen = f.read()

enc = gen[encrypted_start + 32:encrypted_start + 32 + encrypted_size]
k = xor(enc[:32], gen[:32])

ps = []
for i in range(0, encrypted_size, 32):
    ps.append(xor(k, enc[i:i + 32]))
    k = sha256(k).digest()

p = "".join(ps)

# first 32 bytes of ciphertext are sha256 over plaintext
assert sha256("".join(ps)).digest() == gen[encrypted_start:encrypted_start+32]
with open("out.exe", "wb") as f:
    f.write(p)
```

## Key generation

Again with the help of `sigsrch`, we reverse the key generation algorithm (Python-like pseudocode):

```python
key = license #split into 8 32 bit integers
nums = [...] #8 random 32 bit integers, unique for each user
m = 10**9+7
key_i = 0;

def random_64_bytes():
    t = (time(0) + key[key_i]) % m
    key_i += 1
    if key_i == 8:
        key_i = 0
        key = sha512(key)[:32] #still treated as 8 integers
    return sha512(nums + t) # effectively only log(m) bit entropy

def random_prime():
    p = int(random_64_bytes() + random_64_bytes()) #1024 bit, treat bytes as big endian
    while not is_prime(p):
        p = int(random_64_bytes() + random_64_bytes())

p = random_prime()
q = random_prime()
N = p * q
```

## Factorization

Given $N$ and $p'$ with $|p-p'| \le 2^k$, it holds that $|N/p-q| \le 2^k$.
We can create a table of all possible upper 8 bytes of $p$ together with their $t$ value (see `random_64_bytes`) (roughly 12 GB).
For fast lookup, we sort the table by the $p'$ bytes.
Additionaly, we create a bitvector which contains a 1 at position $i$ iff $i$ corresponds to the first four bytes of a $p'$.

For each possibility $p'$, we check if the upper 8 bytes of $q' := N/p'$ are correct.
The lookup for $q'$ is done using binary search.
The bitvector is used to skip the binary search in most cases and therefore drastically reduce the number of cache misses (that was probably premature optimization, but I wanted to see the performance difference...).

We now can get the first 64 bytes of $p$ and $q$:

```cpp
#include <iostream>
#include <cstdint>
#include <iomanip>
#include <cstdio>
#include <thread>
#include <mutex>
#include <openssl/sha.h>
#include <algorithm>
#include <vector>

constexpr const uint32_t nums[] = { // extraced from binary
        0x0E576698C,
        0x0150441B5,
        0x0BD08E9BD,
        0x0DF15EE4D,
        0x0C8A967B1,
        0x0B84BFC73,
        0x02A6F1FA8,
        0x018A948B4,
};

constexpr const uint32_t m = 0x3B9ACA07;
constexpr const size_t thread_num = 8;

typedef unsigned __int128 uint128_t;
constexpr const uint128_t N = (((uint128_t)0x03d54efad73f9e99) << 64u) + 0xbc6b8156d3c589d6;

struct __attribute__ ((packed)) Candidate {
    uint64_t p;
    uint32_t t;
    bool operator<(const Candidate& rhs) const { return p < rhs.p; }
};

Candidate *candidates;
uint8_t *bitvec;
constexpr const size_t bitvec_size = 1u << 29u;
std::mutex io_mtx;

void save_candidates() {
    FILE* f = fopen("candidates.bin", "wb");
    fwrite(candidates, sizeof(Candidate), m, f);
    fclose(f);
}

void load_candidates() {
    FILE* f = fopen("candidates.bin", "rb");
    fread(candidates, sizeof(Candidate), m, f);
    fclose(f);
}

void hash_thread(uint32_t lo, uint32_t hi) {
    uint32_t buf[9];
    uint8_t digest[64];
    std::copy(nums, nums+8, buf);

    for (uint32_t i = lo; i < hi; ++i) {
        if ((i & 0xffffff) == 0) {
            std::lock_guard<std::mutex> l(io_mtx);
            printf("hash %x\n", i);
        }

        buf[8] = i;
        SHA512((uint8_t *)buf, 36, digest);

        auto& c = candidates[i];
        c.t = i;
        c.p = __builtin_bswap64(*(uint64_t*)digest); // big endian!
    }
}

void generate_candidates() {
    puts("generate");
    std::vector<std::thread> threads;
    uint32_t batch_size = m / thread_num + thread_num;
    for (uint32_t i = 0; i < thread_num; ++i) {
        threads.emplace_back(hash_thread, i * batch_size, std::min(m, (i+1) * batch_size));
    }

    for (auto& thread : threads) {
        thread.join();
    }

    puts("sort");
    std::sort(candidates, candidates+m);

    puts("save");
    save_candidates();
}

uint32_t find_candidate(uint64_t p) {
    auto prefix = p >> 32u;
    if (!(bitvec[prefix / 8] & (1u << (prefix % 8)))) {
        return m;
    }

    size_t lo = 0, hi = m - 1;
    while (lo <= hi) {
        auto mid = (lo + hi) / 2;
        auto &c = candidates[mid];
        if (c.p < p) {
            lo = mid + 1;
        } else if (c.p > p) {
            if (mid == 0) break;
            hi = mid - 1;
        } else {
            return c.t;
        }
    }
    return m;
}

bool check_candindate(const Candidate& c) {
    auto q = (uint64_t) (N / ((uint128_t)c.p)); //we only need 128 bits of N to get the first 64 bit of q
    auto i = find_candidate(q);
    if (i < m) {
        std::lock_guard<std::mutex> l(io_mtx);
        printf("p: %llx t: %u q: %llx t: %u\n", c.p, c.t, q, i); // later reconstruct all 512 bits of p and q from the t values
        return true;
    }
    return false;
}

void generate_bitvector() {
    puts("generate bitvector");
    std::fill(bitvec, bitvec+bitvec_size, 0);
    for (size_t i = 0; i < m; ++i) {
        auto prefix = candidates[i].p >> 32u;
        bitvec[prefix / 8] |= 1u << (prefix % 8);
    }
}

void search_thread(uint32_t lo, uint32_t hi) {
    uint32_t buf[9];
    uint8_t digest[64];
    std::copy(nums, nums+8, buf);

    for (uint32_t i = lo; i < hi; ++i) {
        if ((i & 0xffffff) == 0) {
            std::lock_guard<std::mutex> l(io_mtx);
            printf("search %x\n", i);
        }

        check_candindate(candidates[i]);
    }
}

void search() {
    puts("search");
    std::vector<std::thread> threads;
    uint32_t batch_size = m / thread_num + thread_num;
    for (uint32_t i = 0; i < thread_num; ++i) {
        threads.emplace_back(search_thread, i * batch_size, std::min(m, (i+1) * batch_size));
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

int main() {
    candidates = new Candidate[m];
    bitvec = new uint8_t[bitvec_size];
    // generate_candidates();

    load_candidates();
    generate_bitvector();

    search();
}
```

Theoretically, we should now be able to factor $N$ using Coppersmith's attack, but I was not able to implement that successfully.
Instead, we use the previous approach to bruteforce the lower half of $p$.

```cpp
void search_thread(uint32_t lo, uint32_t hi) {
    uint32_t buf[9];
    uint8_t digest[128];
    mpz_t p, r, n;

    mpz_set_str(n, "483901264006946269405283937218262944021205510033824140430120406965422208942781742610300462772237450489835092525764447026827915305166372385721345243437217652055280011968958645513779764522873874876168998429546523181404652757474147967518856439439314619402447703345139460317764743055227009595477949315591334102623664616616842043021518775210997349987012692811620258928276654394316710846752732008480088149395145019159397592415637014390713798032125010969597335893399022114906679996982147566245244212524824346645297637425927685406944205604775116409108280942928854694743108774892001745535921521172975113294131711065606768927", 10);
    mpz_init2(p, 1024);
    mpz_init2(r, 1024);

    std::copy(nums, nums+8, buf);

    buf[8] = 769339107; //t value for p
    SHA512((uint8_t *)buf, 36, digest);

    for (uint32_t i = lo; i < hi; ++i) {
        if ((i & 0xffffff) == 0) {
            std::lock_guard<std::mutex> l(io_mtx);
            printf("hash %x\n", i);
        }

        buf[8] = i;
        SHA512((uint8_t *)buf, 36, digest+64);

        mpz_import(p, 128, 1, sizeof(uint8_t), 0, 0, digest);
        mpz_mod(r, n, p);
        if (mpz_sgn(r) == 0) {
            std::lock_guard<std::mutex> l(io_mtx);
            gmp_printf("%Zx\n", p);
        }
    }

    mpz_clear(p);
    mpz_clear(r);
    mpz_clear(n);
}
```

Finally, we get $p$ and can decrypt the message:

```python
n = 483901264006946269405283937218262944021205510033824140430120406965422208942781742610300462772237450489835092525764447026827915305166372385721345243437217652055280011968958645513779764522873874876168998429546523181404652757474147967518856439439314619402447703345139460317764743055227009595477949315591334102623664616616842043021518775210997349987012692811620258928276654394316710846752732008480088149395145019159397592415637014390713798032125010969597335893399022114906679996982147566245244212524824346645297637425927685406944205604775116409108280942928854694743108774892001745535921521172975113294131711065606768927
c = 320881698662242726122152659576060496538921409976895582875089953705144841691963343665651276480485795667557825130432466455684921314043200553005547236066163215094843668681362420498455007509549517213285453773102481574390864574950259479765662844102553652977000035769295606566722752949297781646289262341623549414376262470908749643200171565760656987980763971637167709961003784180963669498213369651680678149962512216448400681654410536708661206594836597126012192813519797526082082969616915806299114666037943718435644796668877715954887614703727461595073689441920573791980162741306838415524808171520369350830683150672985523901
e = 65537

p = 0x316d178262ba16c320787a0acc4cffcd704c12751f70422e2eeedd078634a50f6014b1bd3e9da6e41e76ca521656882d50447d90e244051f4970d4d65594ed348e5e10dac0799b63d818be541550fdb77ea4203a3d921dcc114a9e2b8afefad7eff38f3b1575c4cd8bc182f7b8adc61ede42f135c02e618a9c63259ccab14e0b
q = n / p

d = gmpy2.invert(e, (p-1)*(q-1))
m = pow(c, d, n)

print unhex(hex(m)[2:]) # flag{fa6778724ed740396fc001b198f30313}
```