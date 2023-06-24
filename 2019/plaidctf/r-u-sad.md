# Writeup "R u SAd?" from PlaidCTF 2019

Description:

> Tears dripped from my face as I stood over the bathroom sink. Exposed again! The tears melted into thoughts, and an idea formed in my head. [This](https://play.plaidctf.com/files/rusad_ece608061c4dd2d74b6011a5c7a7f83d.zip) will surely keep my secrets safe, once and for all. I crept back to my computer and began to type.

We are given a relatively long python script implementing RSA encryption, together with a public key and an encrypted file.
They use a custom key format which is saved using the pickle module:

```python
class Key:
    PRIVATE_INFO = ['P', 'Q', 'D', 'DmP1', 'DmQ1']

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        assert self.bits % 8 == 0

    def ispub(self):
        return all(not hasattr(self, key) for key in self.PRIVATE_INFO)

    def ispriv(self):
        return all(hasattr(self, key) for key in self.PRIVATE_INFO)

    def pub(self):
        p = deepcopy(self)
        for key in self.PRIVATE_INFO:
            if hasattr(p, key):
                delattr(p, key)
        return p

    def priv(self):
        raise NotImplementedError()

def genkey(bits):
    assert bits % 2 == 0
    while True:
        p = genprime(bits // 2)
        q = genprime(bits // 2)
        e = 65537
        d, _, g = egcd(e, (p - 1) * (q - 1))
        if g != 1: continue
        iQmP, iPmQ, _ = egcd(q, p)
        return Key(
            N=p * q, P=p, Q=q, E=e, D=d % ((p - 1) * (q - 1)), DmP1=d % (p - 1), DmQ1=d % (q - 1),
            iQmP=iQmP % p, iPmQ=iPmQ % q, bits=bits,
        )
```

Notice that the values `iPmQ` and `iQmP` are not removed when constructing the public key.
Let us call these values $a$ and $b$ in the following.
If $a', b'=egcd(p, q)$, then $a'p+b'q=gcd(p,q)$ by [Bézout's identity](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity).
Hence, 
$$
\begin{aligned}
    \quad (a+iq)p + (b+jp)q &= 1\\
    \Rightarrow ap+bq+(i+j)pq &= 1\\\
    \Rightarrow ap+bq=1+zn&=:c
\end{aligned}
$$
for small values $i,j,z\in \mathbb Z$.

Let $x, y = egcd(a, b)$. Since $gcd(a, b)=1$ (in our case), we have

$$
\begin{aligned}
\quad ap+bq&=1+zn=c\\
\quad ax+by&=1\\
\Rightarrow a(p-xc)+b(q-yc) &= 0\qquad \text{(subtract the second equation $c$ times from the first)}\\
\Rightarrow a(p-xc) &= b(yc-q)\\
\Rightarrow (q-yc) &\equiv 0 \mod a\\
\Rightarrow q-yc&=ka
\end{aligned}
$$

We can expect $q/a$ to be small.
Hence, $k\approx -yc/a$.
Then, $q=ka+yc$.

## Code

```python
a = k.iPmQ
b = k.iQmP
n = k.N

x, y, _ = egcd(a, b)

for z in range(-10, 10):
    c = 1 + z*n
    for k in range(-y*c//a-10, -y*c//a+10):
        q = k*a + y*c
        if n % q == 0:
            print(q, n//q)
```