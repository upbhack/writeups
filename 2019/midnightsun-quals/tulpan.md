# Writeup Tulpan257 from Midnightsun CTF 2019 (Quals)

> We made a ZK protocol with a bit of HFS-flair to it!
> 
>> Correction of description, prover does not take a string, but a polynomial


chall.sage:

```python
flag = "XXXXXXXXXXXXXXXXXXXXXXXXX"
p = 257
k = len(flag) + 1

def prover(secret, beta=107, alpha=42):
    F = GF(p)
    FF.<x> = GF(p)[]
    r = FF.random_element(k - 1)
    masked = (r * secret).mod(x^k + 1)
    y = [
        masked(i) if randint(0, beta) >= alpha else
        masked(i) + F.random_element()
        for i in range(0, beta)
    ]
    return r.coeffs(), y

sage: prover(flag)

[141, 56, 14, 221, 102, 34, 216, 33, 204, 223, 194, 174, 179, 67, 226, 101, 79, 236, 214, 198, 129, 11, 52, 148, 180, 49]
[138, 229, 245, 162, 184, 116, 195, 143, 68, 1, 94, 35, 73, 202, 113, 235, 46, 97, 100, 148, 191, 102, 60, 118, 230, 256, 9, 175, 203, 136, 232, 82, 242, 236, 37, 201, 37, 116, 149, 90, 240, 200, 100, 179, 154, 69, 243, 43, 186, 167, 94, 99, 158, 149, 218, 137, 87, 178, 187, 195, 59, 191, 194, 198, 247, 230, 110, 222, 117, 164, 218, 228, 242, 182, 165, 174, 149, 150, 120, 202, 94, 148, 206, 69, 12, 178, 239, 160, 7, 235, 153, 187, 251, 83, 213, 179, 242, 215, 83, 88, 1, 108, 32, 138, 180, 102, 34]
```

Flag is given here as string, but it must be a polynomial.
We assume that the flag bytes are its coefficients.

The prover chooses a random polynomial $r$ of degree $k$ from $\mathbb F_p[x]$ (https://en.wikipedia.org/wiki/Polynomial_ring).
It chooses $masked = secret\times r\mod (x^k+1)$ and returns $r$ and $y$, where 
$$
y[i] = \begin{cases}
masked(i), &\text{with probability } (1-alpha/\beta)\approx 0.6\\
\text{random value}, & \text{else}
\end{cases}.
$$

Thus, if we choose $k$ random elements, the probability that they all are correct is $(1-\alpha/\beta)^{26}\approx 2\times 10^{-6}$.
We solve the challenge using bruteforce by choosing $k$ random points from $y$ and computing $masked$ with polynomial interpolation.
To obtain $secret$, we multiply $masked$ by $1/r$ in $\mathbb F_p[x]/(x^k+1)$ (Quotient ring).
The first $secret$ we get twice is the correct one with high probability.
In expectation, this happens after $\approx 10^6$ iterations.

```python
F = GF(p)
FF.<x> = GF(p)[]
FFF.<a> = FF.quotient_ring(x^k+1)

ri = 1/FFF(r)
assert (ri*r).mod(x^k+1) == 1

polys = set()
iy = list(enumerate(y))
while 1:
    points = random.sample(iy, 26)
    masked = FF.lagrange_polynomial(points)
    secret = (masked * ri).mod(x^k+1)
    coeffs = tuple(secret.list())
    if coeffs in polys:
        print coeffs
        break
    polys.add(coeffs)
```