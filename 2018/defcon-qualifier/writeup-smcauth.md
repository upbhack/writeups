# Writeup smcauth from DEF CON CTF Qualifier 2018

## Challenge

We were given a binary [smcauth](smcauth) together with a verilog file [smcauth_syn.v](smcauth_syn.v) and a server address.
It can act as server:

```sh
./smcauth verify --secret aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --netlist smcauth_syn.v [--listen ip:port]
```

and client:

```sh
./smcauth auth --secret aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --netlist smcauth_syn.v [--verifier ip:port]
```

The client tells us whether the secret was "correct", or rather whether the circuit specified by `--netlist`
evaluates to true, taking the client's and server's secret as input.

```nohightlight
May 14 13:31:42.775 INFO authentication successful

May 14 13:31:57.274 WARN authentication failed
```

At this point, it is pretty obvious that we need to obtain the server's secret.

## Circuit

Let us take a look at the `smcauth_syn.v` file:

```verilog
/* Generated by Yosys 0.7 (git sha1 cc49ece, clang 6.0.0 -march=x86-64 -mtune=generic -O2 -fstack-protector-strong -fno-plt -fPIC -Os) */

(* top =  1  *)
(* src = "smcauth.v:3" *)
module smcauth(clk, rst, g_input, e_input, o);
  wire _0000_;
  wire _0001_;
  /* ... */
  wire _0685_;
  (* src = "smcauth.v:6" *)
  input clk;
  (* src = "smcauth.v:5" *)
  input [255:0] e_input;
  (* src = "smcauth.v:4" *)
  input [255:0] g_input;
  (* src = "smcauth.v:7" *)
  output o;
  (* src = "smcauth.v:6" *)
  input rst;
  NANDN _0686_ (
    .A(g_input[10]),
    .B(e_input[10]),
    .Z(_0200_)
  );
  ANDN _0687_ (
    .A(e_input[12]),
    .B(g_input[12]),
    .Z(_0201_)
  );
  /* ... */
  XOR _0694_ (
    .A(g_input[18]),
    .B(e_input[18]),
    .Z(_0208_)
  );
  OR _0695_ (
    .A(_0208_),
    .B(_0207_),
    .Z(_0209_)
  );
  /* ... */
  ANDN _1372_ (
    .A(_0199_),
    .B(_0538_),
    .Z(o)
  );
endmodule
```

Note that `A ANDN B = (not A) and B`.
Using `smcauth` with a simple custom circuit (see below), we can determine that `e_input` corresponds to the client's secret.
The secret's first byte corresponds to bits 0 to 7 where 7 is the lowest order bit.
The secret needs to be a valid UTF-8 string of 32 bytes.

```verilog
ANDN _1_ (
  .A(e_input[7]),
  .B(g_input[7]),
  .Z(o)
);
```

The following code generates a graph from the circuit:

```python
from graphviz import Digraph
import re

with open("smcauth_syn.v", "r") as f:
    v = f.read()

class Bit:
    def __init__(self, addr, name):
        self.addr = addr
        self.name = name
        self.val = False

    def __str__(self):
        return f"{self.name}[{self.addr}]"
        #return f"{self.name[0]}_{self.addr}"

    def value(self):
        return self.val


E_BITS = [Bit(i, "e_input") for i in range(256)]
G_BITS = [Bit(i, "g_input") for i in range(256)]

NAMES = {}
for b in E_BITS+G_BITS:
    NAMES[str(b)] = b

# We wrote logic to evaluate the circuit while still figuring out what the challenge was about
OPS = {
    "NANDN": lambda a, b: not (not a and b),
    "ANDN": lambda a, b: not a and b,
    "OR": lambda a, b: a or b,
    "XOR": lambda a, b: (a and not b) or (not a and b),
}

class Gate:
    def __init__(self, a, b, z, op, id):
        self.a_name = a
        self.b_name = b
        self.z_name = z
        self.a = None
        self.b = None
        self.z = None
        self.op = op
        self.id = id
        assert z not in NAMES
        NAMES[z] = self

    def setup(self):
        self.a = NAMES[self.a_name]
        self.b = NAMES[self.b_name]
        self.z = NAMES[self.z_name]
        assert self.a is not None and self.b is not None and self.z is not None

    def value(self):
        return OPS[self.op](self.a.value(), self.b.value())

    def __str__(self):
        return f"{self.z_name} = {self.a_name} {self.op} {self.b_name}  # {self.id}"


gates = []
v = v.replace("\n", "").replace(" ", "")

ID = 0

for op, id, a, b, z in re.findall(r"(OR|XOR|ANDN|NANDN)_(\d+)_\(\.A\(([^)]+)\),\.B\(([^)]+)\),\.Z\(([^)]+)\)\)", v):
    if "input" in a:   # for pretty graphs, make duplicate nodes for inputs used multiple times
        a += str(ID)
        b += str(ID)
        ID += 1
    gates.append(Gate(a, b, z, op, id))

dot = Digraph()

for g in gates:
    dot.node(g.z_name, f"{g.op} {g.id}")
    for n in (g.a_name, g.b_name):
        if "input" in n:
            label = n[:n.index("]")+1]
            dot.node(n, label)
    dot.edge(g.a_name, g.z_name, "A")
    dot.edge(g.b_name, g.z_name, "B")

dot.render("graph", view=True)
```

Looking at the [graph](graph.pdf), we can see that the circuit just checks whether both inputs are equal.
One interesting thing however is that most bits are compared with a single `XOR` gate
and the rest use two `ANDN` or `NANDN` gates which essentially correspond to logical implications.

## Crypto

At this point, we still do not how to get the flag.
What is interesting however is that both server and client need to specify a circuit.
If we change the client's circuit file, e.g. by using different inputs for a gate, we get an interesting error message:

```nohightlight
thread 'main' panicked at 'ERROR: evaluation error: unable to decrypt garbled table row', src/main.rs:185:9
note: Run with `RUST_BACKTRACE=1` for a backtrace.
```

A quick search for the phrase *garbled table* leads us to *Yao's Garbled Circuit*.
We used these [lecture notes](https://homepages.cwi.nl/~schaffne/courses/crypto/2014/presentations/Kostis_Yao.pdf)
to get an understanding of the construction.
Its purpose is to evaluate a logical circuit with inputs from two parties such that no party reveals its inputs.

In short, for each wire $w$ (including inputs and output), the server generates keys $k_w^0, k_w^1$, corresponding to values 0 and 1.
For each gate $g$ with inputs $a, b$ and output $z$, the server encrypts the gate's truth table.
A row with $a=i, b=j$ is encrypted to $E_{k_a^i \oplus k_b^j}(k_z^{g(i, j)} \circ pad)$ using a symmetric cipher.
Rows are shuffled randomly.
Note that different variations to this construction exist.

To evaluate the circuit, the server sends all garbled tables and its inputs to the client.
Using oblivious transfer, the client receives the keys for its inputs without learning 
anything about the keys for different inputs or revealing any information to the server.
To evaluate a gate, the client decrypts all rows of the garbled table and checks for correct padding.
The gates are evaluated in the order of a topolical sort.
The final output can then be compared to the server to determine its value.

## Exploit Idea

Garbled circuits are provably secure.
But only if they are not reused.
A quick comparison of two subsequent communications shows a large amount of duplication, hinting that
the server does not recompute the tables for each client.

Therefore, we invoke the server twice so that we obtain both keys for each bit.
In our case we use the characters `+` and `T` because the XOR of their charcodes is `0b01111111`.
We assume that the flag is ASCII and the highest order bit to therefore be 0.
Next, we will calculate all possible outputs for each gate, starting with the inputs.
We then have two possible output keys.
The correct output is the one that is different to the output obtained with the wrong secret.

Starting with the output gate, we recursively assign "correct" outputs to each gate until we arrive at the "leaf gates"
which receive the client's inputs.
We choose our inputs such that leaf gates give the correct output.

For example, if the want the last gate $g$ to output a key $k$, which it only outputs for inputs $k_1$ and $k_2$,
we need to ensure that the gates connected to $g$ output $k_1$ and $k_2$, respectively.
For those bits compared using `ANDN` (or `NANDN`), we only learn one output for one of the `ANDN` gates.
For all other gates, there is only one correct set of inputs (in the given circuit).

## Reversing

Now, we know how to get the flag, but we still need the keys and tables to do that.
We can obtain these by debugging the program.
A good starting point is the function printing the error message `unable to decrypt garbled table row`.
It is located at `0x555555582E70`.
Note that you may need to relocate the binary to `0x555555554000` in your reverse engineering tool.
We can immediately see that keys are xor'd and that AES 256 is used:

```c
v14 = _mm_xor_ps(v75[1], v6[1]);
v78 = (__int128)_mm_xor_ps(*v75, *v6);
v79 = v14;
v15 = j_EVP_aes_256_ecb(a1, a2);
```

The function contains a loop that iterates over the garbled table's rows and attempts to decrypt them.
Using *pwndbg*, we see that initially `rsi` points to a pointer to a string containing the current gate's name from the verilog file.
We need to take into account that strings in rust are not null-terminated.

We use radare2 and r2pipe to debug the binary from python.
We disable ASLR using `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space` to ensure that our breakpoints work.

The following code connects to the server and dumps all tables and keys.

```python
import r2pipe
import pickle

from Crypto.Cipher import AES

PADDING = bytes.fromhex("10"*16)

r2 = r2pipe.open("smcauth")

c = "T"  # execute also with c="+"
id_len = 6
r2.cmd(f"ood auth -s {c*32} -n smcauth_syn.v -v 13.57.20.216:8080")

r2.cmd("db 0x555555582EA6 DecryptTable")
r2.cmd("db 0x0000555555582ec7 RowAddress")
r2.cmd("db 0x555555582F19 CipherInit")

class TableInfo:
    def __init__(self, id, keys, xor_key, rows):
        self.keys = keys
        self.xor_key = xor_key
        self.rows = rows
        self.id = id

    def decrypt(self):
        for row in self.rows:
            aes = AES.new(self.xor_key, AES.MODE_ECB)
            dec = aes.decrypt(row)
            if dec.endswith(PADDING):
                return dec[:32]

    def __str__(self):
        rows = "\n".join("  " + r.hex() for r in self.rows)
        return f"id: {self.id}\nkey 1: {self.keys[0].hex()}\nkey 2: {self.keys[1].hex()}\nxor: {self.xor_key.hex()}\ntable:\n{rows}"


def cont():
    r2.cmd("dc")
    return r2.cmd("dbn").split(" ")[-1]


def addr_at(a):
    return hex(r2.cmdj(f"pxqj 8 @ {a}")[0])
    

tables = []

def dump_circuit():
    while cont() != "DecryptTable":
        pass
    id = int(r2.cmd(f"ps {id_len} @ " + addr_at("rsi"))[1:-1])

    assert cont() == "RowAddress"
    rows = []
    addr = r2.cmdj("drj")["rax"]
    for i in range(4):
        row_addr = addr_at(hex(addr + 8 * 3 * i))
        row = bytes(r2.cmdj("pxj 48 @ " + row_addr))  # like 0x555555582ECB in the binary 
        rows.append(row)

    assert cont() == "CipherInit"
    key1 = bytes(r2.cmdj("pxj 32 @ r12"))
    key2 = bytes(r2.cmdj("pxj 32 @ " + addr_at("rsp+0x138")))
    xor_key = bytes(r2.cmdj("pxj 32 @ rsp+0x150"))

    tables.append(TableInfo(id, (key1, key2), xor_key, rows))

for i in range(687):
    dump_circuit()  # invoke for each gate

for t in tables:
    print(t)
    print(t.decrypt().hex())  # ensure that all tables can be decrypted

pickle.dump(tables, open(f"tables_{c}.p", "wb"))
```

## Flag

Now we have all the information we need to get the flag.

```python
import pickle
from Crypto.Cipher import AES
import re


PADDING = bytes.fromhex("10"*16)


def decrypt_table(key, rows):
    for row in rows:
        aes = AES.new(key, AES.MODE_ECB)
        dec = aes.decrypt(row)
        # print(dec.hex())
        if dec.endswith(PADDING):
            return dec[:32]


def xor(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


# Beware the copy paste code...
class TableInfo:
    def __init__(self, id, keys, xor_key, rows):
        self.keys = keys
        self.xor_key = xor_key
        self.rows = rows
        self.id = id

    def decrypt(self):
        return decrypt_table(self.xor_key, self.rows)

    def __str__(self):
        rows = "\n".join("  " + r.hex() for r in self.rows)
        return f"id: {self.id}\nkey 1: {self.keys[0].hex()}\nkey 2: {self.keys[1].hex()}\nxor: {self.xor_key.hex()}\ntable:\n{rows}"


with open("smcauth_syn.v", "r") as f:
    v = f.read()


class Bit:
    def __init__(self, addr, name):
        self.addr = addr
        self.name = name
        self.val = False

    def __str__(self):
        return f"{self.name}[{self.addr}]"
        #return f"{self.name[0]}_{self.addr}"

    def value(self):
        return self.val


E_BITS = [Bit(i, "e_input") for i in range(256)]
G_BITS = [Bit(i, "g_input") for i in range(256)]

NAMES = {}
for b in E_BITS+G_BITS:
    NAMES[str(b)] = b


OPS = {
    "NANDN": lambda a, b: not (not a and b),
    "ANDN": lambda a, b: not a and b,
    "OR": lambda a, b: a or b,
    "XOR": lambda a, b: (a and not b) or (not a and b),
}

flag_bits = {}
def set_flag_bit(i, val):
    assert i not in flag_bits or flag_bits[i] == val
    flag_bits[i] = val

class Gate:
    def __init__(self, a, b, z, op, id):
        self.a_name = a
        self.b_name = b
        self.z_name = z
        self.a = None
        self.b = None
        self.inputs = None
        self.z = None
        self.op = op
        self.id = int(id)

        self.server_key = None
        self.client_keys = None
        self.client_input_idx = None
        self.rows = None
        self.output_set = None

        assert z not in NAMES
        NAMES[z] = self

    def setup(self):
        self.a = NAMES[self.a_name]
        self.b = NAMES[self.b_name]
        self.z = NAMES[self.z_name]
        self.inputs = (self.a, self.b)
        assert self.a is not None and self.b is not None and self.z is not None

    def value(self):
        return OPS[self.op](self.a.value(), self.b.value())

    def __str__(self):
        return f"{self.z_name} = {self.a_name} {self.op} {self.b_name}  # {self.id}"

    def is_leaf(self):
        return isinstance(self.a, Bit)

    def is_leaf8(self):
        return self.is_leaf() and self.a.addr % 8 == 0

    def calculate_outputs(self):
        """recursively compute the possible outputs keys for this gate with the current inputs"""
        if self.output_set is not None:
            return
        if self.is_leaf():
            if self.is_leaf8():
                output = decrypt_table(xor(self.server_key, self.client_keys[0]), self.rows)
                self.output_set = {output}
            else:
                self.output_set = {decrypt_table(xor(self.server_key, self.client_keys[i]), self.rows) for i in range(2)}
                if self.op == "XOR":
                    assert len(self.output_set) == 2
                elif self.op in ("NANDN", "ANDN"):
                    # For these gates, we could deduce inputs directly
                    # if len(self.output_set) == 1:
                    #     set_flag_bit(self.a.addr, self.client_input_idx)
                    # else:
                    #     set_flag_bit(self.a.addr, 1-self.client_input_idx)
                    pass
                else:
                    assert False
            assert None not in self.output_set
        else:
            self.a.calculate_outputs()
            self.b.calculate_outputs()
            self.output_set = set()
            for ka in self.a.output_set:
                for kb in self.b.output_set:
                    self.output_set.add(decrypt_table(xor(ka, kb), self.rows))
            assert len(self.output_set) in (1, 2) and None not in self.output_set

    def ensure_output(self, out):
        """ensure that this gate's output is out and set flag_bits accordingly"""
        if self.is_leaf():
            hits = 0
            hit_i = None
            for i in range(len(self.client_keys)):
                dec = decrypt_table(xor(self.server_key, self.client_keys[i]), self.rows)
                assert dec is not None
                if out == dec:
                    hit_i = i
                    hits += 1
            assert hits != 0
            if hits == 1:  # ignore those leaf gates that only give one output, we gain no information from them
                set_flag_bit(self.a.addr, hit_i)
        else:
            hit_a = None
            hit_b = None
            hits = 0
            for ka in self.a.output_set:
                for kb in self.b.output_set:
                    dec = decrypt_table(xor(ka, kb), self.rows)
                    assert dec is not None
                    if dec == out:
                        hit_a = ka
                        hit_b = kb
                        hits += 1
            assert hits == 1
            self.a.ensure_output(hit_a)
            self.b.ensure_output(hit_b)




gates = []
v = v.replace("\n", "").replace(" ", "")

ID = 0

for op, id, a, b, z in re.findall(r"(OR|XOR|ANDN|NANDN)_(\d+)_\(\.A\(([^)]+)\),\.B\(([^)]+)\),\.Z\(([^)]+)\)\)", v):
    gates.append(Gate(a, b, z, op, id))

leaf_gates = []
gates_by_id = {}

for g in gates:
    g.setup()
    gates_by_id[g.id] = g
    if g.is_leaf():
        leaf_gates.append(g)


def load_tables(name):
    tables = pickle.load(open(name, "rb"))
    tables = sorted(tables, key=lambda x: x.id)
    by_id = {}
    for t in tables:
        by_id[t.id] = t
    return tables, by_id


def one_at(bit):
    return 1 << (7 - bit)


def get_bit(byte, bit):
    return 1 if byte & one_at(bit) else 0


c1 = ord("+")
c2 = ord("T")
assert c1 ^ c2 == 0x7f
tables1, tables1_by_id = load_tables("tables_+.p")
tables2, tables2_by_id = load_tables("tables_T.p")
assert len(tables1) == len(tables2)

for t1, t2 in zip(tables1, tables1):
    assert t1.rows == t2.rows

for t in tables1 + tables2:
    assert t.decrypt() is not None

for g in leaf_gates:
    bit = g.a.addr % 8
    if bit == 0:
        set_flag_bit(g.a.addr, 0)
        continue
    t1 = tables1_by_id[g.id]
    t2 = tables2_by_id[g.id]
    for i in range(2):
        if t1.keys[i] == t2.keys[i]:
            j = 1-i
            assert t1.keys[j] != t2.keys[j]
            g.client_input_idx = i  # fix wrong order of inputs between TableInfo and Gate
            g.client_keys = (t1.keys[j], t2.keys[j])
            g.server_key = t1.keys[i]
            assert get_bit(c1, bit) != get_bit(c2, bit)
            assert g.inputs[g.client_input_idx].name[0] == "e"
            if get_bit(c1, bit) == 1:  # g.client_keys[i] should be the key corresponding to bit value i
                g.client_keys = g.client_keys[::-1]
            break
    else:
        assert False

for t in tables1:
    g = gates_by_id[t.id]
    g.rows = t.rows
    if g.is_leaf8():  # we only have the key for 0 for the hightest order bit
        g.server_key = t.keys[0]
        g.client_keys = (t.keys[1], )
        g.client_input_index = 0

for g in gates:
    g.calculate_outputs()

root = NAMES["o"]
root_false = tables1_by_id[1372].decrypt()

assert root_false == tables2_by_id[1372].decrypt()  # orginal output corresponds to false
assert root_false in root.output_set
assert len(root.output_set) == 2

root_true = list(root.output_set - {root_false})[0]
root.ensure_output(root_true)

flag = bytearray(32)
for i in range(255):
    if flag_bits[i]:
        flag[i//8] ^= one_at(i%8)
print(flag)
```

The code prints `OOO{m4by3_7ru57_1sn7_4lw4y5_b4d|`.
The correct flag is of course `OOO{m4by3_7ru57_1sn7_4lw4y5_b4d}`.
So our code gets bit 255 wrong. Oh well...