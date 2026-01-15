# Hose

Hose is like Unix pipes for the network.


## Installation

Download the latest [release](https://github.com/sam-rba/hose/releases/latest) from GitHub.
Unzip it and copy the executable to somewhere accessible on your `PATH`.


## Compiling on Linux/BSD/MacOS

### Requirements
- Go

### Instructions
1. Clone the repository: `git clone https://git.samanthony.xyz/hose`.
2. Move to the directory: `cd hose`.
3. Compile: `go build`.
4. Install: `go install`.
5. Add the executable to your path: `echo 'export PATH="$PATH:$HOME/go/bin"' >>~/.profile`.


## Usage

Suppose Alice wants to send a file to Bob over their local area network.
Alice's IP address is `10.0.0.12` and Bob's IP address is `10.0.0.34`.


### Key exchange

Hose uses public key cryptography for encryption and signing, so Alice and Bob must first exchange public keys by performing a _handshake_.
Alice runs `hose -handshake 10.0.0.34` on her machine, and Bob runs `hose -handshake 10.0.0.12` on his.

Hose uses two keys: an _encryption_ key and a _signing_ key.
They are both generated the first time Hose runs.
During the handshake, Hose asks Alice and Bob to verify that the public keys it received are correct.
For instance, Bob might see
```
bob@bar $ hose -handshake 10.0.0.12
...
Public encryption key key of host "10.0.0.12": 76769a010ffb2d153beec072acab97029d121efe571c3fac95d9ed9afcde2144
Is this the correct key (yes/[no])?
```
Bob should check with Alice that `76769a010ffb2d153beec072acab97029d121efe571c3fac95d9ed9afcde2144` is, in fact, her public encryption key.
It's best to do this in-person by writing the public key down on a piece of paper.
On Linux, the public encryption key (aka _box_ key) is located at `$HOME/.local/share/hose/box_pub.key`.
```
alice@foo $ cat ~/.local/share/hose/box_pub.key
76769a010ffb2d153beec072acab97029d121efe571c3fac95d9ed9afcde2144
```

Once Bob has confirmed that he received the genuine key, he answers "yes" to the prompt.
```
Public encryption key key of host "10.0.0.12": 76769a010ffb2d153beec072acab97029d121efe571c3fac95d9ed9afcde2144
Is this the correct key (yes/[no])?
yes
```

He is then asked to verify Alice's _public signature verification key_.
```
Public signature verification key key of host "10.0.0.12": b08b75c0ff2ce2ecbc348d253716b66b53d8ae44f3cf04610dad28281297241c
Is this the correct key (yes/[no])?
```
He should verify that it is correct, and answer "yes" if it is.
On Linux, the public signature verification key is located at `$HOME/.local/share/hose/sig_pub.key`.

Similarly, Alice should verify the keys she receives as well, to make sure they are really from Bob.


### File transfer

Once Alice and Bob have exchanged keys, they can use Hose to send data back and forth.

Suppose Alice wants to send a file, `hello.txt`, to Bob.

First, Bob must have Hose running with the `-r` flag, to _receive_ the file.
```
bob@bar $ hose -r
listening on :60321
```

Then Alice can _send_ the file with the `-s` flag.
```
alice@foo $ hose -s 10.0.0.34 <hello.txt
```

`hose -s` pipes data from stdin to the network, and `hose -r` pipes data from the network to stdout.
This means Alice could, for instance, redirect the output of a program to Hose, and Bob could receive it, pipe it to another program, and redirect it into a file.
```
bob@bar $ hose -r | head -n1 >msg.txt
```
```
alice@foo $ echo 'Hi, Bob!\n-Alice' | hose -s 10.0.0.34
```
```
bob@bar $ cat msg.txt
Hi, Bob!
```


