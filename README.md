# Attack on Diffie Hellman with Parameter Injection
Diffie Hellman works by exchanging two party's public keys and multiplying
the their public key's exponent with the exponent that is the private key.
The public key comes in the form g^b and the private key is simply a. This
entire operation occurs over the ringer of integers mod p, with p being a 
publicly known value. g is also a known value, but finding g^b mod p is 
very much a difficult task (confirm and insert link for discrete log here).
So by multiplying g^b mod p by a we get (g^b mod p)^a mod p. This is 
equivalent to g^(b\*a) mod p, which is unatanable by some advisary Eve. 
However, as is demonstrated here, simply replacing the public key with a
value known to eve will make the chosen session key deducible. This is
known as a "man in the middle" attack, the parameter we're injecting is
the stolen and swapped pubilic key.


## Installation and Execution
 *  If you don't have Rust, It's attainable with a simple cURL, and it's 
    actually quite a streamlined set of tools. 
    + `https://www.rust-lang.org/en-US/install.html`

 * If you do have Rust, simply clone the repo
    + `git clone git@gitlab.com:dejef/dh\_attack.git`

 * Change into the listener's directory
    + `cd alice/`

 * Run the listener on localhost port 7878 (RUST :)
    + `cargo run`

 + Change into the client's directory
    + `cd ../bob/`

 + Run the client
    + `cargo run`

## Understanding Results
If you followed the steps above you may notice three new files in `./bob/` 
These files are the public key, private key, and session key generated by 
the programs. Listing the contents of `../alice/` should show the same. 
(Display opposite public key) Alice's public key could have been printed
by Bob, and vice-versa. The priavte key however, would not be known. The
session key is what makes all this work worthwhile, and we can use it to 
generate a symmetric key for use with an different cryptographic protocol.

## Running Tests
TODO 

## Contributing
TODO

## Versioning 
There should be some tags and commit messages indicating a working program,
more specifically version v0.1.0 and v0.2.0 

# Licensing
Refer to the LICENSE file in the repo.

#Acknowledgments
 * Authors of Cryptopals
    + https://cryptopals.com/sets/5/challenges/34

 * Professor Bryant York 
    + http://web.cecs.pdx.edu/~york/

 * Rust documentation authors and Rust developers
    + https://doc.rust-lang.org/std/
