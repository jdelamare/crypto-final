#![feature(no_panic_pow)]
extern crate num_bigint;
extern crate num_traits;
extern crate rand;

use num_bigint::{BigUint, RandomBits};
use num_traits::{Zero, One};
use rand::Rng;
use std::fs;
use std::io::prelude::*;
use std::net::TcpStream;

fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:7878").unwrap();
    create_priv_key();
    create_pub_key();
    connect(stream);
    // should check to see that the session key file has been created
    create_session_key();
}

fn connect(mut stream: TcpStream) {
    // create a buffer for the response 
    let mut response = [0;1024];
    // read the public key from file into request
    let request = fs::read_to_string("pub_key").unwrap();
    // send the request to the stream  *
    stream.write(request.as_bytes()).unwrap();
    // the stream carries the response back into response buffer
    stream.read(&mut response);
    let mut their_pub_key = String::from_utf8_lossy(&response[..]).to_string();
    sanitize_data_buffer(&mut their_pub_key);
    // write the response to file. session key partially created
    fs::write("session_key", their_pub_key); //STRING
}

fn create_pub_key() {
    // create the generator point
    let g: Vec<u32> = vec![2;1]; // BigUint represents nums in radix 2^32
    let g: BigUint = BigUint::new(g);
    // define the modulus size
    let p: BigUint = BigUint::from_bytes_le(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc740\
             20bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f\
             e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee3\
             86bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da\
             48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52\
             9077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
             .as_bytes());
    // attempt to parse the private key file
    let a = fs::read_to_string("priv_key").unwrap();
    match u32::from_str_radix(&a, 10) {
        Ok(a) => {
            let a: Vec<u32> = vec![a;1]; // BigUint represents nums in radix 2^32
            let a: BigUint = BigUint::new(a);
            let A = g.modpow(&a, &p);    // Create public key A
            fs::write("pub_key", format!("{:?}",A));
            //sanitize_big_num("pub_key");
            //panic!();
        },
        _ => panic!("create pub key")
    }
    /*
    match a.parse::<u32>() {
        Ok(a) => {
            let pub_key = g.wrapping_pow(a) % p;
            println!("pub_key: {:?}", pub_key);
            fs::write("pub_key", pub_key.to_string());
        },
        _ => panic!("create pub key")
    }*/
}

fn create_priv_key() {
    let mut rng = rand::thread_rng();
    let a: BigUint = rng.sample(RandomBits::new(32));
    fs::write("priv_key", a.to_str_radix(10)); // TODO: Keep it all in 2^32?
}

fn create_session_key() { 
    // need another copy of mod 
    let p: BigUint = BigUint::from_bytes_le(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc740\
             20bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f\
             e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee3\
             86bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da\
             48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52\
             9077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
             .as_bytes());

    // note that session_key file contains other person's public key
    // take this client's public key from the file
    let a = fs::read_to_string("priv_key").unwrap();

    // attempt to parse my private key
    match u32::from_str_radix(&a, 10) {
        Ok(a) => {
            // represent my private key as a bignum
            let a: Vec<u32> = vec![a;1]; // BigUint represents nums in radix 2^32
            let a: BigUint = BigUint::new(a);
            println!("{:?}", a);
            // take their public key B from the session file
            let B = fs::read_to_string("session_key").unwrap();
            println!("old: {:?}", B);
            panic!();
            let B0 = sanitize_big_num("session_key");
            println!("new: {:?}", B);
            match u32::from_str_radix(&B, 10) {
                Ok(B) => {
                    println!("my priv: {:?}\ntheir pub {:?}", a, B);
                    let B: Vec<u32> = vec![B;1];
                    let B: BigUint = BigUint::new(B);
                    let session_key = B.modpow(&a, &p);
                    fs::write("session_key", session_key.to_str_radix(10));
                },
                _ => panic!("create session key")
            }
        },
        _ => panic!("create session key")
    }
}

fn sanitize_data_buffer(response: &mut String) {
    response.retain(|c| c != '\u{0}');
}


// * currently no concept of overflowing the server. stores data in
// string, maybe leverage for stack overflow attack?

fn sanitize_big_num(filename: &str) -> Vec<u32> {
    // takes in a file handle
    let mut raw_data = fs::read_to_string(filename).unwrap(); //TODO: Are we guaranteed a file?
    // strips the contents that are not 0-9 or whitespace
    raw_data.retain(|c| c == ' ' ||
                        c == '0' ||
                        c == '1' ||
                        c == '2' ||
                        c == '3' ||
                        c == '4' ||
                        c == '5' ||
                        c == '6' ||
                        c == '7' ||
                        c == '8' ||
                        c == '9');
    // take each of those chunks and plop it in an element of Vec<u32>
    let split_data = raw_data.split_whitespace();
    let mut parsed_data: Vec<u32> = vec![];
    for chunk in split_data {
        match chunk.parse::<u32>() {
            Ok(x) => println!("{:?}",x),//parsed_data.push(x),
            _ => panic!("bad")
        }
    }

    parsed_data
}


// current state
// have data passing effectively, need to get it into vector form
// stuff coming from off the wire is a string
// currently writing a function to get that into a Vec<u32>

fn parse_bignum_from_string(data: String) {
    // repeatedly divide by 2^32 ? 
    // there should be a function for this...
    // call into python lolz
}
