extern crate num_bigint;
extern crate num_traits;
extern crate rand;

use num_bigint::{BigUint, RandomBits};
use num_traits::{Zero, One};
use rand::Rng;
use std::fs;
use std::io::prelude::*;
use std::net::TcpStream;
use std::net::TcpListener;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").expect("bind error");
    create_priv_key();
    create_pub_key();

    for stream in listener.incoming() {
        let stream = stream.expect("stream error");

        handle_connection(stream);
    }
}

fn handle_connection(mut stream: TcpStream) {
    // create a buffer for the request 
    let mut request = [0;2048];
    // read the request from the stream (their public key)
    stream.read(&mut request).unwrap();
    // read in the public key for this server (my public key)
    let response = fs::read_to_string("pub_key").unwrap();
    // respond to the request with my public key
    stream.write(response.as_bytes()).unwrap();
    // now deal with their request by moving it from buffer to string
    let mut their_pub_key = String::from_utf8_lossy(&request[..]).to_string();
    // the string contains a lot of \u{0}, remove them.
    sanitize_their_pub_key(&mut their_pub_key);
    // their sanitized public key is temporarily held in the session_key file 
    fs::write("session_key", their_pub_key);
    // generate the session key with the gathered information
    create_session_key();
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
    let a = sanitize_big_num("priv_key");
    println!("\nmy priv key\n{:?}",a);
    let A = g.modpow(&a, &p);
    println!("\nmy pub key\n{:?}",A);
    fs::write("pub_key", format!("{:?}", A));
    // attempt to parse the private key file
    /*
    let a = fs::read_to_string("priv_key").unwrap();
    match u32::from_str_radix(&a, 10) {
        Ok(a) => {  
            let a: Vec<u32> = vec![a;1]; // BigUint represents nums in radix 2^32
            let a: BigUint = BigUint::new(a);
            let A = g.modpow(&a, &p);    // Create public key A
// CHANGE           fs::write("pub_key", A.to_str_radix(10));
            fs::write("pub_key", format!("{:?}", A));
        },
        _ => panic!("create pub key")
    }*/
}

fn create_priv_key() {
    let mut rng = rand::thread_rng();
    let a: BigUint = rng.sample(RandomBits::new(32));
//    fs::write("priv_key", a.to_str_radix(10)); // TODO: Keep it all in 2^32?
    fs::write("priv_key", format!("{:?}", a)); // TODO: Keep it all in 2^32?
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
    //let a = fs::read_to_string("priv_key").unwrap();
    let a = sanitize_big_num("priv_key");
    let B = sanitize_big_num("session_key");
    println!("\ntheir pub key\n{:?}",B);
    let session_key = B.modpow(&a, &p);
    println!("\nsession key{:?}",session_key);
    /*
    // attempt to parse my private key
    match u32::from_str_radix(&a, 10) {
        Ok(a) => {
            // represent my private key as a bignum
            let a: Vec<u32> = vec![a;1]; // BigUint represents nums in radix 2^32
            let a: BigUint = BigUint::new(a);
            
            // take their public key B from the session file
            let B = fs::read_to_string("session_key").unwrap();
            println!("{:?}", B);
            //panic!();
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
    }*/
}

fn sanitize_their_pub_key(response: &mut String) {
    response.retain(|c| c != '\u{0}');
}


fn sanitize_big_num(filename: &str) -> BigUint { //TODO: return a result
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
            Ok(x) => parsed_data.push(x),
            _ => panic!("sanitizing big num")
        }
    }

    let bignum = BigUint::new(parsed_data);

    bignum
}
