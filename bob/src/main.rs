#![feature(no_panic_pow)]
extern crate rand;

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
    let mut response = [0;512];
//    let mut response = String::new(); STRING
    // read the public key from file into request
    let request = fs::read_to_string("pub_key").unwrap();
//    let request = fs::read_to_string("pub_key").unwrap(); STRING
    // send the request to the stream  
    // currently no concept of overflowing the server. stores data in
    // string, maybe leverage for stack overflow attack?
    stream.write(request.as_bytes()).unwrap();
    // the stream carries the response back into response buffer
    stream.read(&mut response);
    //println!("{:?}", String::from_utf8_lossy(&response[..]));
    let x = String::from_utf8_lossy(&response[..]).to_string();
    println!("{}", x);
    // write the response to file. session key partially created
    fs::write("session_key", x); //STRING
    
}

fn create_pub_key() {
    let g: u32 = 3;
    let p: u32 = 12341234;
    let a = fs::read_to_string("priv_key").unwrap();
    match a.parse::<u32>() {
        Ok(a) => {
            let pub_key = g.wrapping_pow(a) % p;
            fs::write("pub_key", pub_key.to_string());
        },
        _ => panic!("create pub key")
    }
}

fn create_priv_key() {
    let mut rng = rand::thread_rng();
    let priv_key: u32 = rng.gen();    
    fs::write("priv_key", priv_key.to_string());
}

fn create_session_key() {
    // note that session_key file contains other person's public key
    // take this client's public key from the file
    let priv_key = fs::read_to_string("priv_key").unwrap(); 
    // attempt to parse my public key 
    match priv_key.parse::<u32>() {
        Ok(x) => {
            // take their public key from session key file
            let their_pub_key = fs::read_to_string("session_key")
                                    .unwrap();
            // parse their public key 
            match their_pub_key.parse::<u32>() {
                Ok(y) => {
                    // my priv key is x, their pub key is y
                    let session_key = x.wrapping_mul(y);
                    // write session_key to file
                    fs::write("session_key", session_key.to_string());
                },
                _ => panic!("create session key")
            }
        },
        _ => panic!("create session key")
    }
}
