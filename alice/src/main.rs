#![feature(no_panic_pow)]
extern crate rand;

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
//    let mut request = [0;512];
    let mut request = String::new();
    // read the request from the stream (their public key)
//    stream.read(&mut request).unwrap();
    println!("hello");
    let _ = stream.read_to_string(&mut request);
    println!("world");
    stream.flush().unwrap();
    println!("request = {:?}", request);
    // read in the public key for this server (my public key)
    let contents = fs::read_to_string("pub_key").unwrap();
    // generating a response object to indicate that everything is ok REMOVE?
    let response = format!("HTTP/1.1 200 OK\r\n\r\n{}", contents);
    // respond to the request with my public key
    stream.write(contents.as_bytes()).unwrap();

    stream.flush().unwrap();

 //   println!("Request: {}", String::from_utf8_lossy(&request[..]));
//    fs::write("session_key", String::from_utf8_lossy(&request[..]));
    panic!();
    create_session_key();
}

fn create_pub_key() {
    // Setting g = 2 results in pub_key = 0. wrapping_pow bug?
    let g: u32 = 3;  
    let p: u32 = 12341234; // using this mod until big num is implemented
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
    // attempt to parse this client's public key
    match priv_key.parse::<u32>() {
        Ok(x) => {
            // take their public key from the session file
            let their_pub_key = fs::read_to_string("session_key")
                                    .unwrap();
            // parse their public key
            match their_pub_key.parse::<u32>() {
                Ok(y) => {
                    // my priv key is x, their pub key is y
                    let session_key = x.wrapping_mul(y);
                    // write session key to file
                    fs::write("session_key", session_key.to_string());
                },
                _ => panic!("create session key")
            }
        },
        _ => panic!("create session key")
    }
}
