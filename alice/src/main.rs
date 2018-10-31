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
    let mut request = [0;512];
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
    // Setting g = 2 results in pub_key = 0. wrapping_pow bug?
    let g: u32 = 3;  
    let p: u32 = 7; // using this mod until big num is implemented
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
    let priv_key =  priv_key % 7;
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
                    println!("my priv: {:?}\ntheir pub {:?}", x, y); 
//                    let session_key = y.wrapping_pow(x) % 7;
                    let session_key = y.pow(x) % 7;
                    println!("session: {:?}", session_key);
                    // write session key to file
                    fs::write("session_key", session_key.to_string());
                },
                _ => panic!("create session key")
            }
        },
        _ => panic!("create session key")
    }
}

fn sanitize_their_pub_key(response: &mut String) {
    response.retain(|c| c != '\u{0}');
}
