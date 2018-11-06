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
    let mut response = [0;1024];
    // read the public key from file into request
    let request = fs::read_to_string("pub_key").unwrap();
    // send the request to the stream  *
    stream.write(request.as_bytes()).unwrap();
    // the stream carries the response back into response buffer
    stream.read(&mut response);
    let mut their_pub_key = String::from_utf8_lossy(&response[..]).to_string();
    sanitize_their_pub_key(&mut their_pub_key);
    // write the response to file. session key partially created
    fs::write("session_key", their_pub_key); //STRING
}

fn create_pub_key() {
    let g: u32 = 3;
    let p: u32 = 6;
    let a = fs::read_to_string("priv_key").unwrap();
    match a.parse::<u32>() {
        Ok(a) => {
            let pub_key = g.wrapping_pow(a) % p;
            println!("pub_key: {:?}", pub_key);
            fs::write("pub_key", pub_key.to_string());
        },
        _ => panic!("create pub key")
    }
}

fn create_priv_key() {
    let mut rng = rand::thread_rng();
    let priv_key: u32 = rng.gen();    
    println!("{:?}", priv_key);
    let priv_key = priv_key % 23;
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
            println!("debug: {:?}", their_pub_key);
            // parse their public key 
            match their_pub_key.parse::<u32>() {
                Ok(y) => {
                    // my priv key is x, their pub key is y
                    println!("my priv: {:?}\ntheir pub {:?}", x, y);
//                    let session_key = y.wrapping_pow(x) % 37;
                    let session_key = y.pow(x) % 6;
                    println!("session: {:?}", session_key);
                    // write session_key to file
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


// * currently no concept of overflowing the server. stores data in
// string, maybe leverage for stack overflow attack?
