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


/// # Create a public key
/// Create a file in the working directory that contains the big num
/// representation of this user's public key. The function takes no
/// arguments, and returns the unit type upon success. If there is 
/// an error sanitizing the input, it is propogated upwards.
/// ## Example
/// ```
/// use std::fs;
///
///fn main() -> std::io::Result<()> {
///     match create_pub_key() {
///         Ok(()) => (), // the file pub_key has been created  
///         _ => panic!("Error generating public key")
///     }
///     let path = fs::canonicalize("priv_key")?;
///     Ok(())
/// }    
/// ```
fn create_pub_key() -> Result<(), &'static str> {
    // create the base point (must be primitive root modulo p)
    let g: Vec<u32> = vec![2;1]; // BigUint represents nums in radix 2^32
    let g: BigUint = BigUint::new(g);

    // define the modulus size p
    let p: BigUint = BigUint::from_bytes_le(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc740\
             20bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f\
             e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee3\
             86bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da\
             48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52\
             9077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
             .as_bytes());

    // take the previously generated private key and craft pub key from it
    match sanitize_big_num("priv_key") {
        Ok(a)  => { 
            let A = g.modpow(&a, &p);
            fs::write("pub_key", format!("{:?}", A));
        },
        Err(e) => return Err(e)
    }

    Ok(())
}


/// # Create a private key
/// Create a file in the working directory that contains the big num
/// representation of the this user's private key. The function takes
/// no arguments and should not fail provided these library calls are stable.
/// ## Example
/// ```
/// use std::fs;
///
/// fn main() -> std::io::Result<()> {
///     create_priv_key();
///     let path = fs::canonicalize("priv_key")?;
///     Ok(())
/// }
/// ```
fn create_priv_key() {
    let mut rng = rand::thread_rng();
    let a: BigUint = rng.sample(RandomBits::new(32));
    fs::write("priv_key", format!("{:?}", a)); 
}


/// # Create a session key
/// Create a file in the working directory that contains the big num
/// representation of the these user's session key.
/// ## Example
/// ```
/// use std::fs;
///
/// fn main() -> std::io::Result<()> {
///     create_priv_key();
///     let path = fs::canonicalize("priv_key")?;
///     Ok(())
/// }
/// ```
fn create_session_key() -> Result<(), &'static str> { 
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
    match sanitize_big_num("priv_key") {
        Ok(a)  => {
            match sanitize_big_num("session_key") {
                Ok(B)  => { 
                    let session_key = B.modpow(&a, &p);
                    fs::write("session_key", format!("{:?}", session_key));
                },
                Err(e) => return Err(e)
            }
        },
        Err(e) => return Err(e)
    }

    Ok(())
}

fn sanitize_their_pub_key(response: &mut String) {
    response.retain(|c| c != '\u{0}');
}


fn sanitize_big_num(filename: &str) -> Result <BigUint, &'static str> { 
    // takes in a filename and reads the contents of the file to a string
    let mut raw_data = String::new();
    match fs::read_to_string(filename) {
        Ok(x) => raw_data = x,
        _     => return Err("missing file")
    }
    // strips the contents that are not 0-9 or whitespace
    raw_data.retain(|c| c == ' ' || c == '0' || c == '1' ||
                        c == '2' || c == '3' || c == '4' ||
                        c == '5' || c == '6' || c == '7' ||
                        c == '8' || c == '9');

    // take each of those chunks and plop it in an element of Vec<u32>
    let split_data = raw_data.split_whitespace();

    // prepare a data structure to store the parsed data
    let mut parsed_data: Vec<u32> = vec![];

    // split the chunks and error out if unsuccessful
    for chunk in split_data {
        match chunk.parse::<u32>() {
            Ok(x) => parsed_data.push(x),
            _ => return Err("sanitizing big num")
        }
    }
    
    // create the desired bignum from the vector
    let bignum = BigUint::new(parsed_data);

    Ok(bignum)
}
