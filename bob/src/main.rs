extern crate num_bigint;
extern crate num_traits;
extern crate rand;

use num_bigint::{BigUint, RandomBits};
use num_traits::{Zero, One};
use rand::Rng;
use std::error;
use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::net::TcpStream;


fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:7878").unwrap();
    create_priv_key();
    create_pub_key();
    connect(stream);
    create_session_key();
}


/// # Create and dispatch web request
/// This creates a web request and sends it off to the port specified
/// by the caller. The stream is permitted to be a length of 2048
/// bytes or less. My public key is sent as a request and the other
/// user's public key is received as a response. Their public key is
/// expected to be correctly formatted, and it is stored in the session_key
/// file. Then the actual session key is generated.
/// # Example
/// ```
/// unimplemented!();
/// ```
fn connect(mut stream: TcpStream) {
    // create a buffer for the response 
    let mut response = [0;2048];

    // read the public key from file into request
    let request = fs::read_to_string("pub_key").unwrap();

    // send the request to the stream  *
    stream.write(request.as_bytes()).unwrap();

    // the stream carries the response back into response buffer
    stream.read(&mut response);

    // get their data from the response buffer, note we're using lossy
    let mut their_pub_key = String::from_utf8_lossy(&response[..]).to_string();

    // this function removes all of the excess padding characters
    sanitize_data_buffer(&mut their_pub_key);
    
    // write the response to file. session key partially created
    // STRING CORRECTLY FORMATTED ON THEIR END
    fs::write("session_key", their_pub_key); 
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

    // I'll roll my own errors one day
    // https://stackoverflow.com/questions/42584368/how-do-you-define-custom-error-types-in-rust
//    let priv_key = sanitize_big_num("priv_key")?;
//    let pub_key = g.modpow(&priv_key, &p);
//    fs::write("pub_key", format!("{:?}", pub_key))?;

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


/// # Sanitize their public key
/// Given a public key over the wire, strip all of the padding characters
/// from the string. The reason this function is necessary is due to the
/// lack of concurrency? when working with a buffer represented by a String
/// instead of an array. As it stands, requests and responses overwrite data
/// in the array, instead of into a String object. Thus manually removeing
/// '\u{0}' is required.
/// ## Example
/// ```
/// unimplemented!();
/// ```
fn sanitize_data_buffer(response: &mut String) {
    response.retain(|c| c != '\u{0}');
}


/// # Sanitize a big num from file
/// The keys are stored as files in the working directory. However, they're
/// not stored as base 10 numbers, rather their big num representation is in
/// 2^32. So this file is stripped of its excess characters, and piped into
/// a BigUint appropriately.
/// ## Example
/// ```
/// unimplemented!()
/// ```
fn sanitize_big_num(filename: &str) -> Result <BigUint, &'static str> { //TODO: return a result
    // takes in a file handle
    let mut raw_data = String::new();
    match fs::read_to_string(filename) {
        Ok(x) => raw_data = x,
        _     => return Err("missing file")
    }
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
            _ => return Err("sanitizing big num")
        }
    }

    // create the desired bignum from the vector
    let bignum = BigUint::new(parsed_data);

    Ok(bignum)
}


// Attempting implement custom error
#[derive(Debug)]
struct ErrorChain;

impl fmt::Display for ErrorChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "print your error msg here")
    }
}

impl error::Error for ErrorChain {
    fn source(&self) -> Option<&(dyn: Error + 'static) {
        None
    }
}

// Need to impl From so these errors can be used with `?`
