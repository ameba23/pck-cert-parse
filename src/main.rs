use pck_cert_parse::{parse_der, pem_to_der, verify_pck, x509_to_subject_public_key};
use std::{fs, io::Read};

fn read_file(file_name: &str) -> Vec<u8> {
    let mut file = fs::File::open(file_name).unwrap();
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes).unwrap();
    file_bytes
}

fn main() {
    let file_bytes = {
        let input_file = std::env::args().nth(1).unwrap();
        println!("Reading {}", input_file);
        read_file(&input_file)
    };
    let der = pem_to_der(&file_bytes).unwrap();
    println!("der size: {}", der.len());
    let x509 = parse_der(&der).unwrap();
    println!("Subject {}", x509.subject());
    println!(
        "Subject RDN: {:?}",
        x509.subject().iter_rdn().next().unwrap() //.as_str()
    );

    let public_key = x509_to_subject_public_key(x509.clone()).unwrap();
    println!("Subject public key: {:?}", public_key);

    let pcs_file_bytes = read_file("assets/pcs_cert_1.pem");
    let pcs_der = pem_to_der(&pcs_file_bytes).unwrap();
    let pcs_x509 = parse_der(&pcs_der).unwrap();

    assert!(verify_pck(&x509, &pcs_x509));
}
