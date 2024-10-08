use pck_cert_parse::{parse_der, pem_to_der, verify_pck, verify_cert_chain, x509_to_subject_public_key};
use std::{fs, io::Read};

/// Read file with a given path
fn read_file(file_name: &str) -> Vec<u8> {
    let mut file = fs::File::open(file_name).unwrap();
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes).unwrap();
    file_bytes
}

fn main() {
    // Read a file given as the first command line argument
    let file_bytes = {
        let input_file = std::env::args().nth(1).unwrap();
        println!("Reading {}", input_file);
        read_file(&input_file)
    };

    // Convert to to der (assuming it is encoded as pem)
    let der = pem_to_der(&file_bytes).unwrap();
    println!("der size: {}", der.len());

    // Parse the certificate
    let x509 = parse_der(&der).unwrap();

    println!("Subject {}", x509.subject());
    println!(
        "Subject RDN: {:?}",
        x509.subject().iter_rdn().next().unwrap()
    );

    let public_key = x509_to_subject_public_key(x509.clone()).unwrap();
    println!("Subject public key: {:?}", public_key);

    // If a second argument was given, attempt to parse it as a PCS file
    if let Some(file_name) = std::env::args().nth(2) {
        let pcs_file_bytes = read_file(&file_name);
        let pcs_der = pem_to_der(&pcs_file_bytes).unwrap();
        let pcs_x509 = parse_der(&pcs_der).unwrap();
        // Attempt to verify the PCK certificate using the public key from the given PCS certifcate
        assert!(verify_pck(&x509, &pcs_x509));
    }
}

#[cfg(test)]
mod test {
    use super::*;


    #[test]
    fn verify_valid_cert_chain() {

            let leaf_cert: Vec<u8> = include_bytes!("leaf_cert.pem").to_vec();
    let intermediate_cert: Vec<u8> = include_bytes!("processor_ca.pem").to_vec();
        let root_cert: Vec<u8> = include_bytes!("root_ca.pem").to_vec();
        
        let der_chain = [leaf_cert, intermediate_cert, root_cert]
            .iter()
            .map(|cert| pem_to_der(cert).unwrap())
            .collect::<Vec<_>>();
        let cert_chain = der_chain
            .iter()
            .map(|cert|  parse_der(cert).unwrap())
                 .collect::<Vec<_>>();
        assert!(verify_cert_chain(cert_chain)
                .is_ok());
    }
}
