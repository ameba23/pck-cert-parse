use std::io;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser;
use x509_parser::nom::HexDisplay;
use x509_parser::pem::Pem;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::{SubjectPublicKeyInfo, X509Version};

static IGCA_PEM: &str = "./assets/pck_cert.pem";

fn main() {
    let data = std::fs::read(IGCA_PEM).expect("Could not read file");
    for pem in Pem::iter_from_buffer(&data) {
        let pem = pem.expect("Reading next PEM block failed");
        let x509 = pem.parse_x509().expect("X.509: decoding DER failed");
        assert_eq!(x509.tbs_certificate.version, X509Version::V3);
        println!("cert: {:?}", x509);
        // print_x509_info(&x509).unwrap();
        println!(
            "attestation key: {:?}",
            x509.tbs_certificate.subject_pki.subject_public_key
        );
    }
}

fn print_x509_info(x509: &X509Certificate) -> io::Result<()> {
    let version = x509.version();
    if version.0 < 3 {
        println!("  Version: {}", version);
    } else {
        println!("  Version: INVALID({})", version.0);
    }
    println!("  Serial: {}", x509.tbs_certificate.raw_serial_as_string());
    println!("  Subject: {}", x509.subject());
    println!("  Issuer: {}", x509.issuer());
    println!("  Validity:");
    println!("    NotBefore: {}", x509.validity().not_before);
    println!("    NotAfter:  {}", x509.validity().not_after);
    println!("    is_valid:  {}", x509.validity().is_valid());
    println!("  Subject Public Key Info:");
    print_x509_ski(x509.public_key());
    // print_x509_signature_algorithm(&x509.signature_algorithm, 4);

    // println!("  Signature Value:");
    // for l in format_number_to_hex_with_colon(&x509.signature_value.data, 16) {
    //     println!("      {}", l);
    // }
    // println!("  Extensions:");
    // for ext in x509.extensions() {
    //     print_x509_extension(&ext.oid, ext);
    // }
    Ok(())
}

fn print_x509_ski(public_key: &SubjectPublicKeyInfo) {
    println!("    Public Key Algorithm:");
    // print_x509_digest_algorithm(&public_key.algorithm, 6);
    match public_key.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            println!("    RSA Public Key: ({} bit)", rsa.key_size());
            // print_hex_dump(rsa.modulus, 1024);
            // for l in format_number_to_hex_with_colon(rsa.modulus, 16) {
            //     println!("        {}", l);
            // }
            if let Ok(e) = rsa.try_exponent() {
                println!("    exponent: 0x{:x} ({})", e, e);
            } else {
                println!("    exponent: <INVALID>:");
                // print_hex_dump(rsa.exponent, 32);
            }
        }
        Ok(PublicKey::EC(ec)) => {
            println!("    EC Public Key: ({} bit)", ec.key_size());
            for l in format_number_to_hex_with_colon(ec.data(), 16) {
                println!("        {}", l);
            }
            // // identify curve
            // if let Some(params) = &public_key.algorithm.parameters {
            //     let curve_oid = params.as_oid();
            //     let curve = curve_oid
            //         .map(|oid| {
            //             oid_registry()
            //                 .get(oid)
            //                 .map(|entry| entry.sn())
            //                 .unwrap_or("<UNKNOWN>")
            //         })
            //         .unwrap_or("<ERROR: NOT AN OID>");
            //     println!("    Curve: {}", curve);
            // }
        }
        Ok(PublicKey::DSA(y)) => {
            println!("    DSA Public Key: ({} bit)", 8 * y.len());
            for l in format_number_to_hex_with_colon(y, 16) {
                println!("        {}", l);
            }
        }
        Ok(PublicKey::GostR3410(y)) => {
            println!("    GOST R 34.10-94 Public Key: ({} bit)", 8 * y.len());
            for l in format_number_to_hex_with_colon(y, 16) {
                println!("        {}", l);
            }
        }
        Ok(PublicKey::GostR3410_2012(y)) => {
            println!("    GOST R 34.10-2012 Public Key: ({} bit)", 8 * y.len());
            for l in format_number_to_hex_with_colon(y, 16) {
                println!("        {}", l);
            }
        }
        Ok(PublicKey::Unknown(b)) => {
            println!("    Unknown key type");
            print_hex_dump(b, 256);
            if let Ok((rem, res)) = der_parser::parse_der(b) {
                eprintln!("rem: {} bytes", rem.len());
                eprintln!("{:?}", res);
            } else {
                eprintln!("      <Could not parse key as DER>");
            }
        }
        Err(_) => {
            println!("    INVALID PUBLIC KEY");
        }
    }
    // dbg!(&public_key);
    // todo!();
}

fn format_number_to_hex_with_colon(b: &[u8], row_size: usize) -> Vec<String> {
    let mut v = Vec::with_capacity(1 + b.len() / row_size);
    for r in b.chunks(row_size) {
        let s = r.iter().fold(String::with_capacity(3 * r.len()), |a, b| {
            a + &format!("{:02x}:", b)
        });
        v.push(s)
    }
    v
}

fn print_hex_dump(bytes: &[u8], max_len: usize) {
    let m = std::cmp::min(bytes.len(), max_len);
    print!("{}", &bytes[..m].to_hex(16));
    if bytes.len() > max_len {
        println!("... <continued>");
    }
}
