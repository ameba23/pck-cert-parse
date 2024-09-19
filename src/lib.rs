use x509_parser::{
    certificate::X509Certificate, error::X509Error, pem, prelude::FromDer, public_key::PublicKey,
};

// pub fn parse_pem(input: &[u8]) -> Result<X509Certificate, X509Error> {
//     let der = pem_to_der(input)?;
//     Ok(parse_der(&der.clone())?)
// }

pub fn parse_der(input: &[u8]) -> Result<X509Certificate, X509Error> {
    let (_remaining, cert) = X509Certificate::from_der(input)?;
    Ok(cert)
}

pub fn pem_to_der(input: &[u8]) -> Result<Vec<u8>, X509Error> {
    let (_data, pem) = pem::parse_x509_pem(input).map_err(|_| X509Error::Generic)?;
    Ok(pem.contents)
}

pub fn x509_to_subject_public_key(input: X509Certificate) -> Result<Vec<u8>, X509Error> {
    let public_key = input.tbs_certificate.subject_pki.parsed()?;
    match public_key {
        PublicKey::EC(ec_point) => Ok(ec_point.data().to_vec()),
        _ => Err(X509Error::Generic),
    }
}

/// Check that a given PCK certificate is signed with the public key from a given PCS
/// certificate which in our case should be from Intel
pub fn verify_pck(pck: &X509Certificate, pcs: &X509Certificate) -> bool {
    let issuer_public_key = pcs.public_key();
    pck.verify_signature(Some(issuer_public_key)).is_ok()
}
