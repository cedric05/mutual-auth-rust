use openssl::{
    ssl::{SslConnector, SslFiletype, SslMethod, SslSessionCacheMode, SslVerifyMode, SslVersion},
    x509::{store::X509StoreBuilder, X509},
};
use std::io::{Read, Write};
use std::{fs, net::TcpStream};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_private_key_file("certs/client/heiko.key", SslFiletype::PEM)?;
    builder.set_certificate_chain_file("certs/client/heiko.crt")?;

    let ca_cert = fs::read_to_string("certs/ca/ca.crt")?.into_bytes();
    let client_ca_cert = X509::from_pem(&ca_cert)?;
    let mut x509_client_store_builder = X509StoreBuilder::new()?;
    x509_client_store_builder.add_cert(client_ca_cert)?;
    let client_cert_store = x509_client_store_builder.build();
    builder.set_verify_cert_store(client_cert_store)?;

    // set options to make sure to validate the peer aka mtls
    let mut verify_mode = SslVerifyMode::empty();
    verify_mode.set(SslVerifyMode::PEER, true);
    verify_mode.set(SslVerifyMode::FAIL_IF_NO_PEER_CERT, true);
    builder.set_verify(verify_mode);

    // may not need to set it to off:
    // https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_set_session_cache_mode.html
    // https://vincent.bernat.ch/en/blog/2011-ssl-session-reuse-rfc5077
    builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    let min_ssl_version_3 = Some(SslVersion::SSL3);
    builder.set_min_proto_version(min_ssl_version_3)?;

    let sslconnector = builder.build();

    let stream = TcpStream::connect("localhost:1234").unwrap();
    let mut stream = sslconnector.connect("server.fqdn", stream).unwrap();
    let message = "hi";
    println!("client writing {}", message);
    stream.write(&message.as_bytes()).unwrap();
    let mut message = [0; 2];
    stream.read(&mut message).unwrap();
    println!("read {}", String::from_utf8(message.to_vec()).unwrap());
    Ok(())
}
