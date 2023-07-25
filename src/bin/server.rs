use clap::Parser;
use openssl::{
    ssl::{
        Ssl, SslAcceptor, SslFiletype, SslMethod, SslSessionCacheMode, SslVerifyMode, SslVersion,
    },
    x509::{store::X509StoreBuilder, X509},
};
use std::{error::Error, fs, net::SocketAddr, pin::Pin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_openssl::SslStream;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(long, default_value = "127.0.0.1:1234")]
    server: String,
    #[clap(long, default_value = "certs/server/client-ssl.bauland42.com.crt")]
    cert: String,
    #[clap(long, default_value = "certs/server/client-ssl.bauland42.com.key")]
    key: String,
    #[clap(long, default_value = "certs/ca/ca.crt")]
    ca: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr: SocketAddr = args.server.parse()?;
    let acceptor = load_acceptor(args)?;
    let server = tokio::net::TcpListener::bind(&addr).await?;
    loop {
        let stream = server.accept().await?.0;
        let acceptor = acceptor.clone();
        tokio::spawn({
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut stream = SslStream::new(ssl, stream).unwrap();
            async move {
                Pin::new(&mut stream).accept().await.unwrap();
                let mut message = [0; 2];
                stream.read(&mut message).await.unwrap();
                println!("read {}", String::from_utf8(message.to_vec()).unwrap());
                stream.write(&message).await.unwrap();
                println!("write {}", String::from_utf8(message.to_vec()).unwrap());
            }
        });
    }
}

fn load_acceptor(args: Args) -> Result<SslAcceptor, Box<dyn Error>> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    builder.set_private_key_file(args.key, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(args.cert)?;
    let ca_cert = fs::read_to_string(args.ca)?.into_bytes();
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
    let acceptor = builder.build();
    Ok(acceptor)
}
