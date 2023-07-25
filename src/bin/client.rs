use clap::Parser;
use openssl::{
    ssl::{SslConnector, SslFiletype, SslMethod, SslSessionCacheMode, SslVerifyMode, SslVersion},
    x509::{store::X509StoreBuilder, X509},
};
use std::{fs, net::SocketAddr, pin::Pin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_openssl::SslStream;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(long, default_value = "127.0.0.1:1234")]
    client: String,
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
    let socket_addr: SocketAddr = args.client.parse()?;
    let sslconnector = load_connector(args)?;
    let ssl = sslconnector
        .configure()
        .unwrap()
        .into_ssl("server.fqdn")
        .unwrap();
    let stream = tokio::net::TcpStream::connect(socket_addr).await?;
    let mut stream = SslStream::new(ssl, stream)?;
    Pin::new(&mut stream).connect().await.unwrap();
    let message = "hi";
    println!("client writing {}", message);
    stream.write(&message.as_bytes()).await.unwrap();
    let mut message = [0; 2];
    stream.read(&mut message).await.unwrap();
    println!("read {}", String::from_utf8(message.to_vec()).unwrap());
    Ok(())
}

fn load_connector(args: Args) -> Result<SslConnector, Box<dyn std::error::Error>> {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_private_key_file(args.key, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(args.cert)?;
    let ca_cert = fs::read_to_string(args.ca)?.into_bytes();
    let client_ca_cert = X509::from_pem(&ca_cert)?;
    let mut x509_client_store_builder = X509StoreBuilder::new()?;
    x509_client_store_builder.add_cert(client_ca_cert)?;
    let client_cert_store = x509_client_store_builder.build();
    builder.set_verify_cert_store(client_cert_store)?;
    let mut verify_mode = SslVerifyMode::empty();
    verify_mode.set(SslVerifyMode::PEER, true);
    verify_mode.set(SslVerifyMode::FAIL_IF_NO_PEER_CERT, true);
    builder.set_verify(verify_mode);
    builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    let min_ssl_version_3 = Some(SslVersion::SSL3);
    builder.set_min_proto_version(min_ssl_version_3)?;
    let sslconnector = builder.build();
    Ok(sslconnector)
}
