mkdir ca
mkdir client
mkdir server
openssl genrsa -aes256 -out ca/ca.key 4096
openssl req -new -x509 -sha256 -days 730 -key ca/ca.key -out ca/ca.crt
chmod 400 ca/ca.key
chmod 444 ca/ca.crt
openssl genrsa -out server/client-ssl.bauland42.com.key 2048
openssl req -new -key server/client-ssl.bauland42.com.key -sha256 -out server/client-ssl.bauland42.com.csr
chmod 400 server/client-ssl.bauland42.com.key
openssl x509 -req -days 365 -sha256 -in server/client-ssl.bauland42.com.csr -CA ca/ca.crt -CAkey ca/ca.key -set_serial 1 -out server/client-ssl.bauland42.com.crt
chmod 444 server/client-ssl.bauland42.com.crt
openssl verify -CAfile ca/ca.crt server/client-ssl.bauland42.com.crt
openssl genrsa -out client/heiko.key 2048
openssl req -new -key client/heiko.key -out client/heiko.csr
openssl x509 -req -days 365 -sha256 -in client/heiko.csr -CA ca/ca.crt -CAkey ca/ca.key -set_serial 2 -out client/heiko.crt
