require 'openssl'

rsa = OpenSSL::PKey::RSA.generate(2048)
File.write("server.key", rsa.to_pem)

csr = OpenSSL::X509::Request.new
name = OpenSSL::X509::Name.new
name.add_entry("CN", "localhost")
name.add_entry("DC", "localhost")
csr.subject = name
csr.version = 0
csr.public_key = rsa.public_key
factory = OpenSSL::X509::ExtensionFactory.new
exts = [factory.create_ext("subjectAltName", "DNS:localhost")]
asn1exts = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(exts)])
csr.add_attribute(OpenSSL::X509::Attribute.new("extReq", asn1exts))
csr.sign(rsa, "sha256")

cert = OpenSSL::X509::Certificate.new
cert.serial = 0
cert.version = 2
cert.not_before = Time.now
cert.not_after = Time.now + (31 * 24 * 60 * 60) # a month later
cert.subject = name
cert.issuer = name
cert.public_key = csr.public_key
cert.sign(rsa, "sha256")
File.write("server.crt", cert.to_pem)

# openssl s_server -accept 4433 -cert server.crt -key server.key -tls1_3
# openssl s_client -connect localhost:4433 -tls1_3 [-keylogfile SSLKEYLOGFILE] -CAfile server.crt
