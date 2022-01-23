const forge = require('node-forge');
const fs = require('fs-extra');

const buffer = fs.readFileSync('./pki/Server/server.pem', 'utf-8');
let pems = forge.pem.decode(buffer);
let certs = pems
    .filter(pem => pem.type == 'CERTIFICATE')
    .map(pem => forge.asn1.fromDer(pem.body, true))
    .map(asn1 => forge.pki.certificateFromAsn1(asn1));
console.log(certs);
let keys = pems.filter(pem => pem.type == 'RSA PRIVATE KEY');