const fs = require('fs-extra');
const forge = require('node-forge');
const createHttpsServer = require('https').createServer;
const express = require('express');
const util = require('util');
const path = require('path');
const readline = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout
});


const question = util.promisify(readline.question).bind(readline);

const selectFile = (target, filter) => {
  return fs.readdir('./pki/Server', {withFileTypes: true})
    .then(entries => entries
        .filter(entry => entry.isFile && filter.test(entry.name)))
    .then(async entries => {
      while (true) {
        entries.forEach((entry, index) => console.log(index + ': ' + entry.name));
        let answer = await question('select ' + target + ': ');
        if (!/^\d+$/.test(answer)) {
          console.log('input number')
          continue;
        }
        let index = Number(answer);
        if (index < 0 || entries.length <= index) {
          console.log('input number')
          continue;
        }
        return path.join('./pki/Server', entries[index].name);
      }
    })
}

const tryToOptionAsCertificationPem = buffer => {
  try {
    let cert = forge.pki.certificateFromPem(buffer.toString());
    console.log(cert.subject.attributes.map(field => `${field.shortName}=${field.value}`).join('/'))
    return {
      'cert': buffer
    };
  } catch (err) {
    console.log('not pem: ' + err);
    return null;
  }
}

const tryToOptionAsCertificationDer = buffer => {
  try {
    let asn1 = forge.asn1.fromDer(forge.util.decode64(buffer.toString('base64')));
    let cert = forge.pki.certificateFromAsn1(asn1);
    console.log(cert.subject.attributes.map(field => `${field.shortName}=${field.value}`).join('/'))
    return {
      'cert': forge.pki.certificateToPem(cert)
    };
  } catch (err) {
    console.log('not der: ' + err);
    return null;
  }
}

const tryToOptionAsPrivateKeyPem = async buffer => {
  let passphrase = '';
  while (true) {
    try {
      let key = forge.pki.decryptRsaPrivateKey(buffer.toString(), passphrase);
      console.log(key)
      if (key != null)
        return {
          'key': buffer,
          'passphrase': passphrase
        };
    } catch (err) {
      console.log(err);
    }
    passphrase = await question('enter certificate passphrase:');
    console.log(passphrase)
  }
}

const tryToOptionAsPrivateKeyDer = buffer => {
  let asn1
  try {
    asn1 = forge.asn1.fromDer(forge.util.decode64(buffer.toString('base64')));
  } catch (err) {
    console.log('not der: ' + err);
    return null;
  }

  try {
    let key = forge.pki.privateKeyFromAsn1(asn1);
    return {
      'key': forge.pki.privateKeyToPem(key)
    };
  } catch (err) {
    console.log('not key: ' + err);
    return null;
  }
}


const tryToOptionAsCertificationPKCS12 = async buffer => {
  try {
    let asn1 = forge.asn1.fromDer(forge.util.decode64(buffer.toString('base64')));

    let passphrase = '';
    while (true) {
      try {
        let pkcs12 = forge.pkcs12.pkcs12FromAsn1(asn1, passphrase);
        let bags = pkcs12.getBags({bagType: forge.pki.oids.certBag});
        var cert = bags[forge.pki.oids.certBag][0].cert;
//        console.log(cert);
        console.log(cert.subject.attributes.map(field => `${field.shortName}=${field.value}`).join('/'))
        return {
          'pfx': buffer,
          'passphrase': passphrase
        }
      } catch (err) {
        console.log(err);
        passphrase = await question('enter certificate passphrase:');
        console.log(passphrase)
      }
    }
  } catch (err) {
    console.log(err);
    return null;
  }
}

const askServerPrivateKey = () => selectFile('priate key', /\.(key|der|pem)$/i)
  .then(path => {
    return fs.readFile(path)
      .then(async buffer => {
        if (/\.der$/i.test(path)) {
          return await tryToOptionAsPrivateKeyDer(buffer);
        } else if (/\.pem$/i.test(path)) {
          return await tryToOptionAsPrivateKeyPem(buffer);
        } else {
          return tryToOptionAsPrivateKeyDer(buffer)
            ?? await tryToOptionAsPrivateKeyPem(buffer);
        }
      })
    });

let https;
const askServerCertificate = () => 
  selectFile('server certificate', /\.(cer|crt|der|pem|pfx|p12)$/i)
    .then(path => {
      return fs.readFile(path)
        .then(async buffer => {
          let options = null;
          if (/\.(pfx|p12)$/i.test(path)) {
            return await tryToOptionAsCertificationPKCS12(buffer);
          } else if (/\.(crt|cer)$/i.test(path)) {
            options = tryToOptionAsCertificationPem(buffer)
            ?? tryToOptionAsCertificationDer(buffer);
          } else if (/\.pem$/i.test(path)) {
            options = tryToOptionAsCertificationPem(buffer);
          } else if (/\.der$/i.test(path)) {
            options = tryToOptionAsCertificationDer(buffer);
          }
          if (options === null) return null;
          let key = await askServerPrivateKey();
          console.log (key);
          if (key === null) return null;
          Object.assign(options, key);
          return options;
        })
    });

askServerCertificate()
.then(options => {
  if (options === null) return;
  const app = express();
  app.get('/', (req, res) => {
    console.log(req.url);
    res.status(200).send('Hello world');
  });
  app.get('/test', (req, res) => {
    console.log(req.url);
    res.status(200).send('test test test');
  });
  
  Object.assign(options, {
    'ca': fs.readFileSync('./pki/InterCA/inter-ca-crt.cer'),
//    maxVersion: 'TLSv1.3',
//    minVersion: 'TLSv1.2',
//    ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256'
  });
  console.log(options);
  https = createHttpsServer(options, app);
  https.listen(8081);          
  console.log('listening')
});


