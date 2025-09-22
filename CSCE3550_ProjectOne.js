//Section 1 - RSA Stuff
const CRYPTO = require("crypto"); //Allows for RSA implementation
const {v4 : uuidv4} = require("uuid"); //The unique ID

//Generate new RSA key pair
function generateKeyPair()
{
    //Sets up the public and private pairs
    const {publicKey, privateKey} = CRYPTO.generateKeyPairSync("rsa", 
    {
        modulusLength: 2048,
        publicKeyEncoding: {type: "skpi", format: "pem"},
        privateKeyEncoding: {type: "pkcs8", format: "pem"}
    });

    //returns the unique id, public and private keys, and expiration date
    return {
        kid: uuidv4(), //Unique id
        publicKey,
        privateKey,
        expiresAt: Date.now + 5 * 60 * 1000 //expires in 5 minutes
    };
}

//Section 2 - Public Key to JWKS Format
function publicKeyToJWK(publickKeyPem, kid)
{
    const publicKeyObj = CRYPTO.createPublicKey(publicKeyPem);
    const der = publicKeyObj.export({type : 'spki', format : 'der'});

    //Something
    const asn1 = der.ToString('base64');

    return {
        kty: "RSA",
        kid: kid,
        use: "sig",
        alg: "RS256",
        n: publicKeyObj.export({format: 'jwk'}).n,
        e: publicKeyObj.export({format: 'jwk'}).e
    };
}

//Section 3 - Store Keys and Servee the JWKS
let keys = [];
keys.push(generateKeyPair());

function getJWKS()
{
    const validKeys = keys.filter(k => k.expiresAt > Date.now());

    return {
        keys: validKeys.map(k => publicKeyToJWK(k.publicKey, k.kid))
    };
}

//Section 3 - Server Stuff
//Import HTTP Module
const HTTP = require('http');

//Hostname for the server
const HOSTNAME = '127.0.0.1';

//The server's port for incoming requests
const PORT = 8080;

//Server is created
const server = HTTP.createServer((req, res) => {
    //Sets the request with a HTML Status and Content Type
    res.writeHead(200, {'Content-Type': 'text/plain'});
    
    //Writes into the website
    res.write("Hello World!");

    //Ends the response
    res.end();
});

//Server listens to any connections
server.listen(PORT, HOSTNAME, () => {
    console.log(`Server running at http://${HOSTNAME}:${PORT}/`);
});