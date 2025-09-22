const HTTP = require("http");           //Imports HTTP Module for Server
const crypto = require("crypto");       //Imports Crypto Module for RSA Implementation
const {v4 : uuivd4} = require("uuid");  //Imports UUID Module for Unique IDS
const jwt = require("jsonwebtoken");    // Imports JTW for JTW Functionality
const HOSTNAME = "127.0.0.1";           //Hostname for the Server
const PORT = 8080;                      //The Port of the Server for Incoming Requests

//Functionality One - Generate RSA Key Pair
function generateKeyPair(isExpired = false)
{
    //Defines Public and Private Keys
    const {publicKey, privateKey} = crypto.generateKeyPairSync("rsa", 
    {
        modulusLength: 2048,
        publicKeyEncoding: {type: "spki", format: "pem"},
        privateKeyEncoding: {type: "pkcs8", format: "pem"}
    });

    //Returns the Unique ID, Private and Public Keys, and Expiration Time
    return {
        kid: uuivd4(),
        publicKey,
        privateKey,
        expiresAt: isExpired ? Date.now() - 60 * 1000 : Date.now() + 5 * 60 * 1000
    };
}

//Section 2 - Public Key to JWKS Format
function publicKeyToJWK(publicKeyPem, kid)
{
    //Creates a Public Key
    const publicKeyObj = crypto.createPublicKey(publicKeyPem);

    //Converts Public Key to JWK Format
    const jwk = publicKeyObj.export({format : "jwk"});

    //Returns 
    return {
        kty: "RSA",
        kid: kid,
        use: "sig",
        alg: "RS256",
        n: jwk.n,
        e: jwk.e
    };
}

//Section 3 - Store Keys and Serve the JWKS
let keys = [];
keys.push(generateKeyPair(false));
keys.push(generateKeyPair(true));

function getJWKS()
{
    const validKeys = keys.filter(k => k.expiresAt > Date.now());

    return {
        keys: validKeys.map(k => publicKeyToJWK(k.publicKey, k.kid))
    };
}

//Section 4 - Handling Autherization
function handleAuth(req, res, url)
{
    //Checks if the URL's keys are expired
    const expired = url.searchParams.get("expired") === true;

    let key;
    if (expired)
    {
        //Keys are Expired
        key = keys.find(k => k.expiresAt < Date.now());
    }
    else
    {
        //Keys are Expired
        key = keys.find(k => k.expiresAt > Date.now());
    }

    //Key is Not Found
    if (!key)
    {
        res.writeHead(500, {'Content-Type' : 'application/json'});
        res.end(JSON.stringify({error: "No suitable key found"}));
        return;
    }

    //Data to Transfer
    const payload = {user: "test-user"};

    //Signs the JWT Token
    const token = jwt.sign(payload, key.privateKey, {
        algorithm: "RS256",
        keyid: key.kid,
        expiresIn: expired ? "-1s" : "5m"
    });

    res.writeHead(200, {'Content-Type' : 'application/json'});
    res.end(JSON.stringify({token}));
}

//Section 5 - The Main Server
//Server is created
const server = HTTP.createServer((req, res) => {
    //Created URL for the Server
    const url = new URL(req.url, `https://${req.headers.host}`);

    //Goes to Different URL Paths
    if (url.pathname === '/.well-known/jwks.json')
    {
        const jwks = getJWKS();
        res.writeHead(200, {'Content-Type' : 'application/json'});
        res.end(JSON.stringify(jwks, null, 2));
    }
    else if (url.pathname === '/auth' && req.method === 'POST')
    {
        handleAuth(req, res, url);
    }
    else
    {
        res.writeHead(405, {'Content-Type' : 'text/plain'});
        res.end("Method Not Allowed");
    }
});

//Server listens to any connections
server.listen(PORT, HOSTNAME, () => {
    console.log(`Server running at http://${HOSTNAME}:${PORT}`);    //Main Page, so error
    console.log(`Server running at http://${HOSTNAME}:${PORT}/jwks.json`);    //The JWKS JSON File
    console.log(`Server running at http://${HOSTNAME}:${PORT}/auth`);    //AUTH page
});