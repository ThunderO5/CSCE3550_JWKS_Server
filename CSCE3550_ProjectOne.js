const HTTP = require("http");           //Imports HTTP Module for Server
const CRYPTO = require("crypto");       //Imports Crypto Module for RSA Implementation
const {v4 : UUIVD4} = require("uuid");  //Imports UUID Module for Unique IDS
const JWT = require("jsonwebtoken");    // Imports JTW for JTW Functionality
const HOSTNAME = "127.0.0.1";           //Hostname for the Server
const PORT = 8080;                      //The Port of the Server for Incoming Requests

//Functionality One - Generate RSA Key Pair
function generateKeyPair()
{
    isExpired = false;

    //Defines Public and Private Keys
    const {PUBLICKEY, PRIVATEKEY} = CRYPTO.generateKeyPairSync("rsa", 
    {
        modulusLength: 2048,
        publicKeyEncoding: {type: "spki", format: "pem"},
        privateKeyEncoding: {type: "pkcs8", format: "pem"}
    });

    //Returns the Unique ID, Private and Public Keys, and Expiration Time
    return {
        kid: UUIVD4(),
        PUBLICKEY,
        PRIVATEKEY,
        expiresAt: areKeysExpired(isExpired)
    };
}

//Helper Function - Checks if the Key's Expiration Passed
function areKeysExpired(isExpired)
{
    if (isExpired)
    {
        Date.now() - 60 * 1000; //Keys Expired One Minute Ago
    }
    else
    {
        Date.now() + 5 * 60 * 1000; //Keys will Expire in Five Minutes
    }
}

//Section 2 - Public Key to JWKS Format
function publicKeyToJWK(publicKeyPem, kid)
{
    //Creates a Public Key
    const PUBLICKEYOBJ = CRYPTO.createPublicKey(publicKeyPem);

    //Converts Public Key to JWK Format
    const JWK = PUBLICKEYOBJ.export({format : "jwk"});

    //Returns 
    return {
        kty: "RSA",
        kid: kid,
        use: "sig",
        alg: "RS256",
        n: JWK.n,
        e: JWK.e
    };
}

//Section 3 - Store Keys and Serve the JWKS
let keys = [];
keys.push(generateKeyPair());

function getJWKS()
{
    const VALIDKEYS = keys.filter(k => k.expiresAt > Date.now());

    return {
        keys: VALIDKEYS.map(k => publicKeyToJWK(k.publicKey, k.kid))
    };
}

//Section 4 - Handling Autherization
function handleAuth(req, res, url)
{
    //Checks if the URL's keys are expired
    const EXPIRED = url.searchParams.get("expired") === true;

    let key;
    if (EXPIRED)
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
    const token = JWT.sign(payload, key.privateKey, {
        algorithm: "RS256",
        keyid: key.kid,
        expiresIn: EXPIRED ? "-1s" : "5m"
    });

    res.writeHead(200, {'Content-Type' : 'application/json'});
    res.end(JSON.stringify({token}));
}

//Section 5 - The Main Server
//Server is created
const server = HTTP.createServer((req, res) => {
    //Created URL for the Server
    const URL = new URL(req.url, `https://${req.headers.host}`);

    //Goes to Different URL Paths
    if (url.pathname === '/jwks.json')
    {
        const JWKS = getJWKS();
        res.writeHead(200, {'Content-Type' : 'application/json'});
        res.end(JSON.stringify(JWKS, null, 2));
    }
    else if (URL.pathname === '/auth' && req.method === 'POST')
    {
        handleAuth(req, res, URL);
    }
    else
    {
        res.writeHead(404, {'Content-Type' : 'text/plain'});
        res.end("Not Found");
    }
});

//Server listens to any connections
server.listen(PORT, HOSTNAME, () => {
    console.log(`Server running at http://${HOSTNAME}:${PORT}`);    //Main Page, so error
    console.log(`Server running at http://${HOSTNAME}:${PORT}/jwks.json`);    //The JWKS JSON File
    console.log(`Server running at http://${HOSTNAME}:${PORT}/auth`);    //AUTH page
});