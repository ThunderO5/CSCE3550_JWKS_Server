const HTTP = require("http"); //Import HTTP Module
const CRYPTO = require("crypto"); //Allows for RSA implementation
const {v4 : uuidv4} = require("uuid"); //The unique ID
const jwt = require("jsonwebtoken");
const HOSTNAME = "127.0.0.1"; //Hostname for the server
const PORT = 8080; //The server's port for incoming requests

//Section 1 - RSA Stuff
//Generate new RSA key pair
function generateKeyPair(isExpired = false)
{
    //Sets up the public and private pairs
    const {publicKey, privateKey} = CRYPTO.generateKeyPairSync("rsa", 
    {
        modulusLength: 2048,
        publicKeyEncoding: {type: "spki", format: "pem"},
        privateKeyEncoding: {type: "pkcs8", format: "pem"}
    });

    //returns the unique id, public and private keys, and expiration date
    return {
        kid: uuidv4(), //Unique id
        publicKey,
        privateKey,
        expiresAt: isExpired ? Date.now() - 60 * 1000 : Date.now() +  5 * 60 * 1000
    };
}

//Section 2 - Public Key to JWKS Format
function publicKeyToJWK(publicKeyPem, kid)
{
    const publicKeyObj = CRYPTO.createPublicKey(publicKeyPem);
    const jwk = publicKeyObj.export({format : "jwk"});

    return {
        kty: "RSA",
        kid: kid,
        use: "sig",
        alg: "RS256",
        n: jwk.n,
        e: jwk.e
    };
}

//Section 3 - Store Keys and Servee the JWKS
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

//Section 4 - HandleAuth
function handleAuth(req, res, url)
{
    const expired = url.searchParams.get("expired") === true;

    let key;
    if (expired)
    {
        key = keys.find(k => k.expiresAt < Date.now());
    }
    else
    {
        key = keys.find(k => k.expiresAt > Date.now());
    }

    if (!key)
    {
        res.writeHead(500, {'Content-Type' : 'application/json'});
        res.end(JSON.stringify({error: "No suitable key found"}));
        return;
    }

    const payload = {user: "test-user"};

    const token = jwt.sign(payload, key.privateKey, {
        algorithm: "RS256",
        keyid: key.kid,
        expiresIn: expired ? "-1s" : "5m"
    });

    res.writeHead(200, {'Content-Type' : 'application/json'});
    res.end(JSON.stringify({token}));
}

//Section 3 - Server Stuff
//Server is created
const server = HTTP.createServer((req, res) => {
    const url = new URL(req.url, `https://${req.headers.host}`);
    if (url.pathname === '/jwks.json')
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
        res.writeHead(404, {'Content-Type' : 'text/plain'});
        res.end("Not Found");
    }
});

//Server listens to any connections
server.listen(PORT, HOSTNAME, () => {
    console.log(`Server running at http://${HOSTNAME}:${PORT}`);
});