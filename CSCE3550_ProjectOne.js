//Import HTTP Module
const HTTP = require('http');

//Localhost for the server
const NAMEHOST = '127.0.0.1';

//Port the server listens to
const PORT = 8080;

//Creating a server
const server = HTTP.createServer((req, res) => {
    //Sets the request with a HTML Status and Content Type
    res.writeHead(200, {'Content-Type': 'text/plain'});

    //Sends the response
    res.end('Hello World!\n');
});

//Server is listening to any connections
server.listen(PORT, NAMEHOST, () => {
    console.log(`Server running at http://${NAMEHOST}:${PORT}/`);
});