# Frontend application

This is a frontend application that can be used to interact with the `cert` application running on the Hyperledger Sawtooth blockchain.

## Installation

 - Install the javascript dependencies: `npm install .`
 - Compile the javascript dependencies: `npx webpack --config webpack.config.js --mode production`
 - Run the proxy server: `node node_modules/cors-anywhere/server.js`
 - Open the file `index.html` in a browser.
 - In the settings tab, adjust the values for the rest-api and the proxy. Bot URL __must__ be in the format `http://<address:port>/`. The default values should work if you are running both the proxy and the rest-api locally.
