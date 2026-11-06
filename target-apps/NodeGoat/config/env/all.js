// default app configurations
const port = process.env.PORT || 4043;
let db = process.env.MONGODB_URI || "mongodb://mongo30:27017/nodegoat";

module.exports = {
    port,
    db,
    cookieSecret: "session_cookie_secret_key_here",
    cryptoKey: "a_secure_key_for_crypto_here",
    cryptoAlgo: "aes256",
    hostName: "localhost",
    environmentalScripts: []
};

