const mysql = require("mysql2/promise");
const poolConfig = {
    host: "217.21.87.103",
    user: "u205680228_rohitchoubey",
    password: "Rohit@choubey5",
    database: "u205680228_lynzo",
    port: process.env.DB_PORT,
    waitForConnections: true, // If connections are maxed out, queue new requests
    connectionLimit: 10,     // Max number of simultaneous connections (adjust as needed)
    queueLimit: 0,           // No limit on the queue for waiting requests
    connectTimeout: 20000, 
    acquireTimeout: 20000 
};

const db = mysql.createPool(poolConfig);

db.getConnection()
    .then(connection => {
        console.log("Database connected and pool ready.");
        connection.release(); // Release the test connection back to the pool
    })
    .catch(error => {
        console.error("Database connection error (Please check config/credentials):", error.message);
    });

module.exports = db;