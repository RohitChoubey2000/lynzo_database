const mysql = require("mysql2/promise");
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const poolConfig = {
    // USE process.env FOR SENSITIVE DATA
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    
    // PORT is optional if standard (3306)
    //port: process.env.DB_PORT || 3306, 
    
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 20000, 
    acquireTimeout: 20000 
};

const db = mysql.createPool(poolConfig);

db.getConnection()
    .then(connection => {
        console.log("Database connected and pool ready.");
        connection.release(); 
    })
    .catch(error => {
        console.error("Database connection error (Please check config/credentials):", error.message);
    });

module.exports = db;