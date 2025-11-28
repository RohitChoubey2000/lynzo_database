const mysql = require("mysql2");

const db = mysql.createPool({
    host: "217.21.87.103",
    user: "u205680228_rohitchoubey",
    password: "Rohit@choubey5",
    database: "u205680228_lynzo",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

db.connect((error) => {
  if (error) {
    console.error(" Database connection error:", error.message);
    return;
  }
  console.log(" Database connected!");
});


module.exports = db;