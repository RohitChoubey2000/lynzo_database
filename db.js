const mysql = require('mysql2');
const db = mysql.createConnection({
    host: "217.21.87.103",
    database : "u205680228_lynzo",
    password : "Rohit@choubey5",
    user : 'u205680228_rohitchoubey'
});

db.connect((error) => {
  if (error) {
    console.error(" Database connection error:", error.message);
    return;
  }
  console.log(" Database connected!");
});


module.exports = db;