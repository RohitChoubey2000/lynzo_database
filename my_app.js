const express = require("express");
const db = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { request } = require("http");
const { error } = require("console");
const app = express();

app.use(express.json());


app.get("/get/users", async (request, response)=>{

  const[result]= await db.query("SELECT *From users");
  response.status(200).json(result);

})



app.get("/users", (request, response) => {
  const token = request.headers.authorization;
  const secretKey = "abcd";
  jwt.verify(token, secretKey, (eror, result) => {
    if (eror) {
      response.status(400).json({ message: "unauthorized" });
    } else {
      response.status(200).json(result);
    }
  });
});

// Post Method to add new user
app.post("/users/signup", async (request, response) => {
  const email = request.body.email;
  const firstName = request.body.firstName;
  const lastName = request.body.lastName;
  const phoneNumber = request.body.phoneNumber;
  const password = request.body.password;
  const passwordHash = await bcrypt.hash(password, 10);
  db.query(
    "INSERT INTO users (Email, FirstName, LastName, PhoneNumber, Password) VALUES (?,?,?,?,?)",
    [email, firstName, lastName, phoneNumber, passwordHash],
    (error, result) => {
      if (error)
        return response
          .status(500)
          .json({ message: "Server internal error: " + error });

      response.status(201).json({
        id: result.insertId,
        email,
        firstName,
        lastName,
        phoneNumber,
      });
    }
  );
});

// Post method for Login
// Post method for Login (Corrected)
// Post method for Login (Final Corrected Version with Case Sensitivity Fix)
app.post("/users/login", async (request, response) => {
    const email = request.body.email;
    const password = request.body.password;

    // Input validation: ensure both fields are present
    if (!email || !password) {
        return response.status(400).json({ message: "Email and password are required." });
    }

    db.query(
        "SELECT * FROM users WHERE Email = ?", // Query by Email column
        [email],
        async (error, result) => {
            if (error) {
                // Handle database server error
                console.error("Database Query Error:", error);
                return response.status(500).json({ message: "Server internal error." });
            }

            try {
                // CRITICAL CHECK 1: Ensure user exists
                if (!result || result.length === 0) {
                    return response.status(401).json({ message: "Login Failed: Invalid Email or Password." });
                }

                const user = result[0];
                
                // ⭐ CASE SENSITIVITY FIX APPLIED HERE:
                // Accessing the properties with the correct initial uppercase: Password, FirstName, etc.
                const dbPassword = user.Password; 
                const firstName = user.FirstName;
                const lastName = user.LastName;
                const phoneNumber = user.PhoneNumber;
                const userEmail = user.Email; // Use the email from the DB result

                // CRITICAL CHECK 2: Ensure password hash is not NULL/undefined
                if (!dbPassword) {
                    console.error("CRASH DEBUG: Password hash is missing for user:", userEmail);
                    return response.status(500).json({ message: "User data is corrupt. Cannot login." });
                }

                // Check password
                const isPassword = await bcrypt.compare(password, dbPassword);

                if (isPassword) {
                    const secretKey = "abcd"; // NOTE: Use an environment variable for a real secret key
                    const token = jwt.sign(
                        { 
                            id: user.id, 
                            firstName: firstName, 
                            lastName: lastName, 
                            phoneNumber: phoneNumber, 
                            email: userEmail 
                        }, 
                        secretKey, 
                        { expiresIn: "1h" }
                    );
                    
                    response.status(200).json({ 
                        message: "Login Successfully", 
                        token: token,
                        user: {
                            firstName: firstName,
                            email: userEmail
                        }
                    });
                } else {
                    // Password mismatch
                    response.status(401).json({ message: "Login Failed: Invalid Email or Password." });
                }
            } catch (runtimeError) {
                // Catch any unexpected crash (e.g., if a column was still missing)
                console.error("CRASH POINT DEBUG:", runtimeError);
                return response.status(500).json({ message: "An unexpected error occurred during login." });
            }
        }
    );
});




app.listen(3500, () => {
  console.log("Server is running on port 3500");
});
