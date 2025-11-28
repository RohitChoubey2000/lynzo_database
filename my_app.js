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
 
   try{ 
  const [result]= await db.query(
    "INSERT INTO users (Email, FirstName, LastName, PhoneNumber, Password) VALUES (?,?,?,?,?)",
    [email, firstName, lastName, phoneNumber, passwordHash]
  );
    response.status(201).json({
        id: result.insertId,
        email,
        firstName,
        lastName,
        phoneNumber,
      });

    }

    catch(error){
      console.log("Database insert erro" + error);

      if (error.errno === 1062) {
            return response.status(409).json({ message: "This email address is already registered." });
        }

        return response.status(500).json({ message: "Server internal error. Could not register user." });
    }
});

// Post method for Login
// Post method for Login (Corrected)
// Post method for Login (Final Corrected Version with Case Sensitivity Fix)
// Post method for Login (Rewritten to use ASYNC/AWAIT)
app.post("/users/login", async (request, response) => {
    const email = request.body.email;
    const password = request.body.password;

    // 1. Input validation
    if (!email || !password) {
        return response.status(400).json({ message: "Email and password are required." });
    }

    try {
        // 2. Database Query (Using await and promise-based query)
        const [result] = await db.query("SELECT * FROM users WHERE Email = ?", [email]);

        // CRITICAL CHECK 1: Ensure user exists
        if (result.length === 0) {
            // Use the same message for security (don't reveal if it's the email or password that's wrong)
            return response.status(401).json({ message: "Login Failed: Invalid Email or Password." });
        }

        const user = result[0];
        
        // 3. Retrieve user data (Ensuring correct casing: Password, FirstName, etc.)
        const dbPassword = user.Password; 
        const firstName = user.FirstName;
        const lastName = user.LastName;
        const phoneNumber = user.PhoneNumber;
        const userEmail = user.Email; 

        // CRITICAL CHECK 2: Ensure password hash is not NULL/undefined
        if (!dbPassword) {
            console.error("User data corrupt: Password hash missing for user:", userEmail);
            return response.status(500).json({ message: "User data is corrupt. Cannot login." });
        }

        // 4. Check password
        const isPassword = await bcrypt.compare(password, dbPassword);

        if (isPassword) {
            // 5. Successful Login: Generate Token
            const secretKey = "abcd";
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
            
            return response.status(200).json({ 
                message: "Login Successfully", 
                token: token,
                user: {
                    firstName: firstName,
                    email: userEmail
                }
            });
        } else {
            // Password mismatch
            return response.status(401).json({ message: "Login Failed: Invalid Email or Password." });
        }
    } catch (error) {
        // Catch any database or runtime error (e.g., connection lost)
        console.error("LOGIN ROUTE CRASH/ERROR:", error);
        return response.status(500).json({ message: "Server internal error. Could not process login." });
    }
});




app.listen(3500, () => {
  console.log("Server is running on port 3500");
});
