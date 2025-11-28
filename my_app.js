require('dotenv').config(); // <-- ADD THIS if you are accessing any env vars here
const express = require("express");
const db = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sendEmail = require("./mailer");
const { request } = require("http");
const { error } = require("console");
const app = express();

app.use(express.json());






// For geting Users Details
app.get("/get/users", async (request, response)=>{

  const[result]= await db.query("SELECT *From users");
  response.status(200).json(result);

})

/////////////////////////////////////
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


// --- 1. Request Password Reset (POST /users/forgot-password) ---
app.post("/users/forgot-password", async (request, response) => {
    const email = request.body.email;

    if (!email) {
        return response.status(400).json({ message: "Email is required." });
    }

    try {
        // 1. Find user by email (case-insensitive search might be better: WHERE Email COLLATE utf8mb4_general_ci = ?)
        const [users] = await db.query("SELECT id FROM users WHERE Email = ?", [email]);

        // Security check: Don't confirm if the email exists
        if (users.length === 0) {
            console.log(`Password reset requested for non-existent email: ${email}`);
            return response.status(200).json({ message: "If a user with that email exists, a password reset link has been sent." });
        }

        const userId = users[0].id;

        // 2. Generate token and expiration (1 hour)
        const resetToken = crypto.randomBytes(20).toString('hex');
        const expirationTime = new Date(Date.now() + 3600000); // 1 hour = 3,600,000 milliseconds

        // 3. Store the token and expiry in the database
        // **IMPORTANT: Your users table needs 'resetPasswordToken' and 'resetPasswordExpires' columns**
        await db.query(
            "UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE id = ?",
            [resetToken, expirationTime, userId]
        );

        // 4. Send the email with the reset link
        const resetURL = `https://your-frontend-domain.com/reset-password?token=${resetToken}`;
        const subject = "Password Reset Request";
        const htmlContent = `
            <p>Hello,</p>
            <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
            <p>Please click on the following link, or paste this into your browser to complete the process:</p>
            <p><a href="${resetURL}">RESET PASSWORD LINK</a></p>
            <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
            <p>This link is valid for 1 hour.</p>
        `;

        const emailSent = await sendEmail(email, subject, htmlContent);

        if (!emailSent) {
            // Log the error but still return 200 to the user for security/rate limiting reasons
            return response.status(200).json({ message: "Password reset link sent (but an email service error occurred)." });
        }

        // 5. Success response
        return response.status(200).json({ 
            message: "If a user with that email exists, a password reset link has been sent." 
        });

    } catch (error) {
        console.error("Forgot password route error:", error);
        return response.status(500).json({ message: "Server internal error. Could not process reset request." });
    }
});

// --- 2. Update Password (POST /users/reset-password) ---
app.post("/users/reset-password", async (request, response) => {
    const { token, newPassword } = request.body;

    if (!token || !newPassword) {
        return response.status(400).json({ message: "Token and new password are required." });
    }

    try {
        // 1. Find user by token AND check if the token is not expired (current time > expiry time)
        const [users] = await db.query(
            "SELECT id FROM users WHERE resetPasswordToken = ? AND resetPasswordExpires > NOW()", 
            [token]
        );

        if (users.length === 0) {
            // Token is invalid, missing, or expired.
            return response.status(400).json({ message: "Password reset token is invalid or has expired." });
        }

        const userId = users[0].id;

        // 2. Hash the new password
        const passwordHash = await bcrypt.hash(newPassword, 10);

        // 3. Update the password and clear the token/expiry fields
        await db.query(
            "UPDATE users SET Password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE id = ?",
            [passwordHash, userId]
        );

        // 4. Optionally: Send a success confirmation email here
        // const [user] = await db.query("SELECT Email FROM users WHERE id = ?", [userId]);
        // await sendEmail(user[0].Email, "Password Successfully Changed", "<p>Your password has been successfully updated.</p>");

        return response.status(200).json({ message: "Your password has been successfully updated." });

    } catch (error) {
        console.error("Reset password route error:", error);
        return response.status(500).json({ message: "Server internal error. Could not reset password." });
    }
});


app.listen(3500, () => {
  console.log("Server is running on port 3500");
});
