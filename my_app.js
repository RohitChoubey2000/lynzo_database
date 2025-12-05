require("dotenv").config(); // <-- ADD THIS if you are accessing any env vars here
const express = require("express");
const db = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sendEmail = require("./mailer");
const { request } = require("http");
const { error } = require("console");
const multer = require("multer");
const path = require("path");
const app = express();
app.use(express.json());




// --- CRITICAL AUTHENTICATION MIDDLEWARE ---
// This function verifies the JWT token sent in the Authorization header
const authenticateToken = (request, response, next) => {
  // Expects: Authorization: Bearer <token>
  const authHeader = request.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1]; // Get the token part
  const secretKey = "abcd"; // MUST match the secret key used in login/token generation

  if (!token) {
    return response
      .status(401)
      .json({ message: "Access denied. Token is missing." });
  }

  jwt.verify(token, secretKey, (error, user) => {
    if (error) {
      // Error could be 'Token expired' or 'Invalid signature'
      return response
        .status(403)
        .json({ message: "Invalid or expired token." });
    }
    // Attach the decoded user payload (id, email, etc.) to the request
    request.user = user;
    next(); // Proceed to the route handler
  });
};

// ------------------------------------------




// For geting Users Details
app.get("/get/users", async (request, response) => {
  const [result] = await db.query("SELECT *From users");
  response.status(200).json(result);
});
// Protected route to get user details based on token
app.get("/users", authenticateToken, (request, response) => {
  // The user information is already available in request.user from the middleware
  response.status(200).json(request.user);
});




// Post Method to add new user
app.post("/users/signup", async (request, response) => {
  const email = request.body.email;
  const firstName = request.body.firstName;
  const lastName = request.body.lastName;
  const phoneNumber = request.body.phoneNumber;
  const password = request.body.password;
  const passwordHash = await bcrypt.hash(password, 10);

  try {
    const [result] = await db.query(
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
  } catch (error) {
    console.log("Database insert erro" + error);

    if (error.errno === 1062) {
      return response
        .status(409)
        .json({ message: "This email address is already registered." });
    }

    return response
      .status(500)
      .json({ message: "Server internal error. Could not register user." });
  }
});



// -----[Post method for Login ()]-----

app.post("/users/login", async (request, response) => {
  const email = request.body.email;
  const password = request.body.password;
  // 1. Input validation
  if (!email || !password) {
    return response
      .status(400)
      .json({ message: "Email and password are required." });
  }
  try {
    // 2. Database Query (Using await and promise-based query)
    const [result] = await db.query("SELECT * FROM users WHERE Email = ?", [
      email,
    ]);

    // CRITICAL CHECK 1: Ensure user exists
    if (result.length === 0) {
      // Use the same message for security (don't reveal if it's the email or password that's wrong)
      return response
        .status(401)
        .json({ message: "Login Failed: Invalid Email or Password." });
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
      console.error(
        "User data corrupt: Password hash missing for user:",
        userEmail
      );
      return response
        .status(500)
        .json({ message: "User data is corrupt. Cannot login." });
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
          email: userEmail,
        },
        secretKey,
        { expiresIn: "1h" }
      );
      return response.status(200).json({
        message: "Login Successfully",
        token: token,
        user: {
          id: user.id,
          firstName: firstName,
          email: userEmail,
        },
      });
    } else {
      // Password mismatch
      return response
        .status(401)
        .json({ message: "Login Failed: Invalid Email or Password." });
    }
  } catch (error) {
    // Catch any database or runtime error (e.g., connection lost)
    console.error("LOGIN ROUTE CRASH/ERROR:", error);
    return response
      .status(500)
      .json({ message: "Server internal error. Could not process login." });
  }
});


// --- 1. Request Password Reset (POST /users/forgot-password) ---
app.post("/users/forgot-password", async (request, response) => {
  const email = request.body.email;

  if (!email) {
    return response.status(400).json({ message: "Email is required." });
  }

  try {
    // 1. Find user by email
    const [users] = await db.query("SELECT id FROM users WHERE Email = ?", [
      email,
    ]);

    // Security check: Don't confirm if the email exists
    if (users.length === 0) {
      console.log(`Password reset requested for non-existent email: ${email}`);
      return response.status(200).json({
        message:
          "If a user with that email exists, a password reset link has been sent.",
      });
    }

    const userId = users[0].id;

    // 2. Generate token and expiration (1 hour)
    const resetToken = crypto.randomBytes(20).toString("hex");
    const expirationTime = new Date(Date.now() + 3600000); // 1 hour = 3,600,000 milliseconds

    // 3. Store the token and expiry in the database
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
      return response.status(200).json({
        message:
          "Password reset link sent (but an email service error occurred).",
      });
    }
    // 5. Success response
    return response.status(200).json({
      message:
        "If a user with that email exists, a password reset link has been sent.",
    });
  } catch (error) {
    console.error("Forgot password route error:", error);
    return response.status(500).json({
      message: "Server internal error. Could not process reset request.",
    });
  }
});


// --- 2. Update Password (POST /users/reset-password) ---
app.post("/users/reset-password", async (request, response) => {
  const { token, newPassword } = request.body;

  if (!token || !newPassword) {
    return response
      .status(400)
      .json({ message: "Token and new password are required." });
  }

  try {
    // 1. Find user by token AND check if the token is not expired
    const [users] = await db.query(
      "SELECT id FROM users WHERE resetPasswordToken = ? AND resetPasswordExpires > NOW()",
      [token]
    );

    if (users.length === 0) {
      // Token is invalid, missing, or expired.
      return response
        .status(400)
        .json({ message: "Password reset token is invalid or has expired." });
    }

    const userId = users[0].id;

    // 2. Hash the new password
    const passwordHash = await bcrypt.hash(newPassword, 10);

    // 3. Update the password and clear the token/expiry fields
    await db.query(
      "UPDATE users SET Password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE id = ?",
      [passwordHash, userId]
    );

    return response
      .status(200)
      .json({ message: "Your password has been successfully updated." });
  } catch (error) {
    console.error("Reset password route error:", error);
    return response
      .status(500)
      .json({ message: "Server internal error. Could not reset password." });
  }
});

// Requires a valid JWT token. Allows self-update OR Admin-update.
app.put("/users/:id", authenticateToken, async (request, response) => {
  // Ensure the ID from the URL is treated as a number for safe comparison
  const userIdFromParams = parseInt(request.params.id, 10);
  const userIdFromToken = request.user.id;
  // Assuming the isAdmin flag is included in the token payload after login
  const isAdmin = request.user.isAdmin === 1 || request.user.isAdmin === true;

  const { firstName, lastName, phoneNumber } = request.body;

  // 1. Security Check: Allow update if the token ID matches the URL ID OR the user is an Admin.
  const isSelfUpdate = userIdFromToken === userIdFromParams;

  if (!isSelfUpdate && !isAdmin) {
    return response.status(403).json({
      message:
        "Forbidden: You can only update your own account unless you are an administrator.",
    });
  }
  // 2. Build the dynamic SQL query
  let updateFields = [];
  let queryParams = [];

  if (firstName) {
    updateFields.push("FirstName = ?");
    queryParams.push(firstName);
  }
  if (lastName) {
    updateFields.push("LastName = ?");
    queryParams.push(lastName);
  }
  if (phoneNumber) {
    updateFields.push("PhoneNumber = ?");
    queryParams.push(phoneNumber);
  }
  // If no fields are provided in the body
  if (updateFields.length === 0) {
    return response.status(400).json({ message: "No update fields provided." });
  }
  // 3. Execute the update query
  const sqlQuery = `UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`;
  queryParams.push(userIdFromParams); // Add the target user ID at the end

  try {
    const [result] = await db.query(sqlQuery, queryParams);

    if (result.affectedRows === 0) {
      return response
        .status(404)
        .json({ message: "User not found or no changes made." });
    }

    return response.status(200).json({
      message: `User (ID: ${userIdFromParams}) profile updated successfully.`,
      updatedFields: { firstName, lastName, phoneNumber },
    });
  } catch (error) {
    console.error("User update error:", error);
    // Catch database errors, potentially the unique constraint violation (though less likely on update)
    return response
      .status(500)
      .json({ message: "Server internal error. Could not update user." });
  }
});


//--------[-]--------\\

// --- MULTER STORAGE CONFIGURATION ---
const storage = multer.diskStorage({
  // The directory where uploaded files will be stored.
  // IMPORTANT: This 'profileImages' folder MUST be created in your project root.
  destination: (request, file, cb) => {
    cb(null, "./profileImages");
  },
  // Define the filename structure to avoid conflicts
  filename: (request, file, cb) => {
    // Generate a unique filename: current timestamp + original file extension
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

// Create the Multer upload instance
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // Optional: Limit file size to 5MB
});

// --- STATIC FILE SERVER ---
// Makes the profileImages folder accessible via a public URL
// e.g., http://localhost:3500/profileImages/1761380677453.png
app.use("/profileImages", express.static(path.join(__dirname, 'profileImages')));

// --- UPLOAD/UPDATE PROFILE PICTURE ROUTE (UNPROTECTED by JWT) ---
// ROUTE: POST /api/user/profile-picture
// Requires the user's email in the form-data body to identify the user.
app.post(
  "/api/user/profile-picture",
  // 1. Multer middleware still handles the file upload (key must be 'profilePic')
  upload.single("profilePic"), 
  async (request, response) => {
    
    // 2. Get the file and email from the request body
    const email = request.body.email;
    
    // 3. Basic Validation Checks
    if (!email) {
      // Must have the email to identify the user
      return response.status(400).json({
        message: "Email is required in the form-data to identify the user.",
      });
    }

    if (!request.file) {
      // Must have the file to upload
      return response.status(400).json({
        message: "File upload failed. Please ensure the file is sent with the key 'profilePic'.",
      });
    }

    // The path is relative to the server and will be stored in the DB
    const filePath = `profileImages/${request.file.filename}`; // e.g., "profileImages/1761380677453.png"

    try {
      // 4. Update the database: Find the user by Email and set the UserProfile path
      const [result] = await db.query(
        // Use the Email column to match the user
        "UPDATE users SET UserProfile = ? WHERE Email = ?",
        [filePath, email]
      );

      if (result.affectedRows === 0) {
        // If the update failed (email not found)
        return response.status(404).json({ 
            message: `User with email '${email}' not found. Profile picture not updated.` 
        });
      }

      // 5. Success Response
      return response.status(200).json({
        message: "Profile picture uploaded and database updated successfully.",
        userEmail: email,
        dbPath: filePath,
        // Provide the full public URL for immediate display
        profilePictureUrl: `${request.protocol}://${request.get('host')}/${filePath}`
      });
      
    } catch (error) {
      console.error("Database or file processing error on profile upload:", error);
      return response.status(500).json({
        message: "Server internal error. Could not process profile picture update.",
      });
    }
  }
);





app.listen(3500, () => {
  console.log("Server is running on port 3500");
});
