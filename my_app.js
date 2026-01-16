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
const fs = require("fs");
const PORT = process.env.PORT
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));



//--------[-]--------\\
// --- Updated Multer Storage Configuration ---
const storage = multer.diskStorage({
  destination: (request, file, cb) => {
    // We use path.join with __dirname to be 100% sure we find the right folder on Linux
    const uploadPath = path.join(__dirname, "profileImages"); 
    
    // Automatically create the folder if it's missing (helps on new deployments)
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath); 
  },
  filename: (request, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

// Configuration for Category Images
const categoryUploadPath = path.join(__dirname, "categoryImages");
const categoryStorage = multer.diskStorage({
  destination: (request, file, cb) => {
    if (!fs.existsSync(categoryUploadPath)) {
      fs.mkdirSync(categoryUploadPath, { recursive: true });
    }
    cb(null, categoryUploadPath);
  },
  filename: (request, file, cb) => {
    cb(null, "cat-" + Date.now() + path.extname(file.originalname));
  },
});
const uploadCategory = multer({ storage: categoryStorage });
app.use("/categoryImages", express.static(categoryUploadPath));


// Configuration for Banner Images
const bannerUploadPath = path.join(__dirname, "bannerImages");
const bannerStorage = multer.diskStorage({
  destination: (request, file, cb) => {
    if (!fs.existsSync(bannerUploadPath)) {
      fs.mkdirSync(bannerUploadPath, { recursive: true });
    }
    cb(null, bannerUploadPath);
  },
  filename: (request, file, cb) => {
    cb(null, "banner-" + Date.now() + path.extname(file.originalname));
  },
});
const uploadBanner = multer({ storage: bannerStorage });
app.use("/bannerImages", express.static(bannerUploadPath));


// Configuration for Brand Images
const brandUploadPath = path.join(__dirname, "brandImages");
const brandStorage = multer.diskStorage({
  destination: (request, file, cb) => {
    if (!fs.existsSync(brandUploadPath)) {
      fs.mkdirSync(brandUploadPath, { recursive: true });
    }
    cb(null, brandUploadPath);
  },
  filename: (request, file, cb) => {
    // Prefixing with 'brand-' for organization
    cb(null, "brand-" + Date.now() + path.extname(file.originalname));
  },
});
const uploadBrand = multer({ storage: brandStorage });
app.use("/brandImages", express.static(brandUploadPath));

// Configuration for Product Thumbnails
const productUploadPath = path.join(__dirname, "productImages");
const productStorage = multer.diskStorage({
  destination: (request, file, cb) => {
    if (!fs.existsSync(productUploadPath)) {
      fs.mkdirSync(productUploadPath, { recursive: true });
    }
    cb(null, productUploadPath);
  },
  filename: (request, file, cb) => {
   cb(null, Date.now() + "-" + file.originalname);
  },
});
const uploadProduct = multer({ storage: productStorage });
app.use("/productImages", express.static(productUploadPath));

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

// Get a specific user's details by ID
app.get("/get/users/:id", async (request, response) => {
  try {
    // 1. Extract the ID from the URL parameters
    const userId = request.params.id;

    // 2. Query the database for that specific ID
    // We select specific fields for security (don't send the PasswordHash back!)
    const [result] = await db.query(
      "SELECT id, Email, FirstName, LastName, PhoneNumber, UserProfile FROM users WHERE id = ?", 
      [userId]
    );

    // 3. Check if a user was actually found
    if (result.length > 0) {
      // Return the first (and only) user in the array
      response.status(200).json(result[0]);
    } else {
      // If the array is empty, the user doesn't exist
      response.status(404).json({ message: "User not found." });
    }

  } catch (error) {
    console.error("Error fetching user by ID:", error);
    response.status(500).json({ message: "Internal server error." });
  }
});




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

// Updated Route: No 'authenticateToken', supports Profile Pic + Info
// Ensure this is placed AFTER your 'const upload = multer(...)' line




//

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 5 }, // 5MB limit
});

// Use absolute path for static serving
app.use("/profileImages", express.static(path.join(__dirname, "profileImages")));

// --- Updated Profile Picture Route ---
app.post(
  "/users/profile-picture",
  authenticateToken,
  upload.single("profilePic"),
  async (request, response) => {
    const userId = request.user.id;

    if (!request.file) {
      return response.status(400).json({
        message: "File upload failed. Ensure you use the 'profilePic' field in form-data.",
      });
    }

    // Use forward slashes for the database string to stay URL-friendly
    const newFileName = path.basename(request.file.path);
    const dbSavePath = `profileImages/${newFileName}`;

    try {
      const [userCheck] = await db.query(
        "SELECT UserProfile FROM users WHERE id = ?",
        [userId]
      );

      if (userCheck.length === 0) {
        if (fs.existsSync(request.file.path)) fs.unlinkSync(request.file.path); 
        return response.status(404).json({ message: "User not found." });
      }

      const oldFilePath = userCheck[0].UserProfile;

      await db.query(
        "UPDATE users SET UserProfile = ? WHERE id = ?",
        [dbSavePath, userId]
      );

      // Cleanup old file
      if (oldFilePath && oldFilePath !== dbSavePath) {
        const fullOldPath = path.join(__dirname, oldFilePath);
        if (fs.existsSync(fullOldPath)) {
          fs.unlinkSync(fullOldPath);
        }
      }

      const publicURL = `${request.protocol}://${request.get('host')}/${dbSavePath}`;
      return response.status(200).json({
        message: "Profile picture updated successfully.",
        profileURL: publicURL,
      });

    } catch (error) {
      console.error("UPLOAD ERROR:", error);
      if (request.file && fs.existsSync(request.file.path)) {
        fs.unlinkSync(request.file.path); 
      }
      return response.status(500).json({ message: "Internal server error during upload." });
    }
  }
);

app.put("/users/:id", (req, res, next) => {
  // We wrap it in a custom function to catch "upload" reference errors
  upload.single("profilePic")(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      return res.status(400).json({ message: "File too large or invalid." });
    } else if (err) {
      return res.status(500).json({ message: "Upload error." });
    }
    next();
  });
}, async (request, response) => {
  const userIdFromParams = parseInt(request.params.id, 10);

  if (isNaN(userIdFromParams)) {
    return response.status(400).json({ message: "Invalid User ID format." });
  }

  const { firstName, lastName, phoneNumber } = request.body;
  let updateFields = [];
  let queryParams = [];

  // Update logic for text
  if (firstName) { updateFields.push("FirstName = ?"); queryParams.push(firstName); }
  if (lastName) { updateFields.push("LastName = ?"); queryParams.push(lastName); }
  if (phoneNumber) { updateFields.push("PhoneNumber = ?"); queryParams.push(phoneNumber); }

  // Update logic for image
  if (request.file) {
    const dbSavePath = `profileImages/${path.basename(request.file.path)}`;
    updateFields.push("UserProfile = ?");
    queryParams.push(dbSavePath);
  }

  if (updateFields.length === 0) {
    return response.status(400).json({ message: "No fields to update." });
  }

  try {
    const sqlQuery = `UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`;
    queryParams.push(userIdFromParams);

    const [result] = await db.query(sqlQuery, queryParams);

    if (result.affectedRows === 0) {
      return response.status(404).json({ message: "User not found." });
    }

    response.status(200).json({ message: "Updated successfully" });
  } catch (error) {
    console.error(error);
    response.status(500).json({ message: "Database error" });
  }
});



// DELETE user by ID (Self-deletion only)
app.delete("/users/:id", authenticateToken, async (request, response) => {
  // 1. Get IDs
  const userIdFromParams = parseInt(request.params.id, 10); // ID in URL
  const userIdFromToken = request.user.id;                  // ID from JWT

  // 2. Security Check: Compare the token ID with the requested ID
  if (userIdFromToken !== userIdFromParams) {
    return response.status(403).json({
      message: "Forbidden: You can only delete your own account.",
    });
  }

  try {
    // 3. Find user to get the profile image path (for file cleanup)
    const [user] = await db.query("SELECT UserProfile FROM users WHERE id = ?", [userIdFromParams]);
    
    if (user.length === 0) {
      return response.status(404).json({ message: "User not found." });
    }

    const profilePath = user[0].UserProfile;

    // 4. Delete the user from the database
    const [result] = await db.query("DELETE FROM users WHERE id = ?", [userIdFromParams]);

    if (result.affectedRows > 0) {
      // 5. Cleanup: Delete the actual file from the 'profileImages' folder
      if (profilePath) {
        const fullPath = path.join(__dirname, profilePath);
        if (fs.existsSync(fullPath)) {
          fs.unlinkSync(fullPath);
        }
      }

      return response.status(200).json({ message: "Your account has been deleted successfully." });
    } else {
      return response.status(404).json({ message: "User not found." });
    }
  } catch (error) {
    console.error("Delete user error:", error);
    return response.status(500).json({ message: "Internal server error while deleting user." });
  }
});

// 1. GET all categories (Now with full URLs)
app.get("/categories", async (request, response) => {
  try {
    const [categories] = await db.query("SELECT * FROM Categories");
    
    // Map through categories to add the full server URL to the image path
    const categoriesWithUrls = categories.map(cat => ({
      ...cat,
      image: cat.image ? `${request.protocol}://${request.get('host')}/${cat.image}` : null
    }));

    response.status(200).json(categoriesWithUrls);
  } catch (error) {
    console.error("Error fetching categories:", error);
    response.status(500).json({ message: "Internal server error." });
  }
});

// 2. GET only featured categories (Now with full URLs)
app.get("/categories/featured", async (request, response) => {
  try {
    const [featured] = await db.query("SELECT * FROM Categories WHERE isFeatured = 1");
    
    const featuredWithUrls = featured.map(cat => ({
      ...cat,
      image: cat.image ? `${request.protocol}://${request.get('host')}/${cat.image}` : null
    }));

    response.status(200).json(featuredWithUrls);
  } catch (error) {
    console.error("Error fetching featured categories:", error);
    response.status(500).json({ message: "Internal server error." });
  }
});

// 3. POST - Add a new category (With Multer)
app.post("/categories", uploadCategory.single("image"), async (request, response) => {
  const { name, parentId, isFeatured } = request.body;

  if (!name) {
    return response.status(400).json({ message: "Category name is required." });
  }

  const dbSavePath = request.file ? `categoryImages/${request.file.filename}` : null;

  try {
    const featuredValue = (isFeatured === "true" || isFeatured === "1" || isFeatured === true) ? 1 : 0;

    const [result] = await db.query(
      "INSERT INTO Categories (name, image, parentId, isFeatured) VALUES (?, ?, ?, ?)",
      [name, dbSavePath, parentId || null, featuredValue]
    );

    response.status(201).json({
      message: "Category created successfully",
      id: result.insertId,
      image: dbSavePath ? `${request.protocol}://${request.get('host')}/${dbSavePath}` : null
    });
  } catch (error) {
    console.error("Error creating category:", error);
    response.status(500).json({ message: "Internal server error." });
  }
});

// 4. DELETE a category (With File Cleanup)
app.delete("/categories/:id", async (request, response) => {
  const categoryId = request.params.id;
  try {
    // First, find the image path to delete the file
    const [category] = await db.query("SELECT image FROM Categories WHERE id = ?", [categoryId]);
    
    if (category.length === 0) {
      return response.status(404).json({ message: "Category not found." });
    }

    const imagePath = category[0].image;

    // Delete from Database
    await db.query("DELETE FROM Categories WHERE id = ?", [categoryId]);

    // Delete the physical file from the server folder
    if (imagePath) {
      const fullPath = path.join(__dirname, imagePath);
      if (fs.existsSync(fullPath)) {
        fs.unlinkSync(fullPath);
      }
    }

    response.status(200).json({ message: "Category and associated image deleted successfully." });
  } catch (error) {
    console.error("Error deleting category:", error);
    response.status(500).json({ message: "Internal server error." });
  }
});


// --- Banner Routes ---

// POST - Add a new banner with an image file
app.post("/banners", uploadBanner.single("image"), async (request, response) => {
  const { active, targetScreen } = request.body;

  // 1. Validation: Image and TargetScreen are required
  if (!request.file) {
    return response.status(400).json({ message: "Banner image is required." });
  }
  if (!targetScreen) {
    return response.status(400).json({ message: "targetScreen is required." });
  }

  // Generate unique bannerId (VARCHAR 50)
  const bannerId = crypto.randomBytes(12).toString("hex");
  const dbSavePath = `bannerImages/${request.file.filename}`;

  try {
    // Convert 'active' string from form-data to boolean/tinyint
    const activeValue = (active === "true" || active === "1" || active === true) ? 1 : 0;

    const [result] = await db.query(
      "INSERT INTO Banners (bannerId, active, imageUrl, targetScreen) VALUES (?, ?, ?, ?)",
      [bannerId, activeValue, dbSavePath, targetScreen]
    );

    response.status(201).json({
      success: true,
      message: "Banner created successfully",
      data: {
        bannerId,
        active: !!activeValue,
        imageUrl: `${request.protocol}://${request.get('host')}/${dbSavePath}`,
        targetScreen
      }
    });
  } catch (error) {
    console.error("Error creating banner:", error);
    
    // Cleanup: If DB fails, delete the uploaded file
    if (request.file) {
      fs.unlinkSync(request.file.path);
    }
    
    response.status(500).json({ message: "Internal server error." });
  }
});

// GET - Get all banners (Useful for your Flutter Carousel)
app.get("/banners", async (request, response) => {
  try {
    const [banners] = await db.query("SELECT * FROM Banners");
    const bannersWithUrls = banners.map(b => ({
      ...b,
      active: !!b.active, // ensure it returns as boolean
      imageUrl: `${request.protocol}://${request.get('host')}/${b.imageUrl}`
    }));
    response.status(200).json(bannersWithUrls);
  } catch (error) {
    console.error("Error fetching banners:", error);
    response.status(500).json({ message: "Internal server error." });
  }
});

// POST - Add a new Brand (With Multer for Image)
app.post("/brands", uploadBrand.single("image"), async (request, response) => {
  const { name, isFeatured, productsCount } = request.body;

  // 1. Validation
  if (!name) {
    return response.status(400).json({ message: "Brand name is required." });
  }
  if (!request.file) {
    return response.status(400).json({ message: "Brand image is required." });
  }

  // Use the alphanumeric ID logic (similar to your Firestore screenshot)
  const brandId = crypto.randomBytes(10).toString("hex");
  const dbSavePath = `brandImages/${request.file.filename}`;

  try {
    // Convert boolean types for SQL (0 or 1)
    const featuredValue = (isFeatured === "true" || isFeatured === "1" || isFeatured === true) ? 1 : 0;
    const countValue = parseInt(productsCount) || 0;

    const [result] = await db.query(
      "INSERT INTO Brands (id, name, image, isFeatured, productsCount) VALUES (?, ?, ?, ?, ?)",
      [brandId, name, dbSavePath, featuredValue, countValue]
    );

    response.status(201).json({
      success: true,
      message: "Brand created successfully",
      data: {
        id: brandId,
        name,
        image: `${request.protocol}://${request.get('host')}/${dbSavePath}`,
        isFeatured: !!featuredValue,
        productsCount: countValue
      }
    });
  } catch (error) {
    console.error("Error creating brand:", error);
    
    // Cleanup: Remove file if DB insert fails
    if (request.file) {
      fs.unlinkSync(request.file.path);
    }
    
    response.status(500).json({ message: "Internal server error." });
  }
});


// GET - Get all Brands (Required for your Flutter UI)
app.get("/brands", async (request, response) => {
  try {
    const [brands] = await db.query("SELECT * FROM Brands");
    
    const brandsWithUrls = brands.map(brand => ({
      ...brand,
      isFeatured: brand.isFeatured === 1 || brand.isFeatured === true, 
      image: brand.image ? `${request.protocol}://${request.get('host')}/${brand.image}` : null
    }));

    response.status(200).json(brandsWithUrls);
  } catch (error) {
    console.error("Error fetching brands:", error);
    response.status(500).json({ message: "Internal server error." });
  }
});



app.post("/products", (req, res, next) => {
    if (!fs.existsSync("productImages")) {
        fs.mkdirSync("productImages", { recursive: true });
    }
    next();
}, uploadProduct.fields([
    { name: 'thumbnail', maxCount: 1 },
    { name: 'images', maxCount: 10 }
]), async (request, response) => {
    try {
        if (!request.body || Object.keys(request.body).length === 0) {
            return response.status(400).json({ message: "No data received" });
        }

        // --- 1. PRE-VALIDATE JSON FIELDS ---
        // We do this before destructuring to prevent 'null' from ever reaching a .map()
        const safeParse = (data) => {
            if (!data || data === "null" || data === "undefined" || data === "" || data === "[]") return [];
            try {
                return typeof data === 'string' ? JSON.parse(data) : data;
            } catch (e) { return []; }
        };

        const rawAttributes = safeParse(request.body.productAttributes);
        const rawVariations = safeParse(request.body.productVariations);

        const {
            id, title, stock, sku, price, salePrice, 
            isFeatured, productType, description, categoryId,
            brand 
        } = request.body;

        // --- 2. HANDLE FILE PATHS & MAPPING ---
        const fileMapping = {};
        const thumbnailPath = (request.files && request.files['thumbnail']) 
            ? `productImages/${request.files['thumbnail'][0].filename}` 
            : null; 
        
        if (request.files && request.files['thumbnail']) {
            const thumbFile = request.files['thumbnail'][0];
            fileMapping[`productImages/${thumbFile.originalname}`] = `productImages/${thumbFile.filename}`;
        }

        if (request.files && request.files['images']) {
            request.files['images'].forEach(file => {
                fileMapping[`productImages/${file.originalname}`] = `productImages/${file.filename}`;
            });
        }

        const finalImages = Object.values(fileMapping);

        // --- 3. PROCESS VARIATIONS ---
        // Guaranteed to work because rawVariations is already validated as an Array above
        let parsedVariations = [];
        if (Array.isArray(rawVariations)) {
            parsedVariations = rawVariations.map(variation => {
                if (variation && variation.image && fileMapping[variation.image]) {
                    return { ...variation, image: fileMapping[variation.image] };
                }
                return variation;
            });
        }

        // --- 4. DATABASE EXECUTION ---
        const sql = `INSERT INTO Products 
          (id, title, stock, sku, price, salePrice, thumbnail, isFeatured, productType, description, categoryId, date, brand, images, productAttributes, productVariations) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?)`;

        const values = [
            id || crypto.randomBytes(10).toString("hex"), 
            title || "Untitled", 
            parseInt(stock) || 0, 
            sku || null, 
            parseFloat(price) || 0.0, 
            parseFloat(salePrice) || 0.0, 
            thumbnailPath, 
            (isFeatured === "true" || isFeatured === true || isFeatured === 1) ? 1 : 0, 
            productType || "ProductType.single", 
            description || null, 
            categoryId || null, 
            (brand === "null" || !brand) ? JSON.stringify({}) : (typeof brand === 'string' ? brand : JSON.stringify(brand)),
            JSON.stringify(finalImages), 
            JSON.stringify(rawAttributes), 
            JSON.stringify(parsedVariations)
        ];

        await db.query(sql, values);
        
        console.log(`✅ Product ${id} uploaded successfully.`);
        response.status(201).json({ success: true, message: "Product created successfully!", id });

    } catch (error) {
        console.error("DATABASE ERROR:", error.sqlMessage || error.message);
        
        if (request.files) {
            const allFiles = [...(request.files['thumbnail'] || []), ...(request.files['images'] || [])];
            allFiles.forEach(file => {
                if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
            });
        }

        response.status(500).json({ 
            message: "Database Error", 
            error: error.sqlMessage || error.message 
        });
    }
});


app.get("/products", async (request, response) => {
  try {
    // 1. GET Query Parameters from the URL
    const { isFeatured, limit } = request.query;

    // 2. BUILD THE SQL QUERY DYNAMICALLY
    let sql = "SELECT * FROM Products";
    let params = [];

    if (isFeatured === 'true') {
      sql += " WHERE isFeatured = 1"; // MySQL uses 1 for true
    }

    if (limit) {
      sql += " LIMIT ?";
      params.push(parseInt(limit));
    }

    const [rows] = await db.query(sql, params);
    const host = `${request.protocol}://${request.get('host')}`;

    const products = rows.map(product => {
      const brandObj = typeof product.brand === 'string' ? JSON.parse(product.brand) : product.brand;
      const imagesList = typeof product.images === 'string' ? JSON.parse(product.images) : product.images;
      
      // Parse variations to fix their internal image URLs too
      let variations = typeof product.productVariations === 'string' 
          ? JSON.parse(product.productVariations) 
          : product.productVariations;

      if (Array.isArray(variations)) {
        variations = variations.map(v => ({
          ...v,
          image: v.image ? (v.image.startsWith('http') ? v.image : `${host}/${v.image}`) : ""
        }));
      }

      return {
        ...product,
        brand: brandObj ? {
          ...brandObj,
          image: brandObj.image ? (brandObj.image.startsWith('http') ? brandObj.image : `${host}/${brandObj.image}`) : ""
        } : null,
        images: Array.isArray(imagesList) ? imagesList.map(img => img.startsWith('http') ? img : `${host}/${img}`) : [],
        thumbnail: product.thumbnail ? (product.thumbnail.startsWith('http') ? product.thumbnail : `${host}/${product.thumbnail}`) : null,
        productAttributes: typeof product.productAttributes === 'string' ? JSON.parse(product.productAttributes) : product.productAttributes,
        productVariations: variations,
        // Ensure boolean return for Flutter
        isFeatured: product.isFeatured === 1 || product.isFeatured === 'true'
      };
    });

    response.status(200).json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    response.status(500).json({ message: "Internal server error." });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
