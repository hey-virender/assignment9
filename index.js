import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import encrypt from "mongoose-encryption";
import cookieParser from "cookie-parser";
dotenv.config();

const app = express();
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());
app.use((req, res, next) => {
  res.locals.isAuthenticated = Boolean(req.cookies.user);
  next();
});

mongoose.connect(process.env.MONGO_URI);

const itemSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const secret = "VirenderChauhan";
itemSchema.plugin(encrypt, { secret, encryptedFields: ["password"] });

const Item = mongoose.model("item", itemSchema);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  const user = req.cookies.user;
  if (!user) {
    return res.redirect("/login");
  }
  res.render("secrets");
});

app.post("/register", async (req, res) => {
  const { email, password, confirmPassword } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;

  try {
    if (!email || !password || !confirmPassword) {
      return res.status(400).send("All fields are required");
    }

    if (!emailRegex.test(email)) {
      return res.status(400).send("Invalid email format");
    }

    if (!passwordRegex.test(password)) {
      return res.status(400).send("Password must include uppercase, lowercase, number, and be at least 6 characters");
    }

    if (password !== confirmPassword) {
      return res.status(422).send("Passwords do not match");
    }

    const existingUser = await Item.findOne({ email });
    if (existingUser) {
      return res.status(409).send("User already exists");
    }

    const newUser = new Item({ email, password });
    await newUser.save();

    return res.redirect("/login");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Error during registration");
  }
});


app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).send("All fields are required");
    }

    const user = await Item.findOne({ email });
    if (!user) {
      return res.status(404).send("User not found");
    }

    if (user.password !== password) {
      return res.status(401).send("Invalid credentials");
    }

    res.cookie("user", user.email, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24,
      
    });

    return res.redirect("/secrets");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Error during login");
  }
});


app.post("/logout", (req, res) => {
  res.clearCookie("user");
  res.redirect("/");
})

app.listen(3000, () => {
  console.log("Server started at 3000");
});
