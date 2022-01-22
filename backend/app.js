require("dotenv").config();
require("./database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const useragent = require("express-useragent");
const cors = require("cors");
const app = express();
const auth = require("./auth");
app.use(express.json());
app.use(cors());

// importing user context
const User = require("./user");

// Register
app.post("/register", async (req, res) => {
  // Our register logic starts here

  try {
    // Get user input
    const { fullname, email, password } = req.body;

    // Validate user input
    if (!(email && password && fullname)) {
      res.status(400).send("All input is required");
    }

    // Check if user registered before
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send("User Already Exist");
    }

    if (
      !email
        .toLowerCase()
        .match(
          /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        )
    ) {
      return res.status(409).send("Not Email");
    }

    //Encrypt user password
    encryptedPassword = await bcrypt.hash(password, 10);

    // Create user in our database
    const user = await User.create({
      fullname,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });
    const useragent = req.headers["user-agent"];
    // Create token
    const token = jwt.sign(
      { user_id: user._id, email, useragent },
      process.env.TOKEN_KEY,
      {
        expiresIn: "6h",
      }
    );
    // save user token
    user.token = token;

    // return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  // Login

  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(400).send("All input is required");
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email });
    const useragent = req.headers["user-agent"];
    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email, useragent },
        process.env.TOKEN_KEY,
        {
          expiresIn: "6h",
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    }
    res.status(400).send("Invalid Credentials");
  } catch (err) {
    console.log(err);
  }
});

app.post("/list", auth, async (req, res) => {
  // List Users

  User.find()
    .then(users => res.json(users).send)
    .catch(err => res.status(400).json('Error '+err).send);
});

module.exports = app;
