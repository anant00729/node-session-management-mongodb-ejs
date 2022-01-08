const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const mongoose = require("mongoose");
const MongoDBStore = require("connect-mongodb-session")(session);
const config = require("config");
const app = express();

const UserModel = require("./models/User");

const DB_URL = process.env.DB_URL || config.get("db_url");

const store = new MongoDBStore({
  uri: DB_URL,
  collection: "mySessions",
});

// Catch errors
store.on("error", function (error) {
  console.log(error);
});

// set the view engine to ejs
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "123123123",
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
    },
    resave: false,
    saveUninitialized: false,
    store: store,
  })
);

mongoose
  .connect(DB_URL)
  .then(() => console.log("successfully connected to mongo db"))
  .catch((err) => console.log(`error in DB connection : ${err.message}`));

const isAuth = (req, res, next) => {
  if (req.session.isAuth) {
    next();
  } else {
    res.redirect("/login");
  }
};

const isNotAuth = (req, res, next) => {
  if (!req.session.isAuth) {
    next();
  } else {
    res.redirect("/");
  }
};

app.get("/login", isNotAuth, (req, res) => {
  res.render("pages/login", { isAuth: req.session.isAuth });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await UserModel.findOne({ email });

  if (!user) {
    return res.redirect("/login");
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (isMatch) {
    req.session.isAuth = true;
    return res.redirect("/");
  } else {
    return res.redirect("/login");
  }
});

app.get("/register", isNotAuth, (req, res) => {
  res.render("pages/register", { isAuth: req.session.isAuth });
});

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    let user = await UserModel.findOne({ email });

    // if user found in the collection
    if (user) {
      res.redirect("/register");
    }

    const hashPassword = await bcrypt.hash(password, 12);

    user = new UserModel({
      username,
      email,
      password: hashPassword,
    });
    await user.save();
    res.redirect("/login");
  } catch (error) {
    res.send(error.message);
  }
});

app.get("/", isAuth, (req, res) => {
  res.render("pages/about", { isAuth: req.session.isAuth });
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) throw err;
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
  console.log(`the app is running on ${PORT}`);
});
