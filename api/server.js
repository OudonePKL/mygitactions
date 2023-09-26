const express = require("express");
const cors = require("cors");
const app = express();
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const jsonParser = bodyParser.json();
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const secret = "TACA-Shop-@2023";

app.use(cors());

// create the connection database
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "taca_db",
});

// ----------------------- For Admin --------------------------
// For register
app.post("/admin/register", jsonParser, function (req, res) {
  try {
    const username = req.body.username;
    const department = req.body.department;
    const email = req.body.email;
    const tel = req.body.tel;
    const gender = req.body.gender;
    const dob = req.body.dob;
    const password = req.body.password;

    bcrypt.hash(password, saltRounds, function (err, hash) {
      connection.execute(
        "INSERT INTO admins (username, department, email, tel, gender, dob, password) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [username, department, email, tel, gender, dob, hash],
        function (err, result, fields) {
          if (err) {
            res.json({ status: "error", message: err });
            return;
          } else {
            res.json({
              status: "ok",
              username: username,
              email: email,
              department: department,
            });
          }
        }
      );
    });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
});

// For user login
app.post("/admin/login", jsonParser, function (req, res) {
  try {
    const email = req.body.email;
    connection.execute(
      "SELECT * FROM admins WHERE email=?",
      [email],
      function (err, users, fields) {
        if (err) {
          res.json({ status: "error", message: err });
          return;
        }
        if (users.length == 0) {
          res.json({ status: "error", message: "Not Found!" });
          return;
        }
        bcrypt.compare(
          req.body.password,
          users[0].password,
          function (err, isLogin) {
            if (isLogin) {
              var token = jwt.sign({ email: users[0].email }, secret, {
                expiresIn: "2h",
              });
              res.json({
                status: "ok",
                message: "Login Success.",
                token,
                email: users[0].email,
              });
            } else {
              res.json({ status: "error", message: "Login Failed!" });
            }
          }
        );
      }
    );
  } catch {
    res.json({ status: "error", message: err.message });
  }
});

app.post("/admin/authen", jsonParser, function (req, res) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({ status: "ok", decoded });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
});

// ----------------------- For Customer --------------------------
// For register
app.post("/register", jsonParser, function (req, res) {
  try {
    const username = req.body.username;
    const email = req.body.email;
    const tel = req.body.tel;
    const gender = req.body.gender;
    const dob = req.body.dob;
    const password = req.body.password;

    bcrypt.hash(password, saltRounds, function (err, hash) {
      connection.execute(
        "INSERT INTO customers (username, email, tel, gender, dob, password) VALUES (?, ?, ?, ?, ?, ?)",
        [username, email, tel, gender, dob, hash],
        function (err, result, fields) {
          if (err) {
            res.json({ status: "error", message: err });
            return;
          } else {
            res.json({
              status: "ok",
              username: username,
              email: email
            });
          }
        }
      );
    });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
});

// For login
app.post("/login", jsonParser, function (req, res) {
  try {
    const email = req.body.email;
    connection.execute(
      "SELECT * FROM customers WHERE email=?",
      [email],
      function (err, users, fields) {
        if (err) {
          res.json({ status: "error", message: err });
          return;
        }
        if (users.length == 0) {
          res.json({ status: "error", message: "Not Found!" });
          return;
        }
        bcrypt.compare(
          req.body.password,
          users[0].password,
          function (err, isLogin) {
            if (isLogin) {
              var token = jwt.sign({ email: users[0].email }, secret, {
                expiresIn: "2h",
              });
              res.json({
                status: "ok",
                message: "Login Success.",
                token,
                email: users[0].email,
              });
            } else {
              res.json({ status: "error", message: "Login Failed!" });
            }
          }
        );
      }
    );
  } catch {
    res.json({ status: "error", message: err.message });
  }
});

// For check header token address and secret address are match or not when customer is login
app.post("/authen", jsonParser, function (req, res) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({ status: "ok", decoded });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
});


app.listen(3333, function () {
  console.log("Web server listening on part 3333");
});
