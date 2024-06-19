const express = require("express");
const app = express();
const port = 3000;
const bodyParser = require("body-parser");
const cors = require("cors");
const mysql = require("mysql");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const util = require("util");

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "dbsystemwd",
});

app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174"],
    methods: ["GET", "POST", "DELETE", "PUT"],
    credentials: true,
  })
);

app.use(cookieParser());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.send("API!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

app.post("/admin/register", async (req, res) => {
  const fullname = req.body.fullname;
  const username = req.body.username;
  const password = req.body.password;
  const sqlInsert =
    "INSERT INTO admin (fullname, username, password) VALUES (?,?,?)";
  const cekUsername = "SELECT * FROM admin WHERE username = ?";

  const generateHash = async (password) => {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  };

  // Generate hash password
  let hashPass = "";
  try {
    hashPass = await generateHash(password);
  } catch (err) {
    console.error("Error generating hash:", err);
    res.status(500).json({ error: "Internal server error" });
    return;
  }

  db.query(cekUsername, username, (err, result) => {
    if (result.length > 0) {
      res.send({ error: "Username sudah ada!" });
    } else {
      db.query(sqlInsert, [fullname, username, hashPass], (err, result) => {
        if (err) {
          res.send({ error: err });
        } else {
          res.send({ success: "Account berhasil di tambahkan!" });
        }
      });
    }
  });
});

app.get("/admin", (req, res) => {
  const sqlSelect = "SELECT * FROM admin ORDER BY admin_id DESC";

  db.query(sqlSelect, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success getting data admin", result });
    }
  });
});

app.delete("/admin/:id", (req, res) => {
  const id = req.params.id;
  const sqlDelete = "DELETE FROM admin WHERE admin_id = ?";

  db.query(sqlDelete, id, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});

app.delete("/multiple/admin", (req, res) => {
  const ids = req.body.ids;
  const sqlDelete = "DELETE FROM admin WHERE admin_id IN (?)";

  if (!ids || ids.length === 0) {
    return res.send({ error: "No data deleted!" });
  }

  db.query(sqlDelete, [ids], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Delete Success!" });
    }
  });
});

app.put("/admin", async (req, res) => {
  const adminId = req.body.adminId;
  const newFullname = req.body.newFullname;
  const newUsername = req.body.newUsername;
  const newPass = req.body.newPass;
  const sqlUpdateWithPass =
    "UPDATE admin SET fullname = ?, username = ?, password = ? WHERE admin_id = ?";
  const sqlUpdateNoPass =
    "UPDATE admin SET fullname = ?, username = ? WHERE admin_id = ?";

  const generateHash = async (password) => {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  };

  // Generate hash password
  let hashPass = "";
  try {
    hashPass = await generateHash(newPass);
  } catch (err) {
    console.error("Error generating hash:", err);
    res.status(500).json({ error: "Internal server error" });
    return;
  }

  if (newPass === "") {
    db.query(
      sqlUpdateNoPass,
      [newFullname, newUsername, adminId],
      (err, result) => {
        if (err) {
          res.send({ error: err });
        } else {
          res.send({ success: "Success" });
        }
      }
    );
  } else {
    db.query(
      sqlUpdateWithPass,
      [newFullname, newUsername, hashPass, adminId],
      (err, result) => {
        if (err) {
          res.send({ error: err });
        } else {
          res.send({ success: "Success" });
        }
      }
    );
  }
});

// ==================== Operator API

app.get("/operator", (req, res) => {
  const sqlSelect =
    "SELECT o.*, ag.name AS agent_name, ag.agent_id FROM operator o JOIN agent ag ON o.agent_id = ag.agent_id ORDER BY user_id DESC";

  db.query(sqlSelect, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success getting data admin", result });
    }
  });
});

app.get("/agent", (req, res) => {
  const sqlSelect = "SELECT * FROM agent ORDER BY agent_id DESC";

  db.query(sqlSelect, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success getting data agent", result });
    }
  });
});

app.post("/operator/register", async (req, res) => {
  const fullname = req.body.fullname;
  const username = req.body.username;
  const password = req.body.password;
  const agent = req.body.agent;
  const role = req.body.role;
  const sqlInsert =
    "INSERT INTO operator (fullname, username, password, agent_id, role) VALUES (?,?,?,?,?)";
  const cekUsername = "SELECT * FROM operator WHERE username = ?";

  const generateHash = async (password) => {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  };

  // Generate hash password
  let hashPass = "";
  try {
    hashPass = await generateHash(password);
  } catch (err) {
    console.error("Error generating hash:", err);
    res.status(500).json({ error: "Internal server error" });
    return;
  }

  db.query(cekUsername, username, (err, result) => {
    if (result.length > 0) {
      res.send({ error: "Username sudah ada!" });
    } else {
      db.query(
        sqlInsert,
        [fullname, username, hashPass, agent, role],
        (err, result) => {
          if (err) {
            res.send({ error: err });
          } else {
            res.send({ success: "Account berhasil di tambahkan!" });
          }
        }
      );
    }
  });
});

app.delete("/operator/:id", (req, res) => {
  const id = req.params.id;
  const sqlDelete = "DELETE FROM operator WHERE user_id = ?";

  db.query(sqlDelete, id, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});

app.delete("/multiple/operator", (req, res) => {
  const ids = req.body.ids;
  const sqlDelete = "DELETE FROM operator WHERE user_id IN (?)";

  if (!ids || ids.length === 0) {
    return res.send({ error: "No data deleted!" });
  }

  db.query(sqlDelete, [ids], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Delete Success!" });
    }
  });
});

app.put("/operator", async (req, res) => {
  const operatorId = req.body.operatorId;
  const newFullname = req.body.newFullname;
  const newUsername = req.body.newUsername;
  const newPass = req.body.newPass;
  const newAgent = req.body.newAgent;
  const newRole = req.body.newRole;
  const sqlUpdateWithPass =
    "UPDATE operator SET fullname = ?, username = ?, password = ?, agent_id = ?, role = ? WHERE user_id = ?";
  const sqlUpdateNoPass =
    "UPDATE operator SET fullname = ?, username = ?, agent_id = ?, role = ? WHERE user_id = ?";

  const generateHash = async (password) => {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  };

  // Generate hash password
  let hashPass = "";
  try {
    hashPass = await generateHash(newPass);
  } catch (err) {
    console.error("Error generating hash:", err);
    res.status(500).json({ error: "Internal server error" });
    return;
  }

  if (newPass === "") {
    db.query(
      sqlUpdateNoPass,
      [newFullname, newUsername, newAgent, newRole, operatorId],
      (err, result) => {
        if (err) {
          res.send({ error: err });
        } else {
          res.send({ success: "Success" });
        }
      }
    );
  } else {
    db.query(
      sqlUpdateWithPass,
      [newFullname, newUsername, hashPass, newAgent, newRole, operatorId],
      (err, result) => {
        if (err) {
          res.send({ error: err });
        } else {
          res.send({ success: "Success" });
        }
      }
    );
  }
});

// Login OP
app.post("/operator/login", (req, res) => {
  const { username, password } = req.body;
  const sql = "SELECT * FROM operator WHERE username = ?";

  db.query(sql, username, async (err, result) => {
    if (err) {
      res.send({ error: err });
      return;
    }

    if (result.length < 1) {
      res.send({ error: "Salah username atau password" });
      return;
    }

    const hashedPassword = result[0].password;

    try {
      const isMatch = await bcrypt.compare(password, hashedPassword);
      if (!isMatch) {
        res.send({ error: "Salah username atau password" });
        return;
      }

      const token = jwt.sign({ success: result[0].user_id }, "secret_key", {
        expiresIn: "1h",
      });

      res.send({ success: "Login Berhasil!", token, username });
    } catch (error) {
      res.send({ error: "Internal Server Error, try again later" });
    }
  });
});

// Get Data Operator Agent
app.get("/operator/agent/:username", (req, res) => {
  const username = req.params.username;
  const sql =
    "SELECT op.user_id, op.fullname, op.username, op.role, ag.agent_id, ag.name, ag.provider FROM operator op JOIN agent ag ON op.agent_id = ag.agent_id WHERE op.username = ?";

  db.query(sql, username, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "success", result });
    }
  });
});

// Operator Input Data WD
app.post("/operator/input", (req, res) => {
  const {
    operatorId,
    agentId,
    username,
    memberWdTime,
    bank,
    accountName,
    accountNumber,
    nominal,
    lastBalance,
  } = req.body;
  const status = "pending";
  const sqlInsert =
    "INSERT INTO data_wd (operator_id, agent_id, member_username, bank_name, account_name, account_number, nominal, last_balance, status, wd_time) VALUES (?,?,?,?,?,?,?,?,?,?)";

  const checkDuplicateQuery =
    "SELECT * FROM data_wd WHERE nominal = ? AND wd_time = ?";

  if (
    operatorId === "" ||
    agentId === "" ||
    username === "" ||
    memberWdTime === "" ||
    bank === "" ||
    accountName === "" ||
    accountNumber === "" ||
    nominal === "" ||
    lastBalance === ""
  ) {
    res.send({
      error: "Please fill all the fields",
      message: "Please fill all the fields",
    });
    return;
  }

  const values = [
    operatorId,
    agentId,
    username,
    bank,
    accountName,
    accountNumber,
    nominal,
    lastBalance,
    status,
    memberWdTime,
  ];

  db.query(checkDuplicateQuery, [nominal, memberWdTime], (err, result) => {
    if (err) {
      res.send({ error: err, message: "Response error checking data" });
    } else if (result.length > 0) {
      res.send({ error: "Data duplicate", message: "Duplicate data found!" });
    } else {
      db.query(sqlInsert, values, (err, result) => {
        if (err) {
          res.send({ error: err, message: "Response error from server!" });
        } else {
          res.send({
            success: "Data WD successfully inserted",
            message: "Data berhasil di input",
          });
        }
      });
    }
  });
});

// Getting Data wd when agent equal
app.get("/operator/datawd/:agent", (req, res) => {
  const agentId = req.params.agent;
  const sql = "SELECT * FROM data_wd WHERE agent_id = ? AND status != 'close'";

  db.query(sql, agentId, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success", result });
    }
  });
});

// Op Pull Request
app.put("/operator/pullrequest/:id", (req, res) => {
  const dataId = req.params.id;
  const sql = "UPDATE data_wd SET status = 'pulled' WHERE data_wd_id = ?";

  db.query(sql, dataId, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});

// Op pull multiple request
app.put("/operator/multiplepullrequest", (req, res) => {
  const selectedItems = req.body.selectedItems;
  const sql = "UPDATE data_wd SET status = 'pulled' WHERE data_wd_id IN (?)";

  if (!selectedItems || selectedItems.length === 0) {
    res.send({ error: "Tidak ada item yang dipilih!" });
    return;
  }

  db.query(sql, [selectedItems], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});