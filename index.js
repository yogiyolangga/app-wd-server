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
const http = require("http");
const { Server } = require("socket.io");

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "dbsystemwd",
});

const server = http.createServer(app);

app.use(
  cors({
    origin: ["http://192.168.20.11:5173", "http://192.168.20.11:5174"],
    methods: ["GET", "POST", "DELETE", "PUT"],
    credentials: true,
  })
);

const io = new Server(server, {
  cors: {
    origin: ["http://192.168.20.11:5173", "http://192.168.20.11:5174"],
    methods: ["GET", "POST", "DELETE", "PUT"],
    credentials: true,
  },
});

io.on("connection", (socket) => {
  console.log(`Client connected : ${socket.id}`);
});

app.use(
  "/uploads/profile",
  express.static(path.join(__dirname, "uploads/profile"))
);

app.use(
  "/uploads/evidence",
  express.static(path.join(__dirname, "uploads/evidence"))
);

app.use(cookieParser());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.send("API!");
});

// app.listen(port, () => {
//   console.log(`Example app listening on port ${port}`);
// });

server.listen(port, "0.0.0.0", () => {
  console.log(`app listening on port ${port}`);
});

// create new admin
app.post("/admin/register", async (req, res) => {
  const fullname = req.body.fullname;
  const username = req.body.username;
  const role = req.body.role;
  const password = req.body.password;
  const sqlInsert =
    "INSERT INTO admin (fullname, username, password, role) VALUES (?,?,?,?)";
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
      db.query(
        sqlInsert,
        [fullname, username, hashPass, role],
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

// mendapatkan data admin
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

// single delete admin account
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

// delete multiple admin
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

// Update data admin
app.put("/admin", async (req, res) => {
  const adminId = req.body.adminId;
  const newFullname = req.body.newFullname;
  const newUsername = req.body.newUsername;
  const newRole = req.body.newRole;
  const newPass = req.body.newPass;
  const sqlUpdateWithPass =
    "UPDATE admin SET fullname = ?, username = ?, password = ?, role = ? WHERE admin_id = ?";
  const sqlUpdateNoPass =
    "UPDATE admin SET fullname = ?, username = ?, role = ? WHERE admin_id = ?";

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
      [newFullname, newUsername, newRole, adminId],
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
      [newFullname, newUsername, hashPass, newRole, adminId],
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

// Admin WD Login
app.post("/adminwd/login", (req, res) => {
  const { username, password } = req.body;
  const sql = "SELECT * FROM admin WHERE username = ?";

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

      res.send({ success: "Login Berhasil!", token, username, result });
    } catch (error) {
      res.send({ error: "Internal Server Error, try again later" });
    }
  });
});

// Getting Admin Data
app.get("/adminwd/dataadmin/:username", (req, res) => {
  const username = req.params.username;
  const sql =
    "SELECT fullname, admin_id, username, role, profile FROM admin WHERE username = ?";

  db.query(sql, [username], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success", result });
    }
  });
});

// Getting Data WD
app.get("/adminwd/datawd", (req, res) => {
  const sql =
    "SELECT dw.*, op.fullname AS operator_name, ag.name AS agent_name, adm.fullname AS admin_name, adm.username AS admin_username, adm.profile FROM data_wd dw JOIN operator op ON dw.operator_id = op.user_id JOIN agent ag ON dw.agent_id = ag.agent_id LEFT JOIN admin adm ON dw.admin_id = adm.admin_id WHERE dw.closed = FALSE AND dw.status != 'pulled'";

  db.query(sql, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success", result });
    }
  });
});

// Get Data Grab by Admin id
app.get("/adminwd/grab/:username", (req, res) => {
  const username = req.params.username;
  const sql =
    "SELECT dw.*, op.fullname AS operator_name, ag.name AS agent_name, adm.username AS admin_username, adm.fullname AS admin_fullname FROM data_wd dw JOIN operator op ON dw.operator_id = op.user_id JOIN agent ag ON dw.agent_id = ag.agent_id JOIN admin adm ON dw.admin_id = adm.admin_id WHERE dw.status = 'grab' AND adm.username = ?";

  db.query(sql, [username], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success", result });
    }
  });
});

// Cancel Data Grab by
app.put("/adminwd/cancelwd/:id", (req, res) => {
  const id = req.params.id;
  const sql = "UPDATE data_wd SET status = 'pending' WHERE data_wd_id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
      io.emit("data_inserted", {
        success: "Success",
        message: "Success",
      });
    }
  });
});

// Confirm Data grab
app.put("/adminwd/confirmwd/:id", (req, res) => {
  const id = req.params.id;
  const sql = "UPDATE data_wd SET status = 'success' WHERE data_wd_id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
      io.emit("data_inserted", {
        success: "Success",
        message: "Success",
      });
    }
  });
});

// Reject Data grab
app.put("/adminwd/rejectwd/:id", (req, res) => {
  const id = req.params.id;
  const sql = "UPDATE data_wd SET status = 'reject' WHERE data_wd_id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
      io.emit("data_inserted", {
        success: "Success",
        message: "Success",
      });
    }
  });
});

// Multiple (Cancel, Reject, Confirm) Action Data Grab
app.put("/adminwd/multipleaction", (req, res) => {
  const { selectedItems, action } = req.body;
  const sql = "UPDATE data_wd SET status = ? WHERE data_wd_id IN (?)";

  db.query(sql, [action, selectedItems], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
      io.emit("data_inserted", {
        success: "Success",
        message: "Success",
      });
    }
  });
});

// Admin WD Grabbing
app.put("/adminwd/grabbing", (req, res) => {
  const { amount, bankName, adminId } = req.body;
  const sql =
    "UPDATE data_wd SET status = 'grab', admin_id = ? WHERE bank_name = ? AND status = 'pending' ORDER BY data_wd_id LIMIT ?";
  const sqlAllBank =
    "UPDATE data_wd SET status = 'grab', admin_id = ? WHERE status = 'pending' ORDER BY data_wd_id LIMIT ?";
  const sqlNoLimit =
    "UPDATE data_wd SET status = 'grab', admin_id = ? WHERE bank_name = ? AND status = 'pending' ORDER BY data_wd_id";
  const sqlNoLimitAllBank =
    "UPDATE data_wd SET status = 'grab', admin_id = ? WHERE status = 'pending' ORDER BY data_wd_id";

  const checkOnProcess =
    "SELECT * FROM data_wd WHERE status = 'grab' AND admin_id = ?";

  db.getConnection((err, connection) => {
    if (err) {
      res.send({ error: err });
      return;
    }

    connection.beginTransaction((err) => {
      if (err) {
        connection.release();
        res.send({ error: err });
        return;
      }

      connection.query(checkOnProcess, [adminId], (err, result) => {
        if (err) {
          connection.rollback(() => {
            connection.release();
            res.send({ error: err });
          });
          return;
        }

        if (result.length > 0) {
          connection.rollback(() => {
            connection.release();
            res.send({ pending: "Selesaikan dulu yang di grab!" });
          });
          return;
        }

        let query;
        let queryParams;

        if (bankName === "all" && amount === 1000) {
          query = sqlNoLimitAllBank;
          queryParams = [adminId];
        } else if (bankName === "all" && amount < 1000) {
          query = sqlAllBank;
          queryParams = [adminId, amount];
        } else if (bankName !== "all" && amount === 1000) {
          query = sqlNoLimit;
          queryParams = [adminId, bankName];
        } else {
          query = sql;
          queryParams = [adminId, bankName, amount];
        }

        connection.query(query, queryParams, (err, result) => {
          if (err) {
            connection.rollback(() => {
              connection.release();
              res.send({ error: err });
            });
            return;
          }

          connection.commit((err) => {
            if (err) {
              connection.rollback(() => {
                connection.release();
                res.send({ error: err });
              });
              return;
            }
            connection.release();
            res.send({ success: "Success" });
            io.emit("data_inserted", {
              success: "Data WD Success Grab",
              message: "Data WD Success Grab",
            });
          });
        });
      });
    });
  });
});

// Admin WD Closing
// app.put("/adminwd/closing", (req, res) => {
//   const { adminId } = req.body;

//   connec

//   db.beginTransaction

//   const insertClosedSql = "INSERT INTO closed (admin_id) VALUES (?)";
//   const updateDataWdSql =
//     "UPDATE data_wd SET closed = TRUE, closed_id = ? WHERE closed = FALSE";
//   db.query(insertClosedSql, [adminId], (err, result) => {
//     if (err) {
//       res.send({ error: err });
//       return;
//     }

//     const newClosedId = result.insertId;

//     db.query(updateDataWdSql, [newClosedId], (err, result) => {
//       if (err) {
//         res.send({ error: err });
//       } else {
//         res.send({ success: "Success Closing" });
//       }
//     });
//   });
// });

// Admin WD Closing
app.put("/adminwd/closing", (req, res) => {
  const { adminId } = req.body;

  // Get a connection from the pool
  db.getConnection((err, connection) => {
    if (err) {
      res.send({ error: err });
      return;
    }

    // Start the transaction
    connection.beginTransaction((err) => {
      if (err) {
        connection.release();
        res.send({ error: err });
        return;
      }

      // SQL for inserting data into the closed table
      const insertClosedSql = "INSERT INTO closed (admin_id) VALUES (?)";

      // Run the query to insert data into the closed table
      connection.query(insertClosedSql, [adminId], (err, result) => {
        if (err) {
          // Rollback if there is an error
          return connection.rollback(() => {
            connection.release();
            res.send({ error: err });
          });
        }

        // Get the new closed ID
        const newClosedId = result.insertId;

        // SQL for updating the data_wd table
        const updateDataWdSql =
          "UPDATE data_wd SET closed = TRUE, closed_id = ? WHERE closed = FALSE";

        // Run the query to update the data_wd table
        connection.query(updateDataWdSql, [newClosedId], (err, result) => {
          if (err) {
            // Rollback if there is an error
            return connection.rollback(() => {
              connection.release();
              res.send({ error: err });
            });
          }

          // Commit the transaction if there are no errors
          connection.commit((err) => {
            if (err) {
              // Rollback if there is an error committing
              return connection.rollback(() => {
                connection.release();
                res.send({ error: err });
              });
            }

            // Release the connection back to the pool
            connection.release();

            // Send success response
            res.send({ success: "Success Closing" });
          });
        });
      });
    });
  });
});

// Admin WD Get History/Closed Data
app.get("/adminwd/history", (req, res) => {
  const sql =
    "SELECT cls.*, adm.fullname AS admin_closed FROM closed cls JOIN admin adm ON cls.admin_id = adm.admin_id ORDER BY closed_id DESC";

  db.query(sql, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success getting data", result });
    }
  });
});

// Admin WD Undo Close Data by closed_id
app.put("/adminwd/undoclosed", (req, res) => {
  const { id } = req.body;
  const sqlUpdateDataWd =
    "UPDATE data_wd SET closed_id = null, closed = FALSE WHERE closed_id = ?";
  const sqlDeleteClose = "DELETE FROM closed WHERE closed_id = ?";

  db.query(sqlUpdateDataWd, [id], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      db.query(sqlDeleteClose, [id], (err, result) => {
        if (err) {
          res.send({ error: err });
        } else {
          res.send({ success: "Success" });
        }
      });
    }
  });
});

// Admin WD getting History by closed ID
app.get("/adminwd/history/:id", (req, res) => {
  const id = req.params.id;
  const sql =
    "SELECT dw.*, ag.name AS agent_name, op.fullname AS operator_name, adm.fullname AS admin_name, adm.profile, cls.closed_timestamp FROM data_wd dw JOIN agent ag ON dw.agent_id = ag.agent_id JOIN operator op ON dw.operator_id = op.user_id JOIN admin adm ON dw.admin_id = adm.admin_id JOIN closed cls ON dw.closed_id = cls.closed_id WHERE dw.closed_id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success", result });
    }
  });
});

// Admin getting data list agent
app.get("/adminwd/agent", (req, res) => {
  const sql = "SELECT * FROM agent";
  db.query(sql, (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success", result });
    }
  });
});

// Admin delete agent
app.delete("/agent/:id", (req, res) => {
  const id = req.params.id;
  const sql = "DELETE FROM agent WHERE agent_id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});

// Admin Multiple Delete Agent
app.delete("/adminwd/agent", (req, res) => {
  const ids = req.body.ids;
  const sqlDelete = "DELETE FROM agent WHERE agent_id IN (?)";

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

// Admin Add Agent
app.post("/adminwd/addagent", (req, res) => {
  const { agentName, provider } = req.body;
  const sql = "INSERT INTO agent (name, provider) VALUES (?,?)";

  db.query(sql, [agentName, provider], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});

// Admin WD Edit agent
app.put("/adminwd/agent", (req, res) => {
  const { editId, newAgentName, newProvider } = req.body;
  const sql = "UPDATE agent SET name = ?, provider = ? WHERE agent_id = ?";

  db.query(sql, [newAgentName, newProvider, editId], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});

// Change profile pic
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/profile");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });

app.put("/adminwd/profilepic", upload.single("image"), (req, res) => {
  const adminId = req.body.adminid;
  const imagePath = req.file.path;

  const sql = "UPDATE admin SET profile = ? WHERE admin_id = ?";

  db.query(sql, [imagePath, adminId], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});

// Upload Evidence
const storageEvidence = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/evidence");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const uploadEvidence = multer({ storage: storageEvidence });

app.put("/adminwd/evidence", uploadEvidence.single("image"), (req, res) => {
  const wdid = req.body.wdid;
  const imagePath = req.file.path;

  const sql = "UPDATE data_wd SET evidence = ? WHERE data_wd_id = ?";

  db.query(sql, [imagePath, wdid], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});

// ==================== Operator API =============================
// Get ada Operator
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

// Getting data agent with agent_id
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

// Create Operator
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

// single delete operator
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

// Multiple delete Operator
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

// Update Operator Data
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

      res.send({ success: "Login Berhasil!", token, username, result });
    } catch (error) {
      res.send({ error: "Internal Server Error, try again later" });
    }
  });
});

// Get Data Operator Agent
app.get("/operator/agent/:username", (req, res) => {
  const username = req.params.username;
  const sql =
    "SELECT op.user_id, op.fullname, op.username, op.role, op.profile, ag.agent_id, ag.name, ag.provider FROM operator op JOIN agent ag ON op.agent_id = ag.agent_id WHERE op.username = ?";

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
          io.emit("data_inserted", {
            success: "Data WD successfully inserted",
            message: "Data WD successfully inserted",
          });
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
  const sqlSelect =
    "SELECT dw.*, adm.fullname AS admin_name, adm.profile, op.fullname AS operator_name FROM data_wd dw LEFT JOIN admin adm ON dw.admin_id = adm.admin_id JOIN operator op ON dw.operator_id = op.user_id WHERE dw.agent_id = ? AND dw.closed = FALSE";

  db.query(sqlSelect, [agentId], (err, result) => {
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

// Operator getting data closed details by id closed and agent_id
app.get("/op/history/:id/:ag", (req, res) => {
  const id = req.params.id;
  const ag = req.params.ag;
  const sql =
    "SELECT dw.*, ag.name AS agent_name, op.fullname AS operator_name, adm.fullname AS admin_name, adm.profile, cls.closed_timestamp FROM data_wd dw JOIN agent ag ON dw.agent_id = ag.agent_id JOIN operator op ON dw.operator_id = op.user_id JOIN admin adm ON dw.admin_id = adm.admin_id JOIN closed cls ON dw.closed_id = cls.closed_id WHERE dw.closed_id = ? AND dw.agent_id = ?";

  db.query(sql, [id, ag], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success", result });
    }
  });
});

// Change profile pic
const storageOp = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/profile");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const uploads = multer({ storage: storageOp });

app.put("/operator/profilepic", uploads.single("image"), (req, res) => {
  const opId = req.body.opId;
  const imagePath = req.file.path;

  const sql = "UPDATE operator SET profile = ? WHERE user_id = ?";

  db.query(sql, [imagePath, opId], (err, result) => {
    if (err) {
      res.send({ error: err });
    } else {
      res.send({ success: "Success" });
    }
  });
});
