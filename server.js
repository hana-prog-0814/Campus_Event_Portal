const express = require("express");
const path = require("path");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "campus_event_secret_key";
const app = express();
app.use(express.static(path.join(__dirname, "frontend")));

app.use(cors());
app.use(express.json());

// MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    }
});

db.connect((err) => {
    if (err) {
        console.log("❌ Database connection failed");
        console.log(err);
    } else {
        console.log("✅ MySQL Connected");
    }
});


function isUser(req, res, next) {
    if (req.user.role !== "user") {
        return res.status(403).json({
            success: false,
            message: "User access only"
        });
    }
    next();
}
function verifyToken(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            success: false,
            message: "Access denied. No token provided."
        });
    }

    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Invalid token format."
        });
    }

    const token = authHeader.split(" ")[1];

    try {

        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();

    } catch (err) {

        return res.status(401).json({
            success: false,
            message: "Invalid or expired token."
        });

    }

}
function isAdmin(req, res, next) {

    if (req.user.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Admin access only"
        });
    }

    next();
}
function isOrganizer(req, res, next) {
    const role = (req.user.role || "").toLowerCase();

    if (role !== "organizer" && role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Organizer access only"
        });
    }

    next();
}

function isAdmin(req, res, next) {
    if (req.user.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Admin access only"
        });
    }
    next();
}


// Test Route
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "frontend", "login.html"));
});
app.post("/register", async (req, res) => {

    const { name, email, password, role } = req.body;

    // Validate input
    if (!name || !email || !password || !role) {
        return res.status(400).json({
            success: false,
            message: "All fields are required"
        });
    }

    // Only allow these roles
    if (!["user", "organizer"].includes(role)) {
        return res.status(400).json({
            success: false,
            message: "Invalid role"
        });
    }

    // Check duplicate email
    db.query(
        "SELECT id FROM users WHERE email = ?",
        [email],
        async (err, result) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Database error"
                });
            }

            if (result.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: "Email already registered"
                });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            db.query(
                "INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                [name, email, hashedPassword, role],
                (err) => {

                    if (err) {
                        return res.status(500).json({
                            success: false,
                            message: "Registration failed"
                        });
                    }

                    res.status(201).json({
                        success: true,
                        message: "Registration successful"
                    });

                }
            );

        }
    );

});

app.post("/login", (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: "Email and password are required"
        });
    }

    db.query(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, result) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Database error"
                });
            }

            if (result.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User not found"
                });
            }

            const user = result[0];

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid password"
                });
            }

           const token = jwt.sign(
{
    id: user.id,
    role: user.role.toLowerCase()
},
JWT_SECRET,
{ expiresIn: "2h" }
);

            res.json({
                success: true,
                message: "Login successful",
                token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });

        }
    );

});


app.get("/admin/test", verifyToken, isAdmin, (req, res) => {
    res.json({
        success: true,
        message: "Admin access granted"
    });
});

app.post("/events", verifyToken, isOrganizer, (req, res) => {

    console.log("CREATE EVENT HIT");
    console.log(req.user); // MUST show role: organizer

    const {
        title, description, category,
        event_date, event_time, venue, capacity
    } = req.body;

    db.query(
        `INSERT INTO events 
        (title, description, category, event_date, event_time, venue, capacity, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            title, description, category,
            event_date, event_time, venue, capacity,
            req.user.id
        ],
        (err, result) => {

            if (err) {
                console.log(err);
                return res.status(500).json({ success: false });
            }

            res.json({
                success: true,
                message: "Event created"
            });
        }
    );
});

app.get("/admin-test",
    verifyToken,
    isAdmin,
    (req, res) => {

        res.json({
            success: true,
            message: "Welcome Admin"
        });

    }
);

app.get("/organizer-test",
    verifyToken,
    isOrganizer,
    (req, res) => {

        res.json({
            success: true,
            message: "Welcome Organizer"
        });

    }
);
app.get("/profile", verifyToken, (req, res) => {

    res.json({
        success: true,
        user: req.user
    });

});

app.get("/events", (req, res) => {

    const sql = `
        SELECT
            events.*,
            users.name AS organizer_name
        FROM events
        JOIN users
        ON events.created_by = users.id
        ORDER BY event_date ASC
    `;

    db.query(sql, (err, results) => {

        if (err) {
            return res.status(500).json({
                success: false,
                message: "Database error"
            });
        }

        res.json({
            success: true,
            events: results
        });

    });

});

app.get("/my-events", verifyToken, isOrganizer, (req, res) => {

    db.query(
        "SELECT * FROM events WHERE created_by = ?",
        [req.user.id],
        (err, result) => {

            if (err) {
                return res.status(500).json({ success: false });
            }

            res.json({
                success: true,
                events: result
            });

        }
    );
});
app.put("/events/:id", verifyToken, isOrganizer, (req, res) => {

    const eventId = req.params.id;

    const {
        title,
        description,
        category,
        event_date,
        event_time,
        venue,
        capacity
    } = req.body;

    // First check ownership
    db.query(
        "SELECT * FROM events WHERE id=? AND created_by=?",
        [eventId, req.user.id],
        (err, result) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Database error"
                });
            }

            if (result.length === 0 && req.user.role !== "admin") {
                return res.status(403).json({
                    success: false,
                    message: "You can edit only your own events."
                });
            }

            const sql = `
                UPDATE events
                SET
                    title=?,
                    description=?,
                    category=?,
                    event_date=?,
                    event_time=?,
                    venue=?,
                    capacity=?
                WHERE id=?
            `;

            db.query(
                sql,
                [
                    title,
                    description,
                    category,
                    event_date,
                    event_time,
                    venue,
                    capacity,
                    eventId
                ],
                (err2) => {

                    if (err2) {
                        return res.status(500).json({
                            success: false,
                            message: "Update failed"
                        });
                    }

                    res.json({
                        success: true,
                        message: "Event updated successfully"
                    });

                }
            );

        }
    );

});

app.delete("/events/:id", verifyToken, isOrganizer, (req, res) => {

    const eventId = req.params.id;

    db.query(
        "SELECT * FROM events WHERE id=?",
        [eventId],
        (err, result) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Database error"
                });
            }

            if (result.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Event not found"
                });
            }

            const event = result[0];

            // Organizer can delete only their own event
            if (
                req.user.role !== "admin" &&
                event.created_by !== req.user.id
            ) {
                return res.status(403).json({
                    success: false,
                    message: "You can delete only your own events."
                });
            }

            db.query(
                "DELETE FROM events WHERE id=?",
                [eventId],
                (err2) => {

                    if (err2) {
                        return res.status(500).json({
                            success: false,
                            message: "Delete failed"
                        });
                    }

                    res.json({
                        success: true,
                        message: "Event deleted successfully"
                    });

                }
            );

        }
    );

});



app.post("/events/:id/register", verifyToken, (req, res) => {

    const eventId = req.params.id;
    const userId = req.user.id;

    const { phone, department, year } = req.body;

    if (!phone || !department || !year) {
        return res.status(400).json({
            success: false,
            message: "Please fill all fields"
        });
    }

    db.query("SELECT * FROM events WHERE id = ?", [eventId], (err, eventResult) => {

        if (err) return res.status(500).json({ message: "DB error" });

        if (eventResult.length === 0) {
            return res.status(404).json({ message: "Event not found" });
        }

        db.query(
            "SELECT * FROM registrations WHERE user_id=? AND event_id=?",
            [userId, eventId],
            (err2, regResult) => {

                if (regResult.length > 0) {
                    return res.status(409).json({ message: "Already registered" });
                }

                db.query(
                    "INSERT INTO registrations(user_id,event_id,phone,department,year) VALUES (?,?,?,?,?)",
                    [userId, eventId, phone, department, year],
                    (err3) => {

                        if (err3) {
                            return res.status(500).json({ message: "Registration failed" });
                        }

                        res.json({
                            success: true,
                            message: "Registered successfully"
                        });

                    }
                );

            }
        );

    });

});

app.get("/my-registrations", verifyToken, isUser, (req, res) => {

    const sql = `
        SELECT
            registrations.id,
            registrations.registered_at,
            events.title,
            events.category,
            events.event_date,
            events.event_time,
            events.venue
        FROM registrations
        JOIN events
            ON registrations.event_id = events.id
        WHERE registrations.user_id = ?
        ORDER BY registrations.registered_at DESC
    `;

    db.query(sql, [req.user.id], (err, results) => {

        if (err) {
            console.log(err);

            return res.status(500).json({
                success: false,
                message: "Database error"
            });
        }

        res.json({
            success: true,
            registrations: results
        });

    });

});

app.get("/events/:id/registrations", verifyToken, isOrganizer, (req, res) => {

    const eventId = req.params.id;

    // Check if organizer owns the event
    db.query(
        "SELECT * FROM events WHERE id=?",
        [eventId],
        (err, eventResult) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Database error"
                });
            }

            if (eventResult.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Event not found"
                });
            }

            const event = eventResult[0];

            if (
                req.user.role !== "admin" &&
                event.created_by !== req.user.id
            ) {
                return res.status(403).json({
                    success: false,
                    message: "Access denied"
                });
            }

            const sql = `
                SELECT
                    users.name,
                    users.email,
                    registrations.phone,
                    registrations.department,
                    registrations.year,
                    registrations.registered_at
                FROM registrations
                JOIN users
                    ON registrations.user_id = users.id
                WHERE registrations.event_id = ?
                ORDER BY registrations.registered_at DESC
            `;

            db.query(sql, [eventId], (err2, results) => {

                if (err2) {
                    return res.status(500).json({
                        success: false,
                        message: "Database error"
                    });
                }

                res.json({
                    success: true,
                    registrations: results
                });

            });

        }
    );

});

app.get("/admin/dashboard", verifyToken, isAdmin, (req, res) => {

    const data = {};

    db.query("SELECT COUNT(*) AS totalUsers FROM users", (err, users) => {
        if (err) return res.json({ success: false });

        data.totalUsers = users[0].totalUsers;

        db.query("SELECT COUNT(*) AS totalEvents FROM events", (err2, events) => {
            if (err2) return res.json({ success: false });

            data.totalEvents = events[0].totalEvents;

            db.query("SELECT COUNT(*) AS totalRegistrations FROM registrations", (err3, regs) => {
                if (err3) return res.json({ success: false });

                data.totalRegistrations = regs[0].totalRegistrations;

                res.json({
                    success: true,
                    dashboard: data
                });

            });

        });

    });

});

app.get("/admin/users", verifyToken, isAdmin, (req, res) => {

    db.query("SELECT id, name, email, role FROM users", (err, results) => {

        if (err) {
            return res.json({ success: false });
        }

        res.json({
            success: true,
            users: results
        });

    });

});

app.get("/admin/events", verifyToken, isAdmin, (req, res) => {

    db.query("SELECT * FROM events", (err, results) => {

        if (err) {
            return res.json({ success: false });
        }

        res.json({
            success: true,
            events: results
        });

    });

});

app.delete("/admin/event/:id", verifyToken, isAdmin, (req, res) => {

    db.query(
        "DELETE FROM events WHERE id = ?",
        [req.params.id],
        (err) => {

            if (err) {
                return res.json({ success: false });
            }

            res.json({
                success: true,
                message: "Event deleted"
            });

        }
    );
});

app.delete("/admin/user/:id", verifyToken, isAdmin, (req, res) => {
    db.query(
        "DELETE FROM users WHERE id = ?",
        [req.params.id],
        (err, result) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "User deletion failed"
                });
            }

            res.json({
                success: true,
                message: "User deleted successfully"
            });
        }
    );
});
const PORT = 3000;

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});