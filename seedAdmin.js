const mysql = require("mysql2");
const bcrypt = require("bcrypt");

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Hana@2006",
    database: "campus_event_portal_v2"
});

async function createAdmin() {

    const hashedPassword = await bcrypt.hash("123456", 10);

    const sql = `
        INSERT INTO users (name, email, password, role)
        VALUES (?, ?, ?, ?)
    `;

    db.query(sql,
        ["Admin", "admin@gmail.com", hashedPassword, "admin"],
        (err) => {
            if (err) {
                console.log("Error creating admin:", err);
            } else {
                console.log("✅ Admin created successfully");
            }

            process.exit();
        }
    );
}

createAdmin();