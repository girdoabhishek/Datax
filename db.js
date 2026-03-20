// db.js
const sqlite3 = require('sqlite3').verbose();

// This creates a new file called 'users.db' in your project folder
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error("Error opening database:", err.message);
    } else {
        console.log("Connected to the SQLite database.");
        
        // Create the users table if it doesn't already exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`);
    }
});

module.exports = db;