const mysql = require('mysql');

// a pool (not a single connection) so the app keeps working
// even if MySQL drops an idle connection
const conn = mysql.createPool({
    connectionLimit: 10,
    host:     process.env.DB_HOST || 'localhost',
    user:     process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'cabs_db'
});

module.exports = conn;
