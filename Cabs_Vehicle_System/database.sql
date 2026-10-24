-- FRESH INSTALL. (Already have the old database? Run migration.sql instead.)
CREATE DATABASE IF NOT EXISTS cabs_db;
USE cabs_db;

CREATE TABLE tbl_users (
    idnum INT AUTO_INCREMENT PRIMARY KEY,
    fullname VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,          -- bcrypt hash
    role ENUM('student','admin','guard') NOT NULL DEFAULT 'student'
);

CREATE TABLE tbl_vehicles (
    idnum INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    plate VARCHAR(20) NOT NULL UNIQUE,       -- stored UPPERCASE, no spaces/dashes
    type VARCHAR(30) NOT NULL,
    brand VARCHAR(50) NOT NULL,
    color VARCHAR(30) NOT NULL,
    status ENUM('Pending','Approved','Rejected') NOT NULL DEFAULT 'Pending',
    date_applied TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES tbl_users(idnum)
);

-- registered vehicles: every ENTRY / EXIT
CREATE TABLE tbl_gate_logs (
    idnum INT AUTO_INCREMENT PRIMARY KEY,
    vehicle_id INT NOT NULL,
    guard_id INT NOT NULL,
    action ENUM('ENTRY','EXIT') NOT NULL,
    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vehicle_id) REFERENCES tbl_vehicles(idnum),
    FOREIGN KEY (guard_id) REFERENCES tbl_users(idnum)
);

-- visitors: separate logbook, one row per visit (time_out stays NULL while inside)
CREATE TABLE tbl_visitor_logs (
    idnum INT AUTO_INCREMENT PRIMARY KEY,
    visitor_name VARCHAR(100) NOT NULL,
    plate VARCHAR(20) NOT NULL,
    id_shown VARCHAR(50) NOT NULL,           -- type of ID the visitor showed
    contact VARCHAR(30) NOT NULL,
    person_visited VARCHAR(100) NOT NULL,
    purpose VARCHAR(150) NOT NULL,
    time_in TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    time_out TIMESTAMP NULL DEFAULT NULL,
    guard_in INT NOT NULL,
    guard_out INT NULL,
    INDEX idx_visitor_out (time_out),
    INDEX idx_visitor_plate (plate),
    FOREIGN KEY (guard_in) REFERENCES tbl_users(idnum),
    FOREIGN KEY (guard_out) REFERENCES tbl_users(idnum)
);

-- ready-made accounts (passwords: admin123 / guard123 -> CHANGE THEM after first login)
INSERT INTO tbl_users (fullname,email,password,role) VALUES
('Administrator','admin@cabs.com','$2a$10$K7j4yxfU/1dgT.M0ewjfauuPXM2jwEE3O8vlS4Hmfdpg/IINod5GC','admin'),
('Security Guard','guard@cabs.com','$2a$10$6qS27rD9lWGxbOdXMvRehON3wryGVjgej/x.NV8PHUt40N4W2B0bO','guard');
