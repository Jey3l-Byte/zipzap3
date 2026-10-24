-- UPGRADE an existing cabs_db (from the first version). Safe to run more than once.
-- Your data is kept. Old plain-text passwords are upgraded to bcrypt automatically
-- the next time each person logs in.
USE cabs_db;

ALTER TABLE tbl_users MODIFY password VARCHAR(255) NOT NULL;

-- normalize plates: "abc 123" / "ABC-123" -> "ABC123"
-- (IGNORE skips rows that would collide with another plate; they are listed below)
UPDATE IGNORE tbl_vehicles SET plate = UPPER(REPLACE(REPLACE(plate,' ',''),'-',''));

CREATE TABLE IF NOT EXISTS tbl_visitor_logs (
    idnum INT AUTO_INCREMENT PRIMARY KEY,
    visitor_name VARCHAR(100) NOT NULL,
    plate VARCHAR(20) NOT NULL,
    id_shown VARCHAR(50) NOT NULL,
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

-- Any rows listed here are duplicate plates that could not be normalized.
-- Delete or fix them by hand (they are the same car registered twice).
SELECT idnum, plate, owner_id, status FROM tbl_vehicles WHERE plate = '' OR plate REGEXP '[^A-Z0-9]';
