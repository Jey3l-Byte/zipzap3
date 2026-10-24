# CABS – Campus Car Pass (v2)

## Run it
```
npm install
mysql -u root < database.sql        # NEW install
# or: mysql -u root < migration.sql  # you already have the old cabs_db (keeps your data)
npm start                            # http://localhost:5000
```
Optional environment variables: `SESSION_SECRET`, `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`.

Seed accounts: `admin@cabs.com / admin123`, `guard@cabs.com / guard123` (change them!).
Students sign up themselves.

## Pages
| Role | Page | What it does |
|---|---|---|
| Student | My Vehicles | register a car, status + INSIDE/OUTSIDE |
| Student | Gate History | own vehicles' entry/exit times (filter by vehicle) |
| Guard | Gate Check | search plate, record entry/exit |
| Guard | Registered Vehicles | all approved cars, inside/outside, search + filter, one-click entry/exit |
| Guard | Visitor Logbook | visitor time in (name, plate, ID shown, contact, person visited, purpose) / time out |
| Admin | Vehicle Requests | approve / reject / revoke |
| Admin | Gate History | registered + visitors in one list; filter by type, entry/exit, dates, plate/name; Export CSV |
| Admin | Inside Now | who is on campus right now |

## Bugs fixed
- A car that is inside can no longer get stuck: admin can't reject/revoke it while inside, and the guard can always record its EXIT.
- Plates are normalized (`abc 123`, `ABC-123`, `ABC123` are the same car); blank/invalid plates rejected.
- DB errors no longer crash the server (connection pool + central error handler).
- Input validation on signup, vehicle and visitor forms.

## Security
- Passwords hashed with bcrypt. Old plain-text passwords are upgraded automatically at each person's next login.
- All actions are POST with a CSRF token (the old GET links `/review/..`, `/gate/..`, `/logout` are gone).
- New session id at login, HttpOnly + SameSite cookie, 8-hour session.
- Login lockout: 5 wrong tries per email+IP -> 10 minutes.
- CSV export neutralizes spreadsheet formulas; output is HTML-escaped; `back=` redirects are whitelisted.

## Known limits (fine for a school project, worth knowing)
- Sessions and the login lockout are kept in memory: restarting the server logs everyone out and resets lockouts.
- Serve over HTTPS if it ever leaves the local network.
- Times use the server's clock/timezone.
