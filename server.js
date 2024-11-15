const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
const JWT_SECRET = 'your_secret_key';

// Configure multer for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './public/uploads'); // Directory to save uploaded files
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`); // Save file with a unique name
    },
});
const upload = multer({ storage });

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Database Connection
const db = new sqlite3.Database('./db/database_setup.db', (err) => {
    if (err) console.error('Database connection failed:', err.message);
    else console.log('Connected to database');
});

// Middleware for authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract token from "Bearer <token>"
    if (!token) return res.status(401).send({ message: 'Access Denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ message: 'Invalid Token' });
        req.user = user;
        next();
    });
}

// Middleware for role-based access control
function authorizeRole(requiredRole) {
    return (req, res, next) => {
        if (req.user.role !== requiredRole) {
            return res.status(403).send({ message: 'Forbidden: Insufficient permissions' });
        }
        next();
    };
}

// --- USER ROUTES ---

// User Registration
app.post('/signup', async (req, res) => {
    const { name, email, password, contact_info, qualification, age, gender } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
        `INSERT INTO users (name, email, password, contact_info, qualification, age, gender)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name, email, hashedPassword, contact_info, qualification, age, gender],
        (err) => {
            if (err) return res.status(500).send({ message: 'Error signing up', error: err.message });
            res.status(201).send({ message: 'User registered successfully' });
        }
    );
});

// User Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Check if the email belongs to a user
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user.id, role: 'user' }, JWT_SECRET, { expiresIn: '6h' });
            return res.send({ token, role: 'user', message: 'Login successful' });
        }

        // Check if the email belongs to an organization
        db.get('SELECT * FROM organizations WHERE email = ?', [email], async (err, org) => {
            if (org && await bcrypt.compare(password, org.password)) {
                const token = jwt.sign({ id: org.id, role: 'organization' }, JWT_SECRET, { expiresIn: '6h' });
                return res.send({ token, role: 'organization', message: 'Login successful' });
            }

            // If neither, return an error
            res.status(401).send({ message: 'Invalid credentials' });
        });
    });
});

// Get User Applications
app.get('/user/applications', authenticateToken, authorizeRole('user'), (req, res) => {
    const userId = req.user.id;
    db.all(
        `SELECT a.id, o.name AS organization_name, p.title AS position_title, a.status
         FROM applications a
         JOIN volunteer_positions p ON a.position_id = p.id
         JOIN organizations o ON p.organization_id = o.id
         WHERE a.user_id = ?`,
        [userId],
        (err, rows) => {
            if (err) return res.status(500).send({ message: 'Error fetching applications', error: err.message });
            res.send(rows);
        }
    );
});

// --- ORGANIZATION ROUTES ---

// Organization Sign-up
app.post('/organization/signup', upload.single('logo'), async (req, res) => {
    const { name, email, password, contact_info, location, description } = req.body;
    const logo = req.file ? `/uploads/${req.file.filename}` : null; // Get file path

    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
        `INSERT INTO organizations (name, email, password, contact_info, location, description, logo)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name, email, hashedPassword, contact_info, location, description, logo],
        (err) => {
            if (err) {
                console.error('Error registering organization:', err.message);
                return res.status(500).send({ message: 'Error signing up organization', error: err.message });
            }
            res.status(201).send({ message: 'Organization registered successfully' });
        }
    );
});

// Post Volunteer Position
app.post('/organization/positions', authenticateToken, authorizeRole('organization'), (req, res) => {
    const { title, description, requirements, location, deadline } = req.body;
    const orgId = req.user.id;
    db.run(
        `INSERT INTO volunteer_positions (organization_id, title, description, requirements, location, deadline)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [orgId, title, description, requirements, location, deadline],
        (err) => {
            if (err) return res.status(500).send({ message: 'Error posting position', error: err.message });
            res.status(201).send({ message: 'Position posted successfully' });
        }
    );
});

// Get Volunteer Applications
app.get('/organization/applications', authenticateToken, authorizeRole('organization'), (req, res) => {
    const orgId = req.user.id;
    db.all(
        `SELECT a.id, u.name AS volunteer_name, p.title AS position_title, a.status
         FROM applications a
         JOIN users u ON a.user_id = u.id
         JOIN volunteer_positions p ON a.position_id = p.id
         WHERE p.organization_id = ?`,
        [orgId],
        (err, rows) => {
            if (err) return res.status(500).send({ message: 'Error fetching applications', error: err.message });
            res.send(rows);
        }
    );
});

// --- ADMIN ROUTES ---

// Get All Users
app.get('/admin/users', authenticateToken, authorizeRole('admin'), (req, res) => {
    db.all('SELECT id, name, email FROM users', [], (err, rows) => {
        if (err) return res.status(500).send({ message: 'Error fetching users', error: err.message });
        res.send(rows);
    });
});

// Get All Organizations
app.get('/admin/organizations', authenticateToken, authorizeRole('admin'), (req, res) => {
    db.all('SELECT id, name, email FROM organizations', [], (err, rows) => {
        if (err) return res.status(500).send({ message: 'Error fetching organizations', error: err.message });
        res.send(rows);
    });
});

// Fetch profile
app.get('/profile', authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from the JWT token

    // Query the database for user details
    db.get('SELECT name, email, contact_info, qualification, age, gender FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Error fetching profile:', err);
            res.status(500).send({ message: 'Error fetching profile' });
        } else if (!row) {
            res.status(404).send({ message: 'User not found' });
        } else {
            res.status(200).send(row); // Send user profile data
        }
    });
});

// Get All Organizations
app.get('/organizations', (req, res) => {
    db.all(
        `SELECT id, name, description, location, logo FROM organizations`,
        [],
        (err, rows) => {
            if (err) {
                console.error('Database error:', err.message);
                return res.status(500).send({ message: 'Error fetching organizations', error: err.message });
            }
            res.status(200).send(rows);
        }
    );
});

// Get Organization Details with Volunteer Positions
app.get('/organizations/:id', (req, res) => {
    const orgId = req.params.id;

    // Query for organization details
    const orgQuery = `SELECT id, name, description, location, logo FROM organizations WHERE id = ?`;

    // Query for volunteer positions associated with the organization
    const positionsQuery = `SELECT id, title, description, requirements, location, deadline FROM volunteer_positions WHERE organization_id = ?`;

    db.get(orgQuery, [orgId], (err, organization) => {
        if (err) {
            console.error('Error fetching organization details:', err.message);
            return res.status(500).send({ message: 'Error fetching organization details' });
        }

        if (!organization) {
            return res.status(404).send({ message: 'Organization not found' });
        }

        // Fetch volunteer positions
        db.all(positionsQuery, [orgId], (err, positions) => {
            if (err) {
                console.error('Error fetching volunteer positions:', err.message);
                return res.status(500).send({ message: 'Error fetching volunteer positions' });
            }

            // Combine organization details with positions
            organization.positions = positions || [];
            res.status(200).send(organization);
        });
    });
});

// Start Server
app.listen(3000, () => {
    console.log('Server running at http://localhost:3000');
});
