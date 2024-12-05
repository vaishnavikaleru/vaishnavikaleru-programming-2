const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const JWT_SECRET = 'voluntree';
const multer = require('multer');
const cors = require('cors');
app.use(cors({
    origin: 'http://localhost:3000', // Allow requests from localhost:3000
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Allow specific HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Allow specific headers
    preflightContinue: false, // Prevents the middleware from passing the request to the next handler
}));

// const multer = require('multer');
const path = require('path');

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'logo') {
            cb(null, './public/uploads/logos'); // Directory for organization logos
        } else if (file.fieldname === 'documents') {
            cb(null, './public/uploads/documents'); // Directory for application documents
        } else {
            cb(new Error('Unexpected field')); // Reject unexpected fields
        }
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    },
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf', 'application/msword'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Unsupported file type'));
    }
};

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB file size limit
    fileFilter,
});

module.exports = upload;


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
app.get('/user/applications', authenticateToken, (req, res) => {
    const userId = req.user.id;
    db.all(
        `SELECT a.id, o.name AS organization_name, p.title AS position_title, a.status
         FROM applications a
         JOIN volunteer_positions p ON a.position_id = p.id
         JOIN organizations o ON p.organization_id = o.id
         WHERE a.user_id = ?`,
        [userId],
        (err, rows) => {
            if (err) {
                console.error('Error fetching applications:', err.message);
                return res.status(500).send({ message: 'Error fetching applications' });
            }
            console.log('Applications:', rows); // Debugging
            res.status(200).send(rows);
        }
    );
});




// --- ORGANIZATION ROUTES ---

// Organization Sign-up
app.post('/organization/signup', upload.single('logo'), async (req, res) => {
    const { name, email, password, contact_info, location, description } = req.body;
    const logo = req.file ? `/uploads/logos/${req.file.filename}` : null; // Get file path

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
// Endpoint to fetch all organizations
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
// Get Organization Details by ID
app.get('/organizations/:id', (req, res) => {
    const orgId = req.params.id;

    const orgQuery = `SELECT id, name, description, location, logo FROM organizations WHERE id = ?`;
    const positionsQuery = `SELECT id, title, description, requirements, location, deadline FROM volunteer_positions WHERE organization_id = ?`;

    db.get(orgQuery, [orgId], (err, organization) => {
        if (err) {
            console.error('Error fetching organization details:', err.message);
            return res.status(500).send({ message: 'Error fetching organization details' });
        }

        if (!organization) {
            return res.status(404).send({ message: 'Organization not found' });
        }

        db.all(positionsQuery, [orgId], (err, positions) => {
            if (err) {
                console.error('Error fetching volunteer positions:', err.message);
                return res.status(500).send({ message: 'Error fetching volunteer positions' });
            }

            organization.positions = positions || [];
            res.status(200).send(organization);
        });
    });
});
app.delete('/user/applications/:id/withdraw', authenticateToken, (req, res) => {
    const applicationId = req.params.id;
    const userId = req.user.id;

    db.run(
        `DELETE FROM applications WHERE id = ? AND user_id = ?`,
        [applicationId, userId],
        (err) => {
            if (err) {
                console.error('Error withdrawing application:', err.message);
                return res.status(500).send({ message: 'Error withdrawing application' });
            }
            res.status(200).send({ message: 'Application withdrawn successfully' });
        }
    );
});
app.get('/positions/:id', (req, res) => {
    const positionId = req.params.id;
    db.get(
        `SELECT p.title, p.description, p.requirements, p.location, p.deadline, o.name AS organization_name, o.logo, o.location AS org_location 
         FROM volunteer_positions p 
         JOIN organizations o ON p.organization_id = o.id 
         WHERE p.id = ?`,
        [positionId],
        (err, data) => {
            if (err) return res.status(500).send({ message: 'Error fetching position details' });
            if (!data) return res.status(404).send({ message: 'Position not found' });
            res.status(200).send(data);
        }
    );
});
// Multer configuration
const uploads = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, './public/uploads'); // Directory to save uploaded files
        },
        filename: (req, file, cb) => {
            cb(null, `${Date.now()}-${file.originalname}`); // Save file with a unique name
        },
    }),
    fileFilter: (req, file, cb) => {
        // Only allow specific file types
        const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF, JPEG, and PNG files are allowed.'));
        }
    },
});
app.put('/user/profile', authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from the token
    const { name, email, contact_info, qualification, age, gender } = req.body;

    // Validate the inputs
    if (!name || !email || !contact_info) {
        return res.status(400).send({ message: 'Name, email, and contact info are required.' });
    }

    // Update the user profile in the database
    db.run(
        `UPDATE users 
         SET name = ?, email = ?, contact_info = ?, qualification = ?, age = ?, gender = ?
         WHERE id = ?`,
        [name, email, contact_info, qualification, age, gender, userId],
        function (err) {
            if (err) {
                console.error('Error updating user profile:', err.message);
                return res.status(500).send({ message: 'Error updating user profile.' });
            }

            if (this.changes === 0) {
                return res.status(404).send({ message: 'User not found.' });
            }

            res.status(200).send({ message: 'Profile updated successfully.' });
        }
    );
});
// Handle volunteer application with document upload
app.post('/positions/:id/apply', authenticateToken, uploads.single('documents'), (req, res) => {
    const positionId = req.params.id; // Extract position ID from URL
    const userId = req.user.id; // Extract user ID from token
    const reason = req.body.reason;
    const documents = req.file ? req.file.filename : null; // Uploaded document filename

    if (!reason || reason.trim() === '') {
        return res.status(400).send({ message: 'Reason for applying is required' });
    }

    // Check if the position exists
    db.get(`SELECT * FROM volunteer_positions WHERE id = ?`, [positionId], (err, position) => {
        if (err) {
            console.error('Error checking position:', err.message);
            return res.status(500).send({ message: 'Error checking position' });
        }

        if (!position) {
            return res.status(404).send({ message: 'Position not found' });
        }

        const deadlineDate = new Date(position.deadline);
        const currentDate = new Date();

        if (currentDate > deadlineDate) {
            return res.status(400).send({ message: 'The deadline for this position has passed.' });
        }

        // Check if the user has already applied for this position
        db.get(
            `SELECT * FROM applications WHERE user_id = ? AND position_id = ?`,
            [userId, positionId],
            (err, application) => {
                if (err) {
                    console.error('Error checking existing application:', err.message);
                    return res.status(500).send({ message: 'Error checking existing application' });
                }

                if (application) {
                    return res.status(400).send({ message: 'You have already applied for this position' });
                }

                // Insert the application
                db.run(
                    `INSERT INTO applications (user_id, position_id, reason, documents, status) 
                     VALUES (?, ?, ?, ?, 'Pending')`,
                    [userId, positionId, reason, documents],
                    function (err) {
                        if (err) {
                            console.error('Error inserting application:', err.message);
                            return res.status(500).send({ message: 'Error submitting application' });
                        }

                        // Create a notification for the user
                        const message = `Your application for the position "${position.title}" has been submitted successfully.`;
                        db.run(
                            `INSERT INTO notifications (user_id, message, is_read) 
                             VALUES (?, ?, ?)`,
                            [userId, message, false],
                            (err) => {
                                if (err) {
                                    console.error('Error creating notification:', err.message);
                                    return res
                                        .status(500)
                                        .send({ message: 'Application submitted, but failed to create notification.' });
                                }
                                res.status(200).send({ message: 'Application submitted successfully, and notification created.' });
                            }
                        );
                    }
                );
            }
        );
    });
});





// Endpoint to fetch a specific position and its organization details
app.get('/organizations/positions/:id', (req, res) => {
    const positionId = req.params.id;

    // Validate the position ID
    if (!positionId) {
        return res.status(400).send({ message: 'Invalid position ID' });
    }

    // Query to fetch position details
    const positionQuery = `
        SELECT title, description, requirements, location, deadline, organization_id 
        FROM volunteer_positions 
        WHERE id = ?
    `;

    // Query to fetch organization details
    const organizationQuery = `
        SELECT name, description, logo, location 
        FROM organizations 
        WHERE id = ?
    `;

    // Execute the position query
    db.get(positionQuery, [positionId], (err, position) => {
        if (err) {
            console.error('Error fetching position details:', err.message);
            return res.status(500).send({ message: 'Error fetching position details' });
        }

        if (!position) {
            return res.status(404).send({ message: 'Position not found' });
        }

        // Execute the organization query based on the organization_id from the position
        db.get(organizationQuery, [position.organization_id], (err, organization) => {
            if (err) {
                console.error('Error fetching organization details:', err.message);
                return res.status(500).send({ message: 'Error fetching organization details' });
            }

            if (!organization) {
                return res.status(404).send({ message: 'Organization not found' });
            }

            // Combine position and organization details
            res.status(200).send({
                position: {
                    title: position.title,
                    description: position.description,
                    requirements: position.requirements,
                    location: position.location,
                    deadline: position.deadline,
                },
                organization: {
                    name: organization.name,
                    description: organization.description,
                    logo: organization.logo,
                    location: organization.location,
                },
            });
        });
    });
});
app.put('/organization/applications/:id', authenticateToken, authorizeRole('organization'), (req, res) => {
    const applicationId = req.params.id;
    const { status } = req.body;

    if (!status) {
        return res.status(400).send({ message: 'Status is required.' });
    }

    db.run(
        `UPDATE applications SET status = ? WHERE id = ?`,
        [status, applicationId],
        (err) => {
            if (err) {
                console.error('Error updating application status:', err.message);
                return res.status(500).send({ message: 'Error updating application status.' });
            }
            res.status(200).send({ message: 'Application status updated successfully.' });
        }
    );
});
app.get('/notifications', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.all(
        `SELECT id, message, is_read, created_at 
         FROM notifications 
         WHERE user_id = ? 
         ORDER BY created_at DESC`,
        [userId],
        (err, rows) => {
            if (err) {
                console.error('Error fetching notifications:', err.message);
                return res.status(500).send({ message: 'Error fetching notifications' });
            }

            if (!rows || rows.length === 0) {
                return res.status(404).send({ message: 'No notifications found' });
            }

            res.status(200).send(rows);
        }
    );
});
app.get('/volunteer-positions', authenticateToken, (req, res) => {
    db.all(
        `SELECT 
            vp.id AS position_id, 
            vp.title AS position_title, 
            vp.description AS position_description, 
            vp.requirements, 
            vp.location AS position_location, 
            vp.deadline, 
            o.id AS organization_id, 
            o.name AS organization_name, 
            o.contact_info AS organization_contact, 
            o.location AS organization_location, 
            o.description AS organization_description
         FROM 
            volunteer_positions vp
         JOIN 
            organizations o ON vp.organization_id = o.id
         ORDER BY 
            vp.deadline ASC`, // Optional: Order positions by deadline
        [],
        (err, rows) => {
            if (err) {
                console.error('Error fetching volunteer positions:', err.message);
                return res.status(500).send({ message: 'Error fetching volunteer positions' });
            }
            console.log('Volunteer Positions:', rows); // Debugging
            res.status(200).send(rows);
        }
    );
});

// Start Server
app.listen(3000, () => {
    console.log('Server running at http://localhost:3000');
});
