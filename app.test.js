const request = require('supertest');
const app = require('./server.js'); 
const sqlite3 = require('sqlite3').verbose();


let db; // Declare a db variable to be initialized for each test

// Create a new mock in-memory database before each test
beforeEach(() => {
    db = new sqlite3.Database(':memory:'); // In-memory database for each test

    // Create the necessary tables for the tests
    db.serialize(() => {
        db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, contact_info TEXT, qualification TEXT, age INTEGER, gender TEXT)");
        db.run("CREATE TABLE organizations (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, contact_info TEXT, location TEXT, description TEXT, logo TEXT)");
        db.run("CREATE TABLE volunteer_positions (id INTEGER PRIMARY KEY, organization_id INTEGER, title TEXT, description TEXT, requirements TEXT, location TEXT, deadline TEXT)");
        db.run("CREATE TABLE applications (id INTEGER PRIMARY KEY, user_id INTEGER, position_id INTEGER, reason TEXT, documents TEXT, status TEXT)");
        db.run("CREATE TABLE notifications (id INTEGER PRIMARY KEY, user_id INTEGER, message TEXT, is_read BOOLEAN, created_at TEXT)");
    });
});
module.exports = db;
// Close the database connection after each test
afterEach(() => {
    if (db) {
        db.close();
    }
});

// Test User Registration
describe('POST /signup', () => {
    it('should register a user successfully', async () => {
        const userData = {
            name: 'John Doe',
            email: 'johndoe@example.com',
            password: 'password123',
            contact_info: '1234567890',
            qualification: 'Bachelor',
            age: 25,
            gender: 'Male'
        };

        const response = await request(app)
            .post('/signup')
            .send(userData);

        expect(response.status).toBe(201);
        expect(response.body.message).toBe('User registered successfully');
    });
});

// Test User Login
describe('POST /login', () => {
    it('should login a user successfully', async () => {
        const loginData = {
            email: 'johndoe1@example.com',
            password: 'password123',
        };

        // Add a user to the mock database for testing login
        db.run("INSERT INTO users (name, email, password, contact_info, qualification, age, gender) VALUES (?, ?, ?, ?, ?, ?, ?)", 
            ['John Doe', 'johndoe@example.com', 'password123', '1234567890', 'Bachelor', 25, 'Male']
        );

        const response = await request(app)
            .post('/login')
            .send(loginData);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Login successful');
        expect(response.body.token).toBeDefined();
    });

    it('should fail to login with incorrect credentials', async () => {
        const loginData = {
            email: 'wronguser@example.com',
            password: 'wrongpassword',
        };

        const response = await request(app)
            .post('/login')
            .send(loginData);

        expect(response.status).toBe(401);
        expect(response.body.message).toBe('Invalid credentials');
    });
});

// Test Organization Signup
describe('POST /organization/signup', () => {
    it('should register an organization successfully', async () => {
        const orgData = {
            name: 'Org One',
            email: 'orgone@example.com',
            password: 'orgpassword123',
            contact_info: '0987654321',
            location: 'Location One',
            description: 'A non-profit organization'
        };

        const response = await request(app)
            .post('/organization/signup')
            .send(orgData);

        expect(response.status).toBe(201);
        expect(response.body.message).toBe('Organization registered successfully');
    });
});

// Test for retrieving user applications
describe('GET /user/applications', () => {
    it('should fetch user applications', async () => {
        const userToken = 'valid-jwt-token';  // Use a valid JWT token here

        const response = await request(app)
            .get('/user/applications')
            .set('Authorization', `Bearer ${userToken}`);

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);  // Check if the response is an array of applications
    });
});

// Integration Test - Frontend and Backend Interaction (Simulate a full registration and login process)
describe('Integration Test: User registration and login flow', () => {
    it('should successfully register and login a user', async () => {
        // Register a user
        const userData = {
            name: 'Jane Doe',
            email: 'janedoe@example.com',
            password: 'password123',
            contact_info: '0987654321',
            qualification: 'Master',
            age: 28,
            gender: 'Female'
        };

        const registerResponse = await request(app)
            .post('/signup')
            .send(userData);

        expect(registerResponse.status).toBe(201);
        expect(registerResponse.body.message).toBe('User registered successfully');

        // Login the user
        const loginData = {
            email: 'janedoe@example.com',
            password: 'password123',
        };

        const loginResponse = await request(app)
            .post('/login')
            .send(loginData);

        expect(loginResponse.status).toBe(200);
        expect(loginResponse.body.message).toBe('Login successful');
        expect(loginResponse.body.token).toBeDefined();
    });
});

// Test updating user profile
describe('PUT /user/profile', () => {
    it('should update user profile successfully', async () => {
        const userToken = 'valid-jwt-token';  // Use a valid JWT token here
        const updatedProfileData = {
            name: 'Jane Doe Updated',
            email: 'janedoeupdated@example.com',
            contact_info: '1231231234',
            qualification: 'PhD',
            age: 29,
            gender: 'Female'
        };

        const response = await request(app)
            .put('/user/profile')
            .set('Authorization', `Bearer ${userToken}`)
            .send(updatedProfileData);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Profile updated successfully');
    });
});

// Test fetching organizations
describe('GET /organizations', () => {
    it('should fetch all organizations', async () => {
        const response = await request(app).get('/organizations');

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);  // Should return an array of organizations
    });
});

// Test deleting user account
describe('DELETE /user/delete-account', () => {
    it('should delete user account successfully', async () => {
        const userToken = 'valid-jwt-token';  // Use a valid JWT token here
        
        // Simulate inserting a user for deletion
        const userId = 1; // Assuming the user ID is 1
        db.run("INSERT INTO users (id, name, email, password, contact_info, qualification, age, gender) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
            [userId, 'janedoe@example.com', 'password123', '0987654321', 'Master', 28, 'Female']
        );

        const response = await request(app)
            .delete('/user/delete-account')
            .set('Authorization', `Bearer ${userToken}`);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('User account deleted successfully');
    });

    it('should return 404 if user not found', async () => {
        const userToken = 'valid-jwt-token';  // Use a valid JWT token here
        
        const response = await request(app)
            .delete('/user/delete-account')
            .set('Authorization', `Bearer ${userToken}`);

        expect(response.status).toBe(404);
        expect(response.body.message).toBe('User account not found');
    });
});
