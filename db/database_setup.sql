-- Create Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    contact_info TEXT NOT NULL,
    qualification TEXT,
    age INTEGER,
    gender TEXT
);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    position_id INTEGER NOT NULL,
    reason TEXT,
    documents TEXT,
    status TEXT DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (position_id) REFERENCES volunteer_positions(id) ON DELETE CASCADE
);

-- Create Volunteer Positions Table
CREATE TABLE IF NOT EXISTS volunteer_positions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    requirements TEXT,
    location TEXT,
    deadline DATE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

-- Create Applications Table
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    position_id INTEGER NOT NULL,
    status TEXT DEFAULT 'Pending',
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (position_id) REFERENCES volunteer_positions(id)
);

-- Create Notifications Table
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    organization_id INTEGER,
    message TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);
