// Retrieve the token from localStorage
function getToken() {
    return localStorage.getItem('token');
}

// Save the token to localStorage
function saveToken(token) {
    localStorage.setItem('token', token);
}

// Utility for making authenticated API requests
async function fetchWithAuth(url, options = {}) {
    const token = getToken();
    if (!token) {
        alert('You need to log in first.');
        window.location.href = 'login.html';
        return;
    }

    options.headers = {
        ...options.headers,
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
    };

    const response = await fetch(url, options);

    // Handle session expiration or unauthorized access
    if (response.status === 401 || response.status === 403) {
        alert('Session expired. Please log in again.');
        localStorage.removeItem('token');
        window.location.href = 'login.html';
        return;
    }

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || response.statusText);
    }

    return response.json();
}

// Log out the user and redirect to login page
function logout() {
    localStorage.removeItem('token');
    window.location.href = 'login.html';
}

// Utility to check user role and redirect to the appropriate dashboard
async function redirectToDashboard() {
    try {
        const userInfo = await fetchWithAuth('/user-info'); // Endpoint to fetch user role and details
        if (userInfo.role === 'user') {
            window.location.href = 'user_dashboard.html';
        } else if (userInfo.role === 'organization') {
            window.location.href = 'organization_dashboard.html';
        } else if (userInfo.role === 'admin') {
            window.location.href = 'admin_panel.html';
        } else {
            alert('Unauthorized access. Please log in again.');
            logout();
        }
    } catch (error) {
        console.error('Error redirecting to dashboard:', error);
        alert('Unable to determine user role. Please log in again.');
        logout();
    }
}

// Call this function on page load to ensure the user is authenticated
async function ensureAuthenticated() {
    const token = getToken();
    if (!token) {
        alert('You need to log in first.');
        window.location.href = 'login.html';
        return;
    }

    try {
        // Optional: Verify token validity on the server
        await fetchWithAuth('/verify-token'); // Endpoint to verify token
    } catch (error) {
        console.error('Authentication error:', error);
        alert('Session expired. Please log in again.');
        logout();
    }
}
