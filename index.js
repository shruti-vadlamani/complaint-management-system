const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

const session = require('express-session');

app.use(session({
    secret: 'securekey',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.json());

const PORT = 8000;

// RSA Key Generation (Run once to generate keys, then comment out)
// if (!fs.existsSync('admin_public.pem') || !fs.existsSync('admin_private.pem')) {
//     const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
//         modulusLength: 2048,
//     });

//     fs.writeFileSync('admin_public.pem', publicKey.export({ type: 'pkcs1', format: 'pem' }));
//     fs.writeFileSync('admin_private.pem', privateKey.export({ type: 'pkcs1', format: 'pem' }));
//     console.log('RSA keys generated and saved to files.');
// }

// Only generate keys if they don't exist AND we're in development
if (process.env.NODE_ENV === 'development' && 
    (!fs.existsSync('admin_public.pem') || !fs.existsSync('admin_private.pem'))) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        }
    });

    fs.writeFileSync('admin_public.pem', publicKey);
    fs.writeFileSync('admin_private.pem', privateKey);
    console.log('RSA keys generated and saved to files.');
}

// Load Admin's RSA Keys
const publicKey = fs.readFileSync('admin_public.pem', 'utf8');
const privateKey = fs.readFileSync('admin_private.pem', 'utf8');

// Encryption Function
function encryptComplaint(complaintText) {
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encryptedComplaint = cipher.update(complaintText, 'utf8', 'hex');
    encryptedComplaint += cipher.final('hex');

    const encryptedAESKey = crypto.publicEncrypt(publicKey, aesKey);

    return {
        encryptedComplaint,
        encryptedAESKey: encryptedAESKey.toString('hex'),
        iv: iv.toString('hex'),
    };
}

// Decryption Function


function decryptComplaint(encryptedAESKey, encryptedComplaint, iv) {
    try {
        // Validate input parameters
        if (!encryptedAESKey || !encryptedComplaint || !iv) {
            throw new Error('decryption parameters');
        }

        // Decrypt the AES key using the private RSA key
        const aesKey = crypto.privateDecrypt(privateKey, Buffer.from(encryptedAESKey, 'hex'));

        // Initialize the AES decipher with the decrypted key and IV
        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, Buffer.from(iv, 'hex'));

        // Decrypt the complaint text
        let decryptedComplaint = decipher.update(encryptedComplaint, 'hex', 'utf8');
        decryptedComplaint += decipher.final('utf8');

        return decryptedComplaint;
    } catch (error) {
        console.error('Decryption failed:', error.message);
        return null; // Return null to indicate decryption failure
    }
}


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const mongoURI = 'mongodb+srv://245122749009:245122749009@cluster0.fdcfx.mongodb.net/miniproject?retryWrites=true&w=majority';
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch((error) => console.error('MongoDB connection error:', error));

// Schemas and Models
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
});

const complaintSchema = new mongoose.Schema({
    encryptedComplaint: { type: String, required: true },
    encryptedAESKey: { type: String, required: true },
    iv: { type: String, required: true },
    status: { type: String, enum: ['pending', 'resolved'], default: 'pending' },
    timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Complaint = mongoose.model('Complaint', complaintSchema);

const authenticateUser = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

const authenticateAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.isAdmin) {
        next();
    } else {
        res.status(403).send('Access denied. Admin privileges required.');
    }
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/register.html'));
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        console.log('User registered successfully');
        res.redirect('/login');
    } catch (error) {
        console.error('Error registering user:', error);
        if (error.code === 11000) {
            res.status(400).send('Username or email already exists');
        } else {
            res.status(500).send('Internal Server Error');
        }
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/login.html'));
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Error logging out');
        }
        res.sendFile(path.join(__dirname, 'public/logout.html'));
    });
});

app.get('/admin_login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin_login.html'));
});

app.post('/admin_login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && user.isAdmin && (await bcrypt.compare(password, user.password))) {
            req.session.user = {
                id: user._id,
                username: user.username,
                isAdmin: true
            };
            res.redirect('/admin_dashboard');
        } else {
            res.status(401).send('Invalid admin credentials');
        }
    } catch (error) {
        console.error('Error during admin login:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && (await bcrypt.compare(password, user.password))) {
            req.session.user = {
                id: user._id,
                username: user.username,
                isAdmin: false
            };
            // Redirect to the /submit_complaint route after successful login
            res.redirect('/submit_complaint');
        } else {
            res.status(401).send('Invalid credentials. Please try again.');
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.get('/submit_complaint', authenticateUser, (req, res) => {
    res.sendFile(path.join(__dirname, 'public/submit_complaint.html'));
});


app.post('/submit_complaint', authenticateUser, async (req, res) => {
    const { complaintText } = req.body;
    try {
        if (!complaintText) {
            return res.status(400).send('Complaint text is required.');
        }
        const encryptedData = encryptComplaint(complaintText);
        // Only save the encrypted data, not the plaintext complaintText
        const newComplaint = new Complaint({ 
            encryptedComplaint: encryptedData.encryptedComplaint,
            encryptedAESKey: encryptedData.encryptedAESKey,
            iv: encryptedData.iv
        });
        await newComplaint.save();
        res.status(201).send(`
            <p>Complaint submitted securely. You will be redirected shortly...</p>
            <script>
                setTimeout(() => {
                    window.location.href = '/index.html';
                }, 3000);
            </script>
        `);
    } catch (error) {
        console.error('Error submitting complaint:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.get('/admin_dashboard', authenticateAdmin, async (req, res) => {
    try {
        const complaints = await Complaint.find().sort({ status: 1, timestamp: -1 });;
        //console.log('Complaints fetched:', complaints); // Check if complaints are being fetched

        const formattedComplaints = complaints.map((complaint) => {
            try {
                const decryptedText = decryptComplaint(
                    complaint.encryptedAESKey,
                    complaint.encryptedComplaint,
                    complaint.iv
                );
                //console.log('Decrypted complaint:', decryptedText);
                return {
                    _id: complaint._id,
                    complaintText: decryptedText,
                    timestamp: complaint.timestamp,
                    status: complaint.status
                };
            } catch (decryptionError) {
                console.error('Error decrypting complaint:', decryptionError);
                return {
                    _id: complaint._id,
                    complaintText: null, // Handle decryption errors gracefully
                    timestamp: complaint.timestamp
                };
            }
        });

        res.render('admin_dashboard', { complaints: formattedComplaints });
    } catch (error) {
        console.error('Error fetching complaints:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/view_complaints/:complaintId', authenticateAdmin, (req, res) => {
    const complaintId = req.params.complaintId;

    Complaint.findById(complaintId)
        .then(complaint => {
            if (complaint) {
                const decryptedText = decryptComplaint(
                    complaint.encryptedAESKey,
                    complaint.encryptedComplaint,
                    complaint.iv
                );

                // Pass complaint object with decrypted text to the view
                res.render('view_complaints', { 
                    complaint: { 
                        _id: complaint._id,
                        complaintText: decryptedText,  // Add decrypted text
                        timestamp: complaint.timestamp
                    }
                });
            } else {
                res.status(404).send('Complaint not found');
            }
        })
        .catch(err => {
            console.error('Error fetching complaint:', err);
            res.status(500).send('Error fetching complaint');
        });
});

// In your app.post('/update_status/:complaintId') route
app.post('/update_status/:complaintId', async (req, res) => {
    console.log('Update status request received:', {
        complaintId: req.params.complaintId,
        newStatus: req.body.status
    });
    
    try {
        const complaint = await Complaint.findByIdAndUpdate(
            req.params.complaintId,
            { status: req.body.status },
            { new: true }
        );
        console.log('Updated complaint:', complaint);
        res.json({ success: true, complaint });
    } catch (error) {
        console.error('Update status error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});


// async function createAdminUser() {
//     try {
//         const adminExists = await User.findOne({ username: 'admin' });
//         if (!adminExists) {
//             const hashedPassword = await bcrypt.hash('admin123', 10);
//             const adminUser = new User({
//                 username: 'admin',
//                 email: 'admin@gmail.com',
//                 password: hashedPassword,
//                 isAdmin: true
//             });
//             await adminUser.save();
//             console.log('Admin user created successfully');
//         }
//     } catch (error) {
//         console.error('Error creating admin user:', error);
//     }
// }


// Start the Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    //createAdminUser();
});