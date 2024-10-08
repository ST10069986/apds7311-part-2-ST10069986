require('dotenv').config();
const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const cors = require('cors');
const hpp = require('hpp');
const crypto = require('crypto');
const forge = require('node-forge');
const csurf = require('csurf');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const passport = require('passport');
const session = require('express-session');
const ExpressBrute = require('express-brute');
const argon2 = require('argon2');
const validator = require('validator');
const sanitizeHtml = require('sanitize-html');
const RateLimiterMongo = require('rate-limiter-flexible/lib/RateLimiterMongo');
const { MongoClient } = require('mongodb');

const app = express();

// MongoDB Connection
const mongoUrl = process.env.MONGODB_URI;
const dbName = 'myAppDatabase'; 
let db;

async function connectToMongo() {
    try {
      const client = await MongoClient.connect(mongoUrl, { useUnifiedTopology: true });
      console.log('Connected successfully to MongoDB');
      db = client.db(dbName);
      
      // Add this line to list all databases
      const databasesList = await client.db().admin().listDatabases();
      console.log("Databases:", databasesList.databases.map(db => db.name));
      
      // Try to insert a test document
      const testResult = await db.collection('users').insertOne({ test: 'data' });
      console.log('Test insert result:', testResult);
    } catch (err) {
      console.error('Failed to connect to MongoDB', err);
      process.exit(1);
    }
  }

// Call this function before starting your server
connectToMongo();

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, httpOnly: true, sameSite: 'strict' }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Basic Express configuration
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Advanced Helmet configuration
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true,
    frameguard: { action: 'deny' }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Brute force protection
const store = new ExpressBrute.MemoryStore();
const bruteforce = new ExpressBrute(store, {
    freeRetries: 5,
    minWait: 5*60*1000, // 5 minutes
    maxWait: 60*60*1000, // 1 hour,
    failCallback: function (req, res, next, nextValidRequestDate) {
        res.status(429).send('Too many failed attempts, please try again later.');
    },
});

// Slow down responses for repeat requests
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 100,
    delayMs: 500
});
app.use(speedLimiter);

// CORS protection
app.use(cors({
    origin: process.env.FRONTEND_URL || 'https://localhost:3000',
    credentials: true
}));

// Protection against HTTP Parameter Pollution attacks
app.use(hpp());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Use CSRF protection
app.use(csurf());

// Custom middleware for additional security headers
app.use((req, res, next) => {
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('Feature-Policy', "geolocation 'none'; microphone 'none'; camera 'none'");
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// Setup rate limiter with MongoDB
const rateLimiterMongo = new RateLimiterMongo({
    storeClient: db,
    keyPrefix: 'middleware',
    points: 10,
    duration: 1,
});

app.use((req, res, next) => {
    rateLimiterMongo.consume(req.ip)
        .then(() => {
            next();
        })
        .catch(() => {
            res.status(429).send('Too Many Requests');
        });
});

// Middleware for input sanitization and validation
app.use((req, res, next) => {
    for (let key in req.body) {
        if (typeof req.body[key] === 'string') {
            req.body[key] = sanitizeHtml(req.body[key]);
            req.body[key] = validator.escape(req.body[key]);
        }
    }
    next();
});

// Serve static files from the React app
app.use(express.static(path.join(__dirname, 'client/build')));

// Enhanced password hashing function
async function hashPassword(password) {
    return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 2 ** 16,
        timeCost: 3,
        parallelism: 1
    });
}

// Password validation function
function validatePassword(password) {
    const minLength = 12;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return password.length >= minLength && hasUppercase && hasLowercase && hasNumbers && hasSpecialChar;
}

// API routes
app.post('/api/login', bruteforce.prevent, async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await db.collection('users').findOne({ email });
        if (user && await argon2.verify(user.password, password)) {
            res.json({ success: true, message: 'Login successful' });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Error during login' });
    }
});

app.post('/api/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (!validatePassword(password)) {
        return res.status(400).json({ success: false, message: 'Password does not meet complexity requirements.' });
    }
    try {
        const hashedPassword = await hashPassword(password);
        const result = await db.collection('users').insertOne({ email, password: hashedPassword, name });res.status(201).json({ success: true, message: 'Registration successful', userId: result.insertedId });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ success: false, message: 'Error during registration' });
    }
});

app.post('/api/user', async (req, res) => {
    const { email, name } = req.body;
    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }
    if (!validator.isAlphanumeric(name.replace(/\s/g, ''))) {
        return res.status(400).json({ success: false, message: 'Name contains invalid characters.' });
    }
    
    try {
        const result = await db.collection('users').insertOne({ email, name });
        res.status(201).json({ 
            success: true, 
            message: 'User created successfully',
            user: { id: result.insertedId, name, email }
        });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ success: false, message: 'Error creating user' });
    }
});

app.get('/test-db', async (req, res) => {
    try {
      const result = await db.collection('users').insertOne({ test: 'data' });
      res.json({ success: true, result });
    } catch (error) {
      console.error('Test insert failed:', error);``
      res.status(500).json({ success: false, error: error.message });
    }
  });

// The "catchall" handler: for any request that doesn't match one above, send back React's index.html file.
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

// Function to generate a self-signed certificate
function generateSelfSignedCert() {
    const pki = forge.pki;
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{
        name: 'commonName',
        value: 'localhost'
    }, {
        name: 'countryName',
        value: 'US'
    }, {
        shortName: 'ST',
        value: 'Virginia'
    }, {
        name: 'localityName',
        value: 'Blacksburg'
    }, {
        name: 'organizationName',
        value: 'Test'
    }, {
        shortName: 'OU',
        value: 'Test'
    }];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey);

    return {
        key: pki.privateKeyToPem(keys.privateKey),
        cert: pki.certificateToPem(cert)
    };
}

// Generate or load SSL certificate
let sslOptions;
try {
    sslOptions = {
        key: fs.readFileSync(process.env.SSL_KEY_FILE || 'key.pem'),
        cert: fs.readFileSync(process.env.SSL_CRT_FILE || 'cert.pem')
    };
} catch (e) {
    console.log('Generating self-signed certificate...');
    const selfsigned = generateSelfSignedCert();
    fs.writeFileSync('key.pem', selfsigned.key);
    fs.writeFileSync('cert.pem', selfsigned.cert);
    sslOptions = selfsigned;
}

// Create HTTPS server with strong cipher suite configuration
const httpsServer = https.createServer({
    key: sslOptions.key,
    cert: sslOptions.cert,
    ciphers: [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256"
    ].join(':'),
    honorCipherOrder: true,
    minVersion: 'TLSv1.3',
    preferServerCipherSuites: true,
    dhparam: fs.readFileSync('dhparam.pem')
}, app);

const PORT = process.env.PORT || 3001;
httpsServer.listen(PORT, () => {
    console.log(`HTTPS Server running at https://localhost:${PORT}/`);
});

// HTTP to HTTPS redirection with HSTS header
http.createServer((req, res) => {
    res.writeHead(301, { 
        "Location": "https://" + req.headers['host'] + req.url,
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
    });
    res.end();
}).listen(80);

// Rotate SSL session keys periodically
setInterval(() => {
    httpsServer.setSecureContext(sslOptions);
}, 24 * 60 * 60 * 1000); // Every 24 hours

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('Shutting down gracefully');
    if (db) {
        await db.client.close();
        console.log('MongoDB connection closed');
    }
    process.exit(0);
});