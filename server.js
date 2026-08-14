const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const path = require('path');

dotenv.config();

const admin = require('firebase-admin');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

// ==================== FIREBASE ADMIN INITIALIZATION ====================
let serviceAccount = null;
let firebaseConfig = null;

// Try to get service account from environment
try {
  // First: Try FIREBASE_SERVICE_ACCOUNT (full service account JSON)
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    console.log('✅ Loaded FIREBASE_SERVICE_ACCOUNT');
  }
  // Second: Try FIREBASE_CONFIG
  else if (process.env.FIREBASE_CONFIG) {
    const config = JSON.parse(process.env.FIREBASE_CONFIG);
    firebaseConfig = config;
    
    // Check if this is a service account (has private_key)
    if (config.private_key && config.client_email) {
      serviceAccount = config;
      console.log('✅ Loaded FIREBASE_CONFIG as service account');
    } else {
      // Web app config - store for later use
      console.log('ℹ️ FIREBASE_CONFIG is web app config');
      serviceAccount = null;
    }
  }
} catch (e) {
  console.error('❌ Error parsing config:', e);
  serviceAccount = null;
}

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  try {
    if (serviceAccount && serviceAccount.private_key) {
      // Use service account
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: serviceAccount.project_id || serviceAccount.projectId || 'pointsdrmirna',
          clientEmail: serviceAccount.client_email,
          privateKey: serviceAccount.private_key
        }),
        projectId: serviceAccount.project_id || serviceAccount.projectId || 'pointsdrmirna'
      });
      console.log('✅ Firebase Admin initialized with Service Account');
    } else {
      // Use Application Default Credentials (for Vercel / Google Cloud)
      try {
        admin.initializeApp({
          credential: admin.credential.applicationDefault(),
          projectId: firebaseConfig?.projectId || 'pointsdrmirna'
        });
        console.log('✅ Firebase Admin initialized with Application Default Credentials');
      } catch (adcError) {
        // Fallback: Try with just project ID
        console.log('⚠️ ADC failed, trying fallback...');
        admin.initializeApp({
          projectId: firebaseConfig?.projectId || 'pointsdrmirna'
        });
        console.log('✅ Firebase Admin initialized with fallback');
      }
    }
  } catch (e) {
    console.error('❌ Firebase Admin initialization error:', e);
    // Final fallback
    try {
      admin.initializeApp({
        projectId: firebaseConfig?.projectId || 'pointsdrmirna'
      });
      console.log('✅ Firebase Admin initialized with final fallback');
    } catch (err) {
      console.error('❌ Failed to initialize Firebase Admin:', err);
    }
  }
}

const db = getFirestore();
const app = express();
const PORT = process.env.PORT || 3000;

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: true,
  credentials: true
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ==================== AUTH MIDDLEWARE ====================
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.cookies.admin_token;
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized - No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.username !== process.env.ADMIN_USERNAME) {
      return res.status(401).json({ error: 'Unauthorized - Invalid credentials' });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized - Invalid token' });
  }
};

// ==================== ADMIN AUTH ROUTES ====================

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
      const token = jwt.sign(
        { username, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.cookie('admin_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
      });

      return res.json({ success: true, message: 'Login successful' });
    }

    return res.status(401).json({ error: 'Invalid username or password' });
  } catch (error) {
    console.error('Admin login error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin logout
app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ success: true, message: 'Logged out successfully' });
});

// Admin session check
app.get('/api/admin/me', authenticateAdmin, (req, res) => {
  res.json({ username: req.admin.username, role: 'admin' });
});

// ==================== USER MANAGEMENT ROUTES ====================

// Get all users (patients)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { search, status, limit = 50, offset = 0 } = req.query;

    let query = db.collection('users').where('role', '==', 'patient');

    if (status) {
      query = query.where('status', '==', status);
    }

    const snapshot = await query
      .orderBy('createdAt', 'desc')
      .limit(parseInt(limit))
      .offset(parseInt(offset))
      .get();

    let users = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      users.push({
        id: doc.id,
        ...data,
        createdAt: data.createdAt ? data.createdAt.toDate().toISOString() : null,
        updatedAt: data.updatedAt ? data.updatedAt.toDate().toISOString() : null
      });
    });

    // Apply search filter if provided
    if (search) {
      const searchLower = search.toLowerCase();
      users = users.filter(user =>
        (user.name && user.name.toLowerCase().includes(searchLower)) ||
        (user.phone && user.phone.includes(search)) ||
        (user.email && user.email.toLowerCase().includes(searchLower))
      );
    }

    // Get total count
    const countSnapshot = await db.collection('users')
      .where('role', '==', 'patient')
      .get();
    const total = countSnapshot.size;

    res.json({
      users,
      total,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Create patient account
app.post('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { name, phone, email, password, initialPoints = 0 } = req.body;

    if (!name || !phone || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    const existingUsers = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (!existingUsers.empty) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Create Firebase Auth user
    let userRecord;
    try {
      userRecord = await admin.auth().createUser({
        email,
        password,
        displayName: name
      });
    } catch (authError) {
      console.error('Firebase Auth error:', authError);
      return res.status(400).json({ error: authError.message || 'Failed to create user' });
    }

    // Create Firestore document
    const userData = {
      uid: userRecord.uid,
      name,
      phone,
      email,
      points: parseInt(initialPoints) || 0,
      role: 'patient',
      status: 'active',
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('users').add(userData);

    // Create initial transaction if initialPoints > 0
    if (parseInt(initialPoints) > 0) {
      await db.collection('transactions').add({
        userId: docRef.id,
        type: 'admin_add',
        points: parseInt(initialPoints),
        previousBalance: 0,
        newBalance: parseInt(initialPoints),
        reason: 'Initial points added by admin',
        performedBy: req.admin.username,
        createdAt: FieldValue.serverTimestamp()
      });
    }

    res.status(201).json({
      success: true,
      id: docRef.id,
      message: 'Patient account created successfully'
    });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Failed to create patient account' });
  }
});

// Get single user
app.get('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const doc = await db.collection('users').doc(req.params.id).get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const data = doc.data();
    res.json({
      id: doc.id,
      ...data,
      createdAt: data.createdAt ? data.createdAt.toDate().toISOString() : null,
      updatedAt: data.updatedAt ? data.updatedAt.toDate().toISOString() : null
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Update user points (add, remove, edit)
app.patch('/api/admin/users/:id/points', authenticateAdmin, async (req, res) => {
  try {
    const { operation, amount, reason } = req.body;

    if (!operation || amount === undefined) {
      return res.status(400).json({ error: 'Operation and amount are required' });
    }

    const amountNum = parseInt(amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    const doc = await db.collection('users').doc(req.params.id).get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const currentData = doc.data();
    const currentPoints = currentData.points || 0;
    let newPoints = currentPoints;
    let transactionType = '';

    switch (operation) {
      case 'add':
        newPoints = currentPoints + amountNum;
        transactionType = 'admin_add';
        break;
      case 'remove':
        if (currentPoints - amountNum < 0) {
          return res.status(400).json({ error: 'Cannot have negative points balance' });
        }
        newPoints = currentPoints - amountNum;
        transactionType = 'admin_remove';
        break;
      case 'set':
        newPoints = amountNum;
        transactionType = 'manual_adjustment';
        break;
      default:
        return res.status(400).json({ error: 'Invalid operation' });
    }

    // Update user points
    await db.collection('users').doc(req.params.id).update({
      points: newPoints,
      updatedAt: FieldValue.serverTimestamp()
    });

    // Create transaction record
    await db.collection('transactions').add({
      userId: req.params.id,
      type: transactionType,
      points: Math.abs(newPoints - currentPoints),
      previousBalance: currentPoints,
      newBalance: newPoints,
      reason: reason || `${operation} operation`,
      performedBy: req.admin.username,
      createdAt: FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      message: 'Points updated successfully',
      previousBalance: currentPoints,
      newBalance: newPoints
    });
  } catch (error) {
    console.error('Update points error:', error);
    res.status(500).json({ error: 'Failed to update points' });
  }
});

// Reset points to zero
app.post('/api/admin/users/:id/reset-points', authenticateAdmin, async (req, res) => {
  try {
    const doc = await db.collection('users').doc(req.params.id).get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const currentData = doc.data();
    const currentPoints = currentData.points || 0;

    if (currentPoints === 0) {
      return res.status(400).json({ error: 'Points are already zero' });
    }

    // Update user points
    await db.collection('users').doc(req.params.id).update({
      points: 0,
      updatedAt: FieldValue.serverTimestamp()
    });

    // Create transaction record
    await db.collection('transactions').add({
      userId: req.params.id,
      type: 'reset',
      points: currentPoints,
      previousBalance: currentPoints,
      newBalance: 0,
      reason: 'Points reset by admin',
      performedBy: req.admin.username,
      createdAt: FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      message: 'Points reset successfully',
      previousBalance: currentPoints,
      newBalance: 0
    });
  } catch (error) {
    console.error('Reset points error:', error);
    res.status(500).json({ error: 'Failed to reset points' });
  }
});

// Get user transactions
app.get('/api/admin/users/:id/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { limit = 50 } = req.query;

    const snapshot = await db.collection('transactions')
      .where('userId', '==', req.params.id)
      .orderBy('createdAt', 'desc')
      .limit(parseInt(limit))
      .get();

    const transactions = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      transactions.push({
        id: doc.id,
        ...data,
        createdAt: data.createdAt ? data.createdAt.toDate().toISOString() : null
      });
    });

    res.json({ transactions });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Get dashboard statistics
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    // Total patients
    const patientsSnapshot = await db.collection('users')
      .where('role', '==', 'patient')
      .get();
    const totalPatients = patientsSnapshot.size;

    // Total points
    let totalPoints = 0;
    patientsSnapshot.forEach(doc => {
      const data = doc.data();
      totalPoints += data.points || 0;
    });

    // Today's transactions
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const todayTransactionsSnapshot = await db.collection('transactions')
      .where('createdAt', '>=', today)
      .where('createdAt', '<', tomorrow)
      .get();
    const todayTransactions = todayTransactionsSnapshot.size;

    // New patients today
    const newPatientsSnapshot = await db.collection('users')
      .where('role', '==', 'patient')
      .where('createdAt', '>=', today)
      .where('createdAt', '<', tomorrow)
      .get();
    const newPatients = newPatientsSnapshot.size;

    res.json({
      totalPatients,
      totalPoints,
      todayTransactions,
      newPatients
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// ==================== PATIENT ROUTES ====================

// Get patient profile (using Firebase Auth UID)
app.get('/api/patient/profile', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split('Bearer ')[1];
    let decodedToken;
    try {
      decodedToken = await admin.auth().verifyIdToken(token);
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const uid = decodedToken.uid;
    const snapshot = await db.collection('users')
      .where('uid', '==', uid)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    let userData = null;
    let userId = null;
    snapshot.forEach(doc => {
      userId = doc.id;
      userData = doc.data();
    });

    // Get transactions
    const transactionsSnapshot = await db.collection('transactions')
      .where('userId', '==', userId)
      .orderBy('createdAt', 'desc')
      .limit(20)
      .get();

    const transactions = [];
    transactionsSnapshot.forEach(doc => {
      const data = doc.data();
      transactions.push({
        id: doc.id,
        ...data,
        createdAt: data.createdAt ? data.createdAt.toDate().toISOString() : null
      });
    });

    res.json({
      id: userId,
      ...userData,
      transactions,
      createdAt: userData.createdAt ? userData.createdAt.toDate().toISOString() : null,
      updatedAt: userData.updatedAt ? userData.updatedAt.toDate().toISOString() : null
    });
  } catch (error) {
    console.error('Get patient profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ==================== FALLBACK ROUTE ====================

// Handle all other routes - serve index.html for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== START SERVER ====================

// For Vercel serverless, we don't need to listen
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Serving static files from: ${path.join(__dirname, 'public')}`);
    console.log(`🔑 Admin username: ${process.env.ADMIN_USERNAME || 'not set'}`);
    console.log(`📊 Firebase Project: ${firebaseConfig?.projectId || 'pointsdrmirna'}`);
  });
}

module.exports = app;
