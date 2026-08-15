require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const { FieldValue } = require('firebase-admin/firestore');

// ===== تهيئة Firebase Admin =====
let firebaseConfig;
try {
  firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
} catch (error) {
  console.error('❌ Error parsing FIREBASE_CONFIG:', error.message);
  console.error('📝 Please make sure FIREBASE_CONFIG is a valid JSON string');
  firebaseConfig = {
    projectId: process.env.FIREBASE_PROJECT_ID || 'pointsdrmirna'
  };
}

admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig),
});

const db = admin.firestore();

// ===== تهيئة Express =====
const app = express();
const PORT = process.env.PORT || 3000;

// ===== Middleware =====
app.use(express.json());
app.use(cookieParser());

const allowedOrigins = process.env.NODE_ENV === 'production' 
  ? ['https://points-dr-mirna.vercel.app', 'https://your-domain.vercel.app'] 
  : ['http://localhost:3000', 'http://127.0.0.1:3000'];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));

app.use(express.static(path.join(__dirname, 'public')));

// ===== التوثيق والصلاحيات =====
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-key-change-this';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123';

// ===== الاسم المعروض في الواجهة =====
const ADMIN_DISPLAY_NAME = 'Points Dr.Mirna';

// ===== Middleware للتحقق من JWT =====
const verifyAdminToken = async (req, res, next) => {
  try {
    const token = req.cookies.admin_token;
    if (!token) {
      return res.status(401).json({ error: 'غير مصرح لك بالوصول' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'صلاحيات غير كافية' });
    }

    req.adminUser = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'جلسة غير صالحة' });
  }
};

// ===== مسارات التوثيق =====

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'الرجاء إدخال اسم المستخدم وكلمة المرور' });
    }

    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const token = jwt.sign(
      { username, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('admin_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({ success: true, message: 'تم تسجيل الدخول بنجاح' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ success: true, message: 'تم تسجيل الخروج' });
});

app.get('/api/admin/me', verifyAdminToken, (req, res) => {
  res.json({ username: ADMIN_DISPLAY_NAME });
});

// ===== مسارات إدارة المستخدمين =====

app.get('/api/admin/users', verifyAdminToken, async (req, res) => {
  try {
    const { search, page = 1, limit = 10 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    let query = db.collection('users').where('role', '==', 'patient');
    let usersSnapshot;

    if (search) {
      const searchLower = search.toLowerCase();
      const allUsers = await query.get();
      const filteredUsers = [];
      allUsers.forEach(doc => {
        const data = doc.data();
        if (data.name?.toLowerCase().includes(searchLower) ||
            data.phone?.includes(search) ||
            data.email?.toLowerCase().includes(searchLower)) {
          filteredUsers.push({ id: doc.id, ...data });
        }
      });
      filteredUsers.sort((a, b) => b.createdAt?.toMillis() - a.createdAt?.toMillis());
      const total = filteredUsers.length;
      const paginatedUsers = filteredUsers.slice(offset, offset + parseInt(limit));
      
      return res.json({
        users: paginatedUsers,
        total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
      });
    }

    try {
      usersSnapshot = await query
        .orderBy('createdAt', 'desc')
        .offset(offset)
        .limit(parseInt(limit))
        .get();
    } catch (indexError) {
      console.warn('⚠️ Index missing, fetching without orderBy:', indexError.message);
      usersSnapshot = await query
        .offset(offset)
        .limit(parseInt(limit))
        .get();
    }

    let total;
    try {
      const totalSnapshot = await query.count().get();
      total = totalSnapshot.data().count;
    } catch (countError) {
      const allDocs = await query.get();
      total = allDocs.size;
    }

    const users = [];
    usersSnapshot.forEach(doc => {
      users.push({ id: doc.id, ...doc.data() });
    });

    res.json({
      users,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المستخدمين' });
  }
});

app.post('/api/admin/users', verifyAdminToken, async (req, res) => {
  try {
    const { name, phone, email, password, initialPoints = 0 } = req.body;

    if (!name || !phone || !email || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'البريد الإلكتروني غير صحيح' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    }

    const existingUser = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (!existingUser.empty) {
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
    }

    let userRecord;
    try {
      userRecord = await admin.auth().createUser({
        email,
        password,
        displayName: name,
      });
    } catch (authError) {
      console.error('Auth creation error:', authError);
      if (authError.code === 'auth/email-already-exists') {
        return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
      }
      throw authError;
    }

    const now = admin.firestore.Timestamp.now();
    const userData = {
      name,
      phone,
      email,
      points: initialPoints || 0,
      role: 'patient',
      status: 'active',
      createdAt: now,
      updatedAt: now,
      firebaseUid: userRecord.uid,
    };

    await db.collection('users').doc(userRecord.uid).set(userData);

    if (initialPoints > 0) {
      await db.collection('transactions').add({
        userId: userRecord.uid,
        type: 'signup',
        points: initialPoints,
        previousBalance: 0,
        newBalance: initialPoints,
        reason: 'نقاط الترحيب',
        performedBy: 'admin',
        createdAt: now,
      });
    }

    res.status(201).json({
      success: true,
      message: 'تم إنشاء حساب المريض بنجاح',
      userId: userRecord.uid,
    });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب' });
  }
});

app.get('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userDoc = await db.collection('users').doc(id).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    const userData = userDoc.data();
    if (userData.role !== 'patient') {
      return res.status(403).json({ error: 'هذا المستخدم ليس مريضاً' });
    }

    res.json({ id: userDoc.id, ...userData });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب بيانات المستخدم' });
  }
});

// ===== تحديث بيانات مريض =====
app.put('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, email } = req.body;
    
    if (!name || !phone || !email) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    const userRef = db.collection('users').doc(id);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }
    
    const userData = userDoc.data();
    if (userData.role !== 'patient') {
      return res.status(403).json({ error: 'هذا المستخدم ليس مريضاً' });
    }
    
    // التحقق من عدم تكرار البريد الإلكتروني
    if (email !== userData.email) {
      const existingUser = await db.collection('users')
        .where('email', '==', email)
        .get();
      
      if (!existingUser.empty) {
        return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
      }
    }
    
    await userRef.update({
      name,
      phone,
      email,
      updatedAt: admin.firestore.Timestamp.now()
    });
    
    res.json({ success: true, message: 'تم تحديث البيانات بنجاح' });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث البيانات' });
  }
});

// ===== حذف مريض =====
app.delete('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userRef = db.collection('users').doc(id);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }
    
    const userData = userDoc.data();
    if (userData.role !== 'patient') {
      return res.status(403).json({ error: 'هذا المستخدم ليس مريضاً' });
    }
    
    try {
      await admin.auth().deleteUser(id);
    } catch (authError) {
      console.warn('⚠️ Auth delete error:', authError.message);
    }
    
    await userRef.delete();
    
    const transactionsSnapshot = await db.collection('transactions')
      .where('userId', '==', id)
      .get();
    
    const batch = db.batch();
    transactionsSnapshot.forEach(doc => {
      batch.delete(doc.ref);
    });
    await batch.commit();
    
    res.json({ success: true, message: 'تم حذف المريض بنجاح' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء حذف المريض' });
  }
});

// ===== مسارات إدارة النقاط =====

app.patch('/api/admin/users/:id/points', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { operation, points, reason } = req.body;

    if (!operation || points === undefined || !reason) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة (operation, points, reason)' });
    }

    if (!['add', 'remove', 'edit'].includes(operation)) {
      return res.status(400).json({ error: 'عملية غير صحيحة' });
    }

    const pointsInt = parseInt(points);
    if (isNaN(pointsInt) || pointsInt < 0) {
      return res.status(400).json({ error: 'يجب أن تكون النقاط عدداً صحيحاً غير سالب' });
    }

    const userRef = db.collection('users').doc(id);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    const userData = userDoc.data();
    if (userData.role !== 'patient') {
      return res.status(403).json({ error: 'هذا المستخدم ليس مريضاً' });
    }

    const currentPoints = userData.points || 0;
    let newPoints = currentPoints;
    let transactionType = '';

    switch (operation) {
      case 'add':
        newPoints = currentPoints + pointsInt;
        transactionType = 'admin_add';
        break;
      case 'remove':
        if (currentPoints - pointsInt < 0) {
          return res.status(400).json({ 
            error: 'لا يمكن أن يصبح رصيد النقاط أقل من صفر',
            currentPoints,
            requestedRemove: pointsInt,
          });
        }
        newPoints = currentPoints - pointsInt;
        transactionType = 'admin_remove';
        break;
      case 'edit':
        if (pointsInt < 0) {
          return res.status(400).json({ error: 'لا يمكن أن يكون الرصيد سالباً' });
        }
        newPoints = pointsInt;
        transactionType = 'manual_adjustment';
        break;
    }

    await userRef.update({
      points: newPoints,
      updatedAt: admin.firestore.Timestamp.now(),
    });

    const now = admin.firestore.Timestamp.now();
    await db.collection('transactions').add({
      userId: id,
      type: transactionType,
      points: Math.abs(pointsInt),
      previousBalance: currentPoints,
      newBalance: newPoints,
      reason: reason,
      performedBy: 'admin',
      createdAt: now,
    });

    const updatedDoc = await userRef.get();
    const updatedData = updatedDoc.data();

    res.json({
      success: true,
      message: 'تم تحديث النقاط بنجاح',
      currentPoints: updatedData.points,
      previousPoints: currentPoints,
      change: newPoints - currentPoints,
    });
  } catch (error) {
    console.error('Update points error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث النقاط' });
  }
});

app.post('/api/admin/users/:id/reset-points', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason = 'تم تصفير النقاط بواسطة الأدمن' } = req.body;

    const userRef = db.collection('users').doc(id);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    const userData = userDoc.data();
    if (userData.role !== 'patient') {
      return res.status(403).json({ error: 'هذا المستخدم ليس مريضاً' });
    }

    const currentPoints = userData.points || 0;

    await userRef.update({
      points: 0,
      updatedAt: admin.firestore.Timestamp.now(),
    });

    const now = admin.firestore.Timestamp.now();
    await db.collection('transactions').add({
      userId: id,
      type: 'reset',
      points: currentPoints,
      previousBalance: currentPoints,
      newBalance: 0,
      reason: reason,
      performedBy: 'admin',
      createdAt: now,
    });

    res.json({
      success: true,
      message: 'تم تصفير النقاط بنجاح',
      previousPoints: currentPoints,
      newPoints: 0,
    });
  } catch (error) {
    console.error('Reset points error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تصفير النقاط' });
  }
});

app.get('/api/admin/users/:id/transactions', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 20 } = req.query;

    let transactions = [];
    let query = db.collection('transactions').where('userId', '==', id);

    try {
      const transactionsSnapshot = await query
        .orderBy('createdAt', 'desc')
        .limit(parseInt(limit))
        .get();

      transactionsSnapshot.forEach(doc => {
        transactions.push({ id: doc.id, ...doc.data() });
      });
    } catch (indexError) {
      console.warn('⚠️ Transactions index missing, fetching without orderBy:', indexError.message);
      const transactionsSnapshot = await query.limit(parseInt(limit) * 2).get();
      
      transactionsSnapshot.forEach(doc => {
        transactions.push({ id: doc.id, ...doc.data() });
      });
      
      transactions.sort((a, b) => {
        const dateA = a.createdAt?.toMillis?.() || 0;
        const dateB = b.createdAt?.toMillis?.() || 0;
        return dateB - dateA;
      });
      
      transactions = transactions.slice(0, parseInt(limit));
    }

    res.json(transactions);
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المعاملات' });
  }
});

// ===== مسارات إحصاءات لوحة التحكم =====

app.get('/api/admin/stats', verifyAdminToken, async (req, res) => {
  try {
    let totalPatients = 0;
    try {
      const patientsSnapshot = await db.collection('users')
        .where('role', '==', 'patient')
        .count()
        .get();
      totalPatients = patientsSnapshot.data().count;
    } catch (countError) {
      console.warn('⚠️ Count failed, fetching manually:', countError.message);
      const allPatients = await db.collection('users')
        .where('role', '==', 'patient')
        .get();
      totalPatients = allPatients.size;
    }

    const allPatients = await db.collection('users')
      .where('role', '==', 'patient')
      .get();
    let totalPoints = 0;
    allPatients.forEach(doc => {
      totalPoints += doc.data().points || 0;
    });

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayTimestamp = admin.firestore.Timestamp.fromDate(today);

    let todayOperations = 0;
    try {
      const todayTransactions = await db.collection('transactions')
        .where('createdAt', '>=', todayTimestamp)
        .count()
        .get();
      todayOperations = todayTransactions.data().count;
    } catch (countError) {
      console.warn('⚠️ Today transactions count failed:', countError.message);
      const txns = await db.collection('transactions')
        .where('createdAt', '>=', todayTimestamp)
        .get();
      todayOperations = txns.size;
    }

    let newPatients = 0;
    try {
      const newPatientsToday = await db.collection('users')
        .where('role', '==', 'patient')
        .where('createdAt', '>=', todayTimestamp)
        .count()
        .get();
      newPatients = newPatientsToday.data().count;
    } catch (countError) {
      console.warn('⚠️ New patients count failed:', countError.message);
      const newPatientsDocs = await db.collection('users')
        .where('role', '==', 'patient')
        .where('createdAt', '>=', todayTimestamp)
        .get();
      newPatients = newPatientsDocs.size;
    }

    res.json({
      totalPatients,
      totalPoints,
      todayOperations,
      newPatients,
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب الإحصاءات' });
  }
});

// ===== مسار إضافي للمريض =====

app.get('/api/patient/profile/:uid', async (req, res) => {
  try {
    const { uid } = req.params;
    const userDoc = await db.collection('users').doc(uid).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    const userData = userDoc.data();
    if (userData.role !== 'patient') {
      return res.status(403).json({ error: 'هذا المستخدم ليس مريضاً' });
    }

    let transactions = [];
    try {
      const transactionsSnapshot = await db.collection('transactions')
        .where('userId', '==', uid)
        .orderBy('createdAt', 'desc')
        .limit(10)
        .get();

      transactionsSnapshot.forEach(doc => {
        transactions.push({ id: doc.id, ...doc.data() });
      });
    } catch (indexError) {
      console.warn('⚠️ Patient transactions index missing:', indexError.message);
      const transactionsSnapshot = await db.collection('transactions')
        .where('userId', '==', uid)
        .limit(20)
        .get();
      
      transactionsSnapshot.forEach(doc => {
        transactions.push({ id: doc.id, ...doc.data() });
      });
      
      transactions.sort((a, b) => {
        const dateA = a.createdAt?.toMillis?.() || 0;
        const dateB = b.createdAt?.toMillis?.() || 0;
        return dateB - dateA;
      });
      
      transactions = transactions.slice(0, 10);
    }

    res.json({
      profile: { id: uid, ...userData },
      transactions,
    });
  } catch (error) {
    console.error('Get patient profile error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب بيانات المريض' });
  }
});

// ===== مسار اختبار الاتصال =====
app.get('/api/test', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Server is running',
    environment: process.env.NODE_ENV || 'development'
  });
});

// ===== معالجة الأخطاء =====

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'حدث خطأ غير متوقع في الخادم' });
});

// ===== تشغيل الخادم =====

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
