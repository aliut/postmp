const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// File upload configuration
const upload = multer({ dest: 'uploads/' });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'mobile-shop-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Database Setup
const db = new sqlite3.Database('./mobile_shop.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'superuser')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Categories table
    db.run(`CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Products table
    db.run(`CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      serial_number TEXT,
      condition TEXT CHECK(condition IN ('new', 'used')) DEFAULT 'new',
      supplier_phone TEXT,
      supplier_cnic TEXT,
      purchase_price REAL NOT NULL,
      selling_price REAL NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 0,
      pta_approved BOOLEAN DEFAULT 0,
      warranty_days INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (category_id) REFERENCES categories(id)
    )`);

    // Sales table
    db.run(`CREATE TABLE IF NOT EXISTS sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      invoice_number TEXT UNIQUE NOT NULL,
      customer_name TEXT,
      customer_phone TEXT,
      customer_cnic TEXT,
      payment_type TEXT CHECK(payment_type IN ('cash', 'bank_transfer', 'card')),
      subtotal REAL NOT NULL,
      discount_amount REAL DEFAULT 0,
      discount_type TEXT CHECK(discount_type IN ('flat', 'percentage')),
      net_total REAL NOT NULL,
      total_profit REAL NOT NULL,
      sale_date DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`);

    // Sale Items table
    db.run(`CREATE TABLE IF NOT EXISTS sale_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sale_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      product_name TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      returned_quantity INTEGER DEFAULT 0,
      unit_price REAL NOT NULL,
      purchase_price REAL NOT NULL,
      line_total REAL NOT NULL,
      serial_imei TEXT,
      profit REAL NOT NULL,
      warranty_days INTEGER DEFAULT 0,
      remarks TEXT,
      FOREIGN KEY (sale_id) REFERENCES sales(id),
      FOREIGN KEY (product_id) REFERENCES products(id)
    )`);

    // Returns table
    db.run(`CREATE TABLE IF NOT EXISTS returns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sale_id INTEGER NOT NULL,
      sale_item_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      return_amount REAL NOT NULL,
      return_profit REAL NOT NULL,
      reason TEXT,
      return_date DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      FOREIGN KEY (sale_id) REFERENCES sales(id),
      FOREIGN KEY (sale_item_id) REFERENCES sale_items(id),
      FOREIGN KEY (product_id) REFERENCES products(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`);

    // Expenses table
    db.run(`CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      description TEXT NOT NULL,
      amount REAL NOT NULL,
      expense_date DATE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`);

    // Insert default categories
    const defaultCategories = ['Phone', 'Watch', 'Accessory'];
    const stmt = db.prepare('INSERT OR IGNORE INTO categories (name) VALUES (?)');
    defaultCategories.forEach(cat => stmt.run(cat));
    stmt.finalize();

    // Create default users (admin and superuser)
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)', 
      ['admin', defaultPassword, 'admin']);
    db.run('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)', 
      ['superuser', defaultPassword, 'superuser']);

    console.log('Database initialized successfully');
  });
}

// Authentication Middleware
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

const requireSuperuser = (req, res, next) => {
  if (req.session.userId && req.session.role === 'superuser') {
    next();
  } else {
    res.status(403).json({ error: 'Forbidden - Superuser access required' });
  }
};

// API Routes

// Auth Routes
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    
    res.json({ 
      success: true, 
      user: { id: user.id, username: user.username, role: user.role }
    });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/current-user', requireAuth, (req, res) => {
  res.json({ 
    id: req.session.userId, 
    username: req.session.username, 
    role: req.session.role 
  });
});

// Category Routes
app.get('/api/categories', requireAuth, (req, res) => {
  db.all('SELECT * FROM categories ORDER BY name', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/categories', requireAuth, (req, res) => {
  const { name } = req.body;
  db.run('INSERT INTO categories (name) VALUES (?)', [name], function(err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ id: this.lastID, name });
  });
});

app.delete('/api/categories/:id', requireAuth, (req, res) => {
  db.get('SELECT COUNT(*) as count FROM products WHERE category_id = ?', [req.params.id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.count > 0) {
      return res.status(400).json({ error: 'Cannot delete category with existing products' });
    }
    
    db.run('DELETE FROM categories WHERE id = ?', [req.params.id], (err) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ success: true });
    });
  });
});

// Product Routes
app.get('/api/products', requireAuth, (req, res) => {
  const query = `
    SELECT p.*, c.name as category_name 
    FROM products p 
    JOIN categories c ON p.category_id = c.id
    ORDER BY p.created_at DESC
  `;
  
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/products/:id', requireAuth, (req, res) => {
  db.get('SELECT * FROM products WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
});

app.post('/api/products', requireAuth, (req, res) => {
  const { category_id, name, description, serial_number, condition, supplier_phone, 
          supplier_cnic, purchase_price, selling_price, quantity, pta_approved, warranty_days } = req.body;
  
  db.run(`INSERT INTO products (category_id, name, description, serial_number, condition, 
          supplier_phone, supplier_cnic, purchase_price, selling_price, quantity, pta_approved, warranty_days)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [category_id, name, description, serial_number, condition, supplier_phone, supplier_cnic,
     purchase_price, selling_price, quantity, pta_approved ? 1 : 0, warranty_days || 0],
    function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
    }
  );
});

app.put('/api/products/:id', requireAuth, (req, res) => {
  const { category_id, name, description, serial_number, condition, supplier_phone,
          supplier_cnic, purchase_price, selling_price, quantity, pta_approved, warranty_days } = req.body;
  
  db.run(`UPDATE products SET category_id=?, name=?, description=?, serial_number=?, condition=?,
          supplier_phone=?, supplier_cnic=?, purchase_price=?, selling_price=?, quantity=?, 
          pta_approved=?, warranty_days=? WHERE id=?`,
    [category_id, name, description, serial_number, condition, supplier_phone, supplier_cnic,
     purchase_price, selling_price, quantity, pta_approved ? 1 : 0, warranty_days || 0, req.params.id],
    (err) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

app.delete('/api/products/:id', requireAuth, (req, res) => {
  db.run('DELETE FROM products WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ success: true });
  });
});

// Sales Routes
app.post('/api/sales', requireAuth, (req, res) => {
  const { customer_name, customer_phone, customer_cnic, payment_type, items, discount_amount, discount_type } = req.body;
  
  const invoiceNumber = 'INV' + Date.now();
  
  let subtotal = 0;
  let totalProfit = 0;
  
  items.forEach(item => {
    subtotal += item.line_total;
    totalProfit += item.profit;
  });
  
  const discountValue = discount_type === 'percentage' 
    ? (subtotal * discount_amount / 100) 
    : discount_amount;
  
  const netTotal = subtotal - discountValue;
  totalProfit -= discountValue;
  
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    
    db.run(`INSERT INTO sales (invoice_number, customer_name, customer_phone, customer_cnic, payment_type, 
            subtotal, discount_amount, discount_type, net_total, total_profit, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [invoiceNumber, customer_name, customer_phone, customer_cnic, payment_type, subtotal, 
       discount_amount, discount_type, netTotal, totalProfit, req.session.userId],
      function(err) {
        if (err) {
          db.run('ROLLBACK');
          return res.status(400).json({ error: err.message });
        }
        
        const saleId = this.lastID;
        const stmt = db.prepare(`INSERT INTO sale_items (sale_id, product_id, product_name, 
                                 quantity, unit_price, purchase_price, line_total, serial_imei, 
                                 profit, warranty_days, remarks)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        
        let completed = 0;
        items.forEach(item => {
          stmt.run([saleId, item.product_id, item.product_name, item.quantity, 
                   item.unit_price, item.purchase_price, item.line_total, 
                   item.serial_imei, item.profit, item.warranty_days || 0, item.remarks || ''], (err) => {
            if (err) {
              db.run('ROLLBACK');
              return res.status(400).json({ error: err.message });
            }
            
            db.run('UPDATE products SET quantity = quantity - ? WHERE id = ?',
              [item.quantity, item.product_id]);
            
            completed++;
            if (completed === items.length) {
              stmt.finalize();
              db.run('COMMIT');
              res.json({ success: true, saleId, invoiceNumber });
            }
          });
        });
      }
    );
  });
});

app.get('/api/sales', requireAuth, (req, res) => {
  const { start_date, end_date, phone, invoice, customer, serial, date } = req.query;
  
  let query = `SELECT s.*, GROUP_CONCAT(si.serial_imei) as serials 
               FROM sales s 
               LEFT JOIN sale_items si ON s.id = si.sale_id
               WHERE 1=1`;
  const params = [];
  
  if (start_date) {
    query += ' AND DATE(s.sale_date) >= DATE(?)';
    params.push(start_date);
  }
  
  if (end_date) {
    query += ' AND DATE(s.sale_date) <= DATE(?)';
    params.push(end_date);
  }
  
  if (phone) {
    query += ' AND s.customer_phone LIKE ?';
    params.push('%' + phone + '%');
  }
  
  if (invoice) {
    query += ' AND s.invoice_number LIKE ?';
    params.push('%' + invoice + '%');
  }
  
  if (customer) {
    query += ' AND s.customer_name LIKE ?';
    params.push('%' + customer + '%');
  }
  
  if (serial) {
    query += ' AND si.serial_imei LIKE ?';
    params.push('%' + serial + '%');
  }
  
  if (date) {
    query += ' AND DATE(s.sale_date) = DATE(?)';
    params.push(date);
  }
  
  query += ' GROUP BY s.id ORDER BY s.sale_date DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/sales/:id', requireAuth, (req, res) => {
  db.get('SELECT * FROM sales WHERE id = ?', [req.params.id], (err, sale) => {
    if (err) return res.status(500).json({ error: err.message });
    
    db.all('SELECT * FROM sale_items WHERE sale_id = ?', [req.params.id], (err, items) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ ...sale, items });
    });
  });
});

// Returns Routes
app.post('/api/returns', requireAuth, (req, res) => {
  const { sale_id, sale_item_id, product_id, quantity, reason } = req.body;
  
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    
    db.get('SELECT * FROM sale_items WHERE id = ?', [sale_item_id], (err, item) => {
      if (err) {
        db.run('ROLLBACK');
        return res.status(400).json({ error: err.message });
      }
      
      const availableQty = item.quantity - item.returned_quantity;
      if (quantity > availableQty) {
        db.run('ROLLBACK');
        return res.status(400).json({ error: 'Quantity exceeds available items for return' });
      }
      
      const returnAmount = item.unit_price * quantity;
      const returnProfit = (item.profit / item.quantity) * quantity;
      
      db.run(`INSERT INTO returns (sale_id, sale_item_id, product_id, quantity, return_amount, return_profit, reason, created_by)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [sale_id, sale_item_id, product_id, quantity, returnAmount, returnProfit, reason, req.session.userId],
        function(err) {
          if (err) {
            db.run('ROLLBACK');
            return res.status(400).json({ error: err.message });
          }
          
          db.run('UPDATE sale_items SET returned_quantity = returned_quantity + ? WHERE id = ?',
            [quantity, sale_item_id], (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(400).json({ error: err.message });
              }
              
              db.run('UPDATE products SET quantity = quantity + ? WHERE id = ?',
                [quantity, product_id], (err) => {
                  if (err) {
                    db.run('ROLLBACK');
                    return res.status(400).json({ error: err.message });
                  }
                  
                  db.run(`UPDATE sales SET net_total = net_total - ?, total_profit = total_profit - ?
                          WHERE id = ?`,
                    [returnAmount, returnProfit, sale_id], (err) => {
                      if (err) {
                        db.run('ROLLBACK');
                        return res.status(400).json({ error: err.message });
                      }
                      
                      db.run('COMMIT');
                      res.json({ success: true });
                    });
                });
            });
        }
      );
    });
  });
});

app.get('/api/returns', requireAuth, (req, res) => {
  const query = `
    SELECT r.*, p.name as product_name, s.invoice_number, s.customer_name, s.customer_phone
    FROM returns r
    JOIN products p ON r.product_id = p.id
    JOIN sales s ON r.sale_id = s.id
    ORDER BY r.return_date DESC
  `;
  
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Expenses Routes
app.get('/api/expenses', requireSuperuser, (req, res) => {
  const { start_date, end_date } = req.query;
  
  let query = 'SELECT * FROM expenses WHERE 1=1';
  const params = [];
  
  if (start_date) {
    query += ' AND DATE(expense_date) >= DATE(?)';
    params.push(start_date);
  }
  
  if (end_date) {
    query += ' AND DATE(expense_date) <= DATE(?)';
    params.push(end_date);
  }
  
  query += ' ORDER BY expense_date DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/expenses', requireSuperuser, (req, res) => {
  const { description, amount, expense_date } = req.body;
  
  db.run(`INSERT INTO expenses (description, amount, expense_date, created_by)
          VALUES (?, ?, ?, ?)`,
    [description, amount, expense_date, req.session.userId],
    function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
    }
  );
});

app.delete('/api/expenses/:id', requireSuperuser, (req, res) => {
  db.run('DELETE FROM expenses WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ success: true });
  });
});

// Dashboard Stats
app.get('/api/dashboard/stats', requireSuperuser, (req, res) => {
  const { start_date, end_date } = req.query;
  
  let salesQuery = 'SELECT COUNT(*) as count, SUM(net_total) as total, SUM(total_profit) as profit FROM sales WHERE 1=1';
  let expensesQuery = 'SELECT SUM(amount) as total FROM expenses WHERE 1=1';
  const params = [];
  
  if (start_date) {
    salesQuery += ' AND DATE(sale_date) >= DATE(?)';
    expensesQuery += ' AND DATE(expense_date) >= DATE(?)';
    params.push(start_date);
  }
  
  if (end_date) {
    salesQuery += ' AND DATE(sale_date) <= DATE(?)';
    expensesQuery += ' AND DATE(expense_date) <= DATE(?)';
    params.push(end_date);
  }
  
  db.get(salesQuery, params, (err, salesData) => {
    if (err) return res.status(500).json({ error: err.message });
    
    db.get(expensesQuery, params, (err, expensesData) => {
      if (err) return res.status(500).json({ error: err.message });
      
      const netProfit = (salesData.profit || 0) - (expensesData.total || 0);
      
      res.json({
        transactions: salesData.count || 0,
        totalSales: salesData.total || 0,
        totalProfit: salesData.profit || 0,
        totalExpenses: expensesData.total || 0,
        netProfit: netProfit
      });
    });
  });
});

app.get('/api/dashboard/top-products', requireSuperuser, (req, res) => {
  const query = `
    SELECT product_name, SUM(quantity) as total_sold, SUM(line_total) as revenue
    FROM sale_items
    GROUP BY product_name
    ORDER BY total_sold DESC
    LIMIT 10
  `;
  
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/dashboard/low-stock', requireSuperuser, (req, res) => {
  const query = `
    SELECT p.*, c.name as category_name 
    FROM products p 
    JOIN categories c ON p.category_id = c.id
    WHERE p.quantity < 5 
    ORDER BY p.quantity ASC
  `;
  
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Export/Import Database
app.get('/api/export/database', requireSuperuser, (req, res) => {
  const dbPath = path.join(__dirname, 'mobile_shop.db');
  res.download(dbPath, 'mobile_shop_backup.db');
});

app.post('/api/import/database', requireSuperuser, upload.single('database'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const uploadPath = req.file.path;
  const dbPath = path.join(__dirname, 'mobile_shop.db');
  
  db.close(() => {
    fs.copyFile(uploadPath, dbPath, (err) => {
      fs.unlinkSync(uploadPath);
      
      if (err) {
        return res.status(500).json({ error: 'Error importing database' });
      }
      
      res.json({ success: true, message: 'Database imported. Please restart the server.' });
    });
  });
});

// Export to Excel (CSV format)
app.get('/api/export/excel', requireSuperuser, (req, res) => {
  const exports = {};
  
  db.all('SELECT * FROM sales ORDER BY sale_date DESC', (err, sales) => {
    exports.sales = sales;
    
    db.all('SELECT * FROM expenses ORDER BY expense_date DESC', (err, expenses) => {
      exports.expenses = expenses;
      
      db.all(`SELECT p.*, c.name as category_name FROM products p 
              JOIN categories c ON p.category_id = c.id`, (err, products) => {
        exports.products = products;
        
        db.all(`SELECT r.*, s.invoice_number, s.customer_name 
                FROM returns r JOIN sales s ON r.sale_id = s.id`, (err, returns) => {
          exports.returns = returns;
          
          res.json(exports);
        });
      });
    });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Default credentials:');
  console.log('Admin - username: admin, password: admin123');
  console.log('Superuser - username: superuser, password: admin123');
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('Database connection closed.');
    process.exit(0);
  });
});
