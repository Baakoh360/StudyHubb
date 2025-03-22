const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

// Load environment variables
dotenv.config();

// Create Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model('User', userSchema);

// Quiz Schema
const quizSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    description: String,
    questions: [{
        question: String,
        options: [String],
        correctAnswer: Number
    }],
    creator: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const Quiz = mongoose.model('Quiz', quizSchema);

// File Schema
const fileSchema = new mongoose.Schema({
    name: String,
    originalName: String,
    category: String,
    path: String,
    size: Number,
    type: String,
    uploadedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    uploadDate: {
        type: Date,
        default: Date.now
    }
});

const File = mongoose.model('File', fileSchema);

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file storage
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function(req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

// Auth middleware for protected routes
const auth = (req, res, next) => {
    try {
        const token = req.header('x-auth-token');
        if (!token) {
            return res.status(401).json({ message: 'No token, authorization denied' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Authentication routes
app.post('/api/signup', async(req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword
        });

        await newUser.save();

        // Create JWT token
        const token = jwt.sign({ userId: newUser._id },
            process.env.JWT_SECRET, { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User created successfully',
            token,
            userId: newUser._id
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/login', async(req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Create JWT token
        const token = jwt.sign({ userId: user._id },
            process.env.JWT_SECRET, { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            userId: user._id,
            username: user.username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User routes
app.get('/api/users/me', auth, async(req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Fetch user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Quiz routes
app.post('/api/quizzes', auth, async(req, res) => {
    try {
        const { title, description, questions } = req.body;
        const newQuiz = new Quiz({
            title,
            description,
            questions,
            creator: req.userId
        });

        await newQuiz.save();
        res.status(201).json({ message: 'Quiz created successfully', quiz: newQuiz });
    } catch (error) {
        console.error('Quiz creation error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/quizzes', auth, async(req, res) => {
    try {
        const quizzes = await Quiz.find().sort({ createdAt: -1 });
        res.json(quizzes);
    } catch (error) {
        console.error('Fetch quizzes error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/quizzes/:id', auth, async(req, res) => {
    try {
        const quiz = await Quiz.findById(req.params.id);
        if (!quiz) {
            return res.status(404).json({ message: 'Quiz not found' });
        }
        res.json(quiz);
    } catch (error) {
        console.error('Fetch quiz error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/quizzes/:id', auth, async(req, res) => {
    try {
        const { title, description, questions } = req.body;
        const quiz = await Quiz.findById(req.params.id);

        if (!quiz) {
            return res.status(404).json({ message: 'Quiz not found' });
        }

        // Check if user is the creator
        if (quiz.creator.toString() !== req.userId) {
            return res.status(401).json({ message: 'Not authorized to update this quiz' });
        }

        quiz.title = title;
        quiz.description = description;
        quiz.questions = questions;
        quiz.updatedAt = Date.now();

        await quiz.save();
        res.json({ message: 'Quiz updated successfully', quiz });
    } catch (error) {
        console.error('Update quiz error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/quizzes/:id', auth, async(req, res) => {
    try {
        const quiz = await Quiz.findById(req.params.id);

        if (!quiz) {
            return res.status(404).json({ message: 'Quiz not found' });
        }

        // Check if user is the creator
        if (quiz.creator.toString() !== req.userId) {
            return res.status(401).json({ message: 'Not authorized to delete this quiz' });
        }

        await Quiz.findByIdAndDelete(req.params.id);
        res.json({ message: 'Quiz deleted successfully' });
    } catch (error) {
        console.error('Delete quiz error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// File upload route
app.post('/api/upload', auth, upload.array('files'), async(req, res) => {
    try {
        const category = req.body.category;
        const savedFiles = [];

        for (const file of req.files) {
            const newFile = new File({
                name: file.filename,
                originalName: file.originalname,
                category: category,
                path: file.path,
                size: file.size,
                type: file.mimetype,
                uploadedBy: req.userId
            });

            const savedFile = await newFile.save();
            savedFiles.push(savedFile);
        }

        res.status(200).json(savedFiles);
    } catch (error) {
        console.error('Error saving files:', error);
        res.status(500).json({ error: 'Failed to upload files' });
    }
});

// Get files by category
app.get('/api/files/:category', auth, async(req, res) => {
    try {
        const category = req.params.category;
        const files = await File.find({
            category: category,
            uploadedBy: req.userId
        }).sort({ uploadDate: -1 });

        res.status(200).json(files);
    } catch (error) {
        console.error('Error fetching files:', error);
        res.status(500).json({ error: 'Failed to fetch files' });
    }
});

// Delete file
app.delete('/api/files/:category/:fileId', auth, async(req, res) => {
    try {
        const fileId = req.params.fileId;
        const file = await File.findById(fileId);

        if (!file) {
            return res.status(404).json({ message: 'File not found' });
        }

        // Check if user is the owner of the file
        if (file.uploadedBy.toString() !== req.userId) {
            return res.status(401).json({ message: 'Not authorized to delete this file' });
        }

        // Delete the file from the filesystem
        fs.unlink(file.path, async(err) => {
            if (err) {
                console.error('Error deleting file from filesystem:', err);
                // Continue with database deletion even if filesystem deletion fails
            }

            // Delete the file from the database
            await File.findByIdAndDelete(fileId);
            res.status(200).json({ message: 'File deleted successfully' });
        });
    } catch (error) {
        console.error('Error deleting file:', error);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Updated OpenAI integration for v4 of the API
const OpenAI = require("openai");

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// Chat Route (Frontend will send messages here)
app.post('/api/chat', auth, async(req, res) => {
    try {
        const { messages } = req.body;

        if (!messages || !Array.isArray(messages)) {
            return res.status(400).json({ error: "Invalid request format" });
        }

        const response = await openai.chat.completions.create({
            model: "gpt-3.5-turbo", // or "gpt-4" if you have access
            messages: messages,
            max_tokens: 1000
        });

        res.json({ response: response.choices[0].message.content });
    } catch (error) {
        console.error("OpenAI API Error:", error);
        res.status(500).json({ error: "Failed to fetch AI response" });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;