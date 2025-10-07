require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const PORT = process.env.PORT || 3001;
const app = express();
const router = require('./router/index');
const errorMiddleware = require('./exceptions/error-middleware');

app.use(express.json())
app.use(cookieParser());
app.use(cors({
  credentials: true,
  origin: process.env.CLIENT_URL
}));
app.use('/api', router);
app.use(errorMiddleware);

// Middleware для обработки ошибок
app.use((err, req, res, next) => {
    console.error('Ошибка сервера:', err.message);
    return res.status(500).json({
        message: err.message || 'Внутренняя ошибка сервера',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});
const start = async () => {
    try {
        await mongoose.connect(process.env.DB_URL);
        app.listen(PORT, () => console.log(`Server start on Port: ${PORT}`))
    } catch (e) {
        console.log(e);
    }
}

start();
