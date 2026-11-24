const db = require('../models');
const brypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const user = db.User;

async function register(req, res) {
    try {
        const {email, password} = req.body;
        if (!email || !password) {
            return res.status(400).json({message: 'Email dan password wajib diisi.'});
        }
        const existingUser = await user.findOne({where: {email}});
        if (existingUser) {
            return res.status(400).json({message: 'Email sudah terdaftar.'});
        }
        const hashedPassword = await brypt.hash(password, 10);
        const user = await user.create({
            email,
            password: hashedPassword,
        });
        return res.status(201).json({
            message: 'Registrasi berhasil.', 
            data: {id: user.id, email: user.email}
        });
    } catch (err) {
        return res.status(500).json({ error: err.message});
    }
}

async function login(req, res) {
    try {
        const {email, password} = req.body;
        if (!email || !password) {
            return res.status(400).json({message: 'Email dan password wajib diisi.'});
        }
        const user = await user.findOne({where: {email}});
        if (!user) {
            return res.status(401).json({message: 'Email atau password salah.'});
        }
        const isMatch = await brypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({message: 'Email atau password salah.'});
        }
        const token = jwt.sign(
            {id: user.id, email: user.email},
            process.env.JWT_SECRET,
            {expiresIn: process.env.JWT_EXPIRES}
        );
        return res.status(200).json({
            message: 'Login berhasil.',
            token,
        });
    } catch (err) {
        return res.status(500).json({ error: err.message});
    }
}

module.exports = {
    register,
    login,
};