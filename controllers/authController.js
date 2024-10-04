const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../model/user");
const dotenv = require('dotenv');

dotenv.config();

exports.register = async (req, res) => {
    const {username, password, name, role, email} = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username, 
            password: hashedPassword,
            name,
            role,
            email // เพิ่มฟิลด์อีเมล
        });
        await user.save();
        res.status(201).send("User registered");
    } catch (err) {
        res.status(400).send(err.message);
    }
};


exports.login = async(req,res) =>{
    const {username , password,name,role} = req.body;
    try {
        const tmpuser = await User.findOne({username});
        if(!tmpuser) return res.status(400).send("User not found");
        const isMatch = await bcrypt.compare(password, tmpuser.password);
        if(!isMatch) return res.status(400).send("Invalid cradentials");
        const user = await User.findOne({username}).select("-password");
       
        const accessToken = jwt.sign(
            {userId : user._id},
            process.env.ACCESS_TOKEN_SECRET,
            {expiresIn : "10m"}
        );
        const refreshToken = jwt.sign(
            {userId: user._id},
            process.env.REFRESH_TOKEN_SECRET,
            {expiresIn : "15m"}
        );
        res.json({user,accessToken, refreshToken});

    }catch (err){
        res.status(500).send(err.message);
    }
};

exports.refresh = async(req,res) =>{
    const token = req.headers['authorization']?.split(' ')[1]; // 'Bearer <token>'
    if (!token) return res.status(401).json({ message: 'No token provided' });
    jwt.verify(token , process.env.REFRESH_TOKEN_SECRET, (err, user)=>{
        if (err) {
            if (err.name === "TokenExpiredError") {
                return res.status(401).send("Refresh token expired. Please log in again.");
            }
            return res.status(403).send("Invalid refresh token");
        }

        const accessToken = jwt.sign(
            {userID: user.userId},
            process.env.ACCESS_TOKEN_SECRET,
            {expiresIn:"1m"}
        );
        res.json({accessToken});
    })
}