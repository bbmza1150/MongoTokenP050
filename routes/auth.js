const express = require('express');
const router = express.Router();

const {register , login , refresh} = require("../controllers/authController");

router.post("/",async(req,res)=>{
    res.sendStatus(404);
});

router.post("/register",register);
router.post("/login",login);
router.post("/refresh",refresh);

module.exports = router;