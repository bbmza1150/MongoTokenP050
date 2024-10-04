const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
    product_name: {type: String , required: true},
    product_type: {type: String , required: true},
    price : {type: Number ,required : true},
    unit : {type : String , required : true},
},{timestamps:true , versionKey:false});

module.exports = mongoose.model('Product',productSchema);