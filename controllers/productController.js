const Product = require('../model/product'); // เรียกใช้โมเดล Product

//CRUD
exports.getProducts = async(req,res) =>{
    try{
        const products = await Product.find();
        res.status(200).json(products);

    }catch (err){
        res.status(500).json({message: err.message});
    }
};

exports.getProduct = async (req,res) =>{
    try{
        const { id } = req.params;
        const product  = await Product.findById(id);
        if (!product) return res.status(404).json({message:"Product not found"});
        res.status(200).json(product);
    }catch (err){
        res.status(500).json({ message: err.message });
    }
};

exports.createProduct = async (req,res) => {
    const {product_name, product_type, price, unit} = req.body;

    const product = new Product({product_name, product_type, price,unit})
    try{
        const newProduct = await product.save();
        res.status(201).json(newProduct);
    }catch (err){
        res.status(400).json({message: err.message});
    }
};

exports.updateProduct = async (req,res) => {
    try{
        const {id} = req.params;
        const product = await Product.findById(id);

        if(!product) return res.status(404).json({message : 'Product not found'});
        const data = {$set : req.body};

        await Product.findByIdAndUpdate(id,data);

        res.status(200).json({ message: 'Product updated successfully' });
    }catch (err) { 

        res.status(400).json({ message: err.message }); 

    }
}

exports.deleteProduct = async(req,res) =>{
    try{
        const { id } = req.params;
        const product = await Product.findById(id);
        if(!product) return res.status(404).json({message: 'Product not found'});
        await Product.findByIdAndDelete(id);
        res.status(200).json({ message: 'Product deleted successfully' });
    }catch(err){
        res.status(404).json({message : err.message});
    }
}
