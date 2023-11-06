const jwt = require("jsonwebtoken");
require("dotenv").config();


exports.auth = (req,res,next)=>{
    try{
        //fetching out token
        const token = req.body.token || req.cookies.token;

        if(!token){
            return res.status(401).json({
                success:false,
                message:'Token missing'
            })
        }

        //verify the token 
        try{
            const decode = jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);

            req.user = decode;
        }catch(error){
            return res.status(401).json({
                success:false,
                message:'token is invalid',
            })
        }
        next();

    }catch(error){
        return res.status(401).json({
            success:false,
            message:'Something went wrong while verifying the token'
        })
    }
}

//Used for authorizationv 
exports.isStudent = (req,res,next)=>{
    try{
        if(req.user.role !== "Student"){
            return res.status(401).json({
                success:false,
                message:'This is protected route for Student'
            })
            
        }
        next();
    }catch(error){
        return res.status(500).json({
            success:false,
            message:'User role cannot be verified'
        })
    }
}

exports.isAdmin = (req, res, next) => {
    try {
        if (req.user.role !== "Admin") {
        return res.status(401).json({
            success: false,
            message: "This is protected route for Admin",
        });
        }
        next();
    } catch (error) {
        return res.status(500).json({
        success: false,
        message: "User role cannot be verified",
        });
    }
};
