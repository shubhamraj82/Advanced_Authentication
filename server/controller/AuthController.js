import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";

export const register =  async (req,res)=>{
    console.log('Request body:', req.body);
    console.log('Content-Type:', req.headers['content-type']);
    
    if(!req.body){
        return res.json({success:false, message:'No request body received. Make sure Content-Type is application/json'})
    }
    
    const {name,email,password}=req.body;
    if(!name||!email||!password){
        return res.json({success:false, message:'Missing Details'})
    }
    try {
        const existingUser = await userModel.findOne({email});
        if(existingUser){
            return res.json({success:false, message:"User already exists"});
        }
        const hashedPassword = await bcrypt.hash(password,10);

        const newUser=new userModel({name,email,password:hashedPassword});
        await newUser.save();

        const token=jwt.sign({id: newUser._id}, process.env.JWT_SECRET, { expiresIn:'7d'});
        res.cookie('token', token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7*24*60*60*1000
        });

        // sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Grooker Website',
            text: `Welcome to Grooker Website. Your account has been created with email id: ${email}`
        }

        try {
            await transporter.sendMail(mailOptions);
            console.log('Welcome email sent successfully to:', email);
        } catch (emailError) {
            console.error('Failed to send welcome email:', emailError.message);
            // Continue with registration even if email fails
        }

        return res.json({success:true, message:'Registration successful'});

    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const login =async(req,res)=>{
    const {email,password}=req.body;
    if(!email || !password){
        return res.json({success:false, message:"Email and password are required"});
    }
    try {
        const newLoginUser=await userModel.findOne({email});
        if(!newLoginUser){
            return res.json({success:false,message:'Invalid email'})
        }
        const isMatch = await bcrypt.compare(password,newLoginUser.password);
        if(!isMatch){
            return res.json({success:false, message:'Invalid password'})
        }

          const token=jwt.sign({id: newLoginUser._id}, process.env.JWT_SECRET, { expiresIn:'7d'});
        res.cookie('token', token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7*24*60*60*1000
        });

         return res.json({success:true, message:'Login successful'});


    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

export const logout=async(req,res)=>{
    try {
         res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });
        return res.json({success:true,message: "Logged Out"})
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

// Send Verification OTP to the User's Email
export const sendVerifyOtp = async(req,res)=>{
    try {
        const {userId} =req.body;
        const user = await userModel.findById(userId);
        if(user.isAccountVerified){
            return res.json({success:false, message:"Account already verified"})
        }

        const otp=String(Math.floor(100000+ Math.random()*900000));
        user.verifyOtp = otp;
        user. verifyOtpExpiredAt = Date.now() + 24 * 60 * 60 * 1000
        await user.save();

        const mailOption={
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP is ${otp}. Verify your account using this OTP.`
        }
        await transporter.sendMail(mailOption);
        return res.json({success:true, message:'Verification OTP sent on Email'});

    } catch (error) {
        return res.json({success:false,message: error.message})
    }
}

//verify otp using email
export const verifyEmail = async(req,res)=>{
    const {userId,otp}=req.body;
    if(!userId || !otp){
       return res.json({success:false,message:"Missing Details"});
    }
    try {
        const user = await userModel.findById(userId);
        if(!user){
            return res.json({success:false,message:'User not found'});
        }
        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({success:false, message:'Invalid OTP'});
        }
        if(user.verifyOtpExpiredAt<Date.now()){
            return res.json({success:false, message:'OTP Expired'});
        }

        user.isAccountVerified=true;
        user.verifyOtp='';
        user.verifyOtpExpiredAt=0;

        await user.save();
        return res.json({success:true, message: 'Email Verified successfully'})
    } catch (error) {
        return res.json({success:false,message:error.message});
    }

}

//check if user is authenticated or not
export const isAuthenticated = async(req,res)=>{
    try {
        return res.json({success:true});
    } catch (error) {
       return res.json({success:false,message:error.message});
    }
}

// Send Password Reset OTP
export const sendResetOtp = async (req,res)=>{
    const{email}=req.body;
    if(!email){
        return res.json({success:false,message:'Email is required'});
    }
    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success:false, message:'User not found'});
        }
        const otp=String(Math.floor(100000+ Math.random()*900000));

        user.resetOtp = otp;
        user.resetOtpExperAt = Date.now() + 15 * 60 * 1000
        await user.save();

        const mailOption={
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password.`
        }
        await transporter.sendMail(mailOption);

       return res.json({success:true, message:'OTP sent to your email'});
        
    } catch (error) {
        return res.json({success:false, message:error.message});
    }
}

//Reset User Password
export const resetPassword = async (req,res)=>{
    const{email,otp,newPassowrd}=req.body;
    if(!email || !otp || !newPassowrd){
        return res.json({success:false,message:'Email,OTP, and new Password are required'});
    }
    try {
        const user= await userModel.findOne({email});
        if(!user){
            return res.json({success:false, message:'User not found'});
        }
        if(user.otp==="" || user.resetOtp!==otp){
            return res.json({success:false, message:'Invalid OTP'});
        }
        if(user.resetOtpExperAt<Date.now()){
            return res.json({success:false, message:'OTP Expired'});
        }

        const hashedPassword = await bcrypt.hash(newPassowrd,10);

        user.password=hashedPassword;
        user.resetOtp='';
        user.resetOtpExperAt=0;

        await user.save();

        return res.json({success:true, message:'Password has been reset successfully'});

    } catch (error) {
        return res.json({success:false, message:error.message});
    }
}
