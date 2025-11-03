import mongoose from "mongoose";

//Function to connect to the database
export const connectDB=async()=>{
    try {
        mongoose.connection.on('connected',()=> console.log('Databse connection estanblished'));
        await mongoose.connect(`${process.env.MONGODB_URL}/advanced-authentication`);
    } catch (error) {
        console.log(error)
    }
}

export default connectDB;