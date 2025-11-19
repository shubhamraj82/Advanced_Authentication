import express from 'express';
import { login, logout, register } from '../controller/AuthController.js';

const authRouter = express.Router();

authRouter.post('/userRegister', register);
authRouter.post('/login', login);
authRouter.post('/logout',logout);

export default authRouter;