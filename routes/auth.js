const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const flash = require('connect-flash');
const otpGenerator = require('otp-generator');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const Patient = require('../models/Patient');
const Doctor = require('../models/Doctor');
const Admin = require('../models/Admin');
const crypto = require('crypto');

const router = express.Router();

router.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

router.use(flash());

router.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  next();
});

const sendOTP = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Verification OTP for Signup',
    text: `Your OTP for signup is: ${otp}`
  };

  await transporter.sendMail(mailOptions);
};
const generateVerificationToken = () => {
  return crypto.randomBytes(20).toString('hex');
};

const sendVerificationEmail = async (email, token, role) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });

  const verificationLink = `http://localhost:8000/auth/verify-email?token=${token}&role=${role}`;


  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Email Verification for Signup',
    text: `Click the following link to verify your email: ${verificationLink}`
  };

  await transporter.sendMail(mailOptions);
};

router.get('/signup/patient', (req, res) => {
  const showOtpForm = req.session.newUser && req.session.newUser.otp;
  res.render('signup_patient', { showOtpForm });
});

router.post('/signup/patient', async (req, res) => {
  const { name, email, password, phoneNumber } = req.body;

  try {
    let existingUser = await Patient.findOne({ email });

    if (existingUser) {
      req.flash('error_msg', 'User already exists');
      return res.redirect('/auth/signup/patient');
    }

    const token = generateVerificationToken();
    await sendVerificationEmail(email, token, 'patient');

    const newPatient = new Patient({
      name,
      email,
      password: await bcrypt.hash(password, 10),
      phoneNumber,
      verificationToken: token
    });

    await newPatient.save();

    req.flash('success_msg', 'Verification email has been sent to your email. Please verify.');
    return res.redirect('/auth/signup/patient');
  } catch (err) {
    console.error('Error in patient signup:', err);
    req.flash('error_msg', 'Server error');
    return res.redirect('/auth/signup/patient');
  }
});

router.get('/signup/doctor', (req, res) => {
  const showOtpForm = req.session.newUser && req.session.newUser.otp;
  res.render('signup_doctor', { showOtpForm });
});

router.post('/signup/doctor', async (req, res) => {
  const { name, email, password, phoneNumber } = req.body;

  try {
    let existingUser = await Doctor.findOne({ email });

    if (existingUser) {
      req.flash('error_msg', 'User already exists');
      return res.redirect('/auth/signup/doctor');
    }

    const token = generateVerificationToken();
    await sendVerificationEmail(email, token, 'doctor');

    const newDoctor = new Doctor({
      name,
      email,
      password: await bcrypt.hash(password, 10),
      phoneNumber,
      verificationToken: token
    });

    await newDoctor.save();

    req.flash('success_msg', 'Verification email has been sent to your email. Please verify.');
    return res.redirect('/auth/signup/doctor');
  } catch (err) {
    console.error('Error in doctor signup:', err);
    req.flash('error_msg', 'Server error');
    return res.redirect('/auth/signup/doctor');
  }
});

router.get('/verify-email', async (req, res) => {
  const { token, role } = req.query;

  try {
    let user;
    if (role === 'patient') {
      user = await Patient.findOne({ verificationToken: token });
    } else if (role === 'doctor') {
      user = await Doctor.findOne({ verificationToken: token });
    }

    if (!user) {
      req.flash('error_msg', 'Invalid or expired verification link');
      return res.redirect(`/auth/signup/${role}`);
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    req.flash('success_msg', 'Your account has been verified. You can now login.');
    return res.redirect('/auth/login');
  } catch (err) {
    console.error('Error in email verification:', err);
    req.flash('error_msg', 'Server error');
    return res.redirect('/auth/signup');
  }
});




router.get('/login', (req, res) => {
  res.render('login');
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = await Patient.findOne({ email }) ||
               await Doctor.findOne({ email }) ||
               await Admin.findOne({ email });

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid Credentials' });
    }

    if (!user.isVerified) {
      return res.status(401).json({ success: false, message: 'Please verify your email before logging in.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid Credentials' });
    }

    req.session.user = {
      _id: user._id,
      email: user.email,
      role: user.role,
      subscriptionType: user.subscriptionType,
      subscriptionVerification: user.subscriptionVerification
    };
    console.log('Session data after login:', req.session);
    return res.status(200).json({ success: true, message: 'Login successful', user });
  } catch (err) {
    console.error('Error in login:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});



const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

const oauth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

router.get('/google/patient', (req, res) => {
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['profile', 'email'],
    state: JSON.stringify({ role: 'patient' }) 
  });
  res.redirect(authUrl);
});

router.get('/google/doctor', (req, res) => {
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['profile', 'email'],
    state: JSON.stringify({ role: 'doctor' }) 
  });
  res.redirect(authUrl);
});

router.get('/google', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email'
    ],
    prompt: 'consent', 
  });
  res.redirect(url);
});


router.get('/google/callback', async (req, res) => {
  const { code } = req.query;

  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({
      auth: oauth2Client,
      version: 'v2'
    });

    const { data } = await oauth2.userinfo.get();
    const { name, email } = data;

    let existingUser = await Patient.findOne({ email })
                       || await Doctor.findOne({ email })
                       || await Admin.findOne({ email });
console.log(existingUser);
    if (existingUser) {
      req.session.user = existingUser;
      res.json({
        success: true,
        user: existingUser,
        message: 'Logged in successfully',
        role: existingUser.role
      });

    } else {
      const { role } = JSON.parse(req.query.state);

      let newUser;
      if (role === 'patient') {
        newUser = new Patient({
          name,
          email,
          role: 'patient', 
        });
      } else if (role === 'doctor') {
        newUser = new Doctor({
          name,
          email,
          role: 'doctor', 
        });
      } else {
        return res.status(400).json({ success: false, message: 'Invalid role' });
      }

      const salt = await bcrypt.genSalt(10);
      newUser.password = await bcrypt.hash(email, salt); 

      await newUser.save();

      req.session.user = newUser;
      res.json({
        success: true,
        user: newUser,
        message: 'Logged in successfully',
        role: newUser.role
      });
    }
  } catch (err) {
    console.error('Error in Google OAuth callback:', err);
    res.status(500).json({ success: false, message: 'Authentication failed. Please try again.' });
  }
});

router.get('/logout', (req, res) => {
  req.flash('success_msg', 'Logged out successfully');
  req.session.destroy(err => {
    if (err) {
      console.error('Error in session destruction:', err);
      req.flash('error_msg', 'Error logging out');
      return res.redirect('/');
    }

    res.clearCookie('connect.sid');
    res.redirect('/auth/login');
  });
});

router.get('/exit', (req, res) => {
  req.flash('success_msg', 'Exited successfully');
  req.session.destroy(err => {
    if (err) {
      console.error('Error in session destruction:', err);
      req.flash('error_msg', 'Error exiting');
      return res.redirect('/auth/signup');
    }

    res.clearCookie('connect.sid');
    res.redirect('/auth/login');
  });
});

module.exports = router;


router.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    let user = await Patient.findOne({ email }) ||
               await Doctor.findOne({ email }) ||
               await Admin.findOne({ email });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = Date.now() + 3600000; // 1 hour

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpires;

    await user.save();

    const resetUrl = `http://localhost:8000/auth/reset-password?token=${resetToken}`;
    await sendResetPasswordEmail(user.email, resetUrl);

    return res.json({ success: true, message: 'A password reset link has been sent to your email.' });
  } catch (err) {
    console.error('Error in forgot password:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});


const generateResetToken = () => {
  return crypto.randomBytes(20).toString('hex');
};

const sendResetPasswordEmail = async (email, resetUrl) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Password Reset',
    text: `You requested a password reset. Click the following link to reset your password: ${resetUrl}`
  };

  await transporter.sendMail(mailOptions);
};

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    let user = await Patient.findOne({ email }) ||
               await Doctor.findOne({ email }) ||
               await Admin.findOne({ email });

    if (!user) {
      req.flash('error_msg', 'User not found');
      return res.redirect('/auth/forgot-password');
    }

    const token = generateResetToken();
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; 

    await user.save();

    await sendResetEmail(email, token);

    req.flash('success_msg', 'Reset link has been sent to your email.');
    return res.redirect('/auth/forgot-password');
  } catch (err) {
    console.error('Error in forgot password:', err);
    req.flash('error_msg', 'Server error');
    return res.redirect('/auth/forgot-password');
  }
});

router.get('/reset-password', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ success: false, message: 'Invalid or expired password reset token' });
  }

  try {
    let user = await Patient.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } }) ||
               await Doctor.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } }) ||
               await Admin.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired password reset token' });
    }

    res.render('reset-password', { token });
  } catch (err) {
    console.error('Error in reset password:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.post('/reset-password', async (req, res) => {
  const { token, newPassword, confirmPassword } = req.body;

  if (!token || !newPassword || !confirmPassword) {
    return res.status(400).json({ success: false, message: 'Please fill all fields' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ success: false, message: 'Passwords do not match' });
  }

  try {
    let user = await Patient.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } }) ||
               await Doctor.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } }) ||
               await Admin.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired password reset token' });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    return res.json({ success: true, message: 'Password reset successful. Please login with your new password.' });
  } catch (err) {
    console.error('Error in reset password:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
