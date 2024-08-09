const express = require('express');
const router = express.Router();
const multer = require('multer');
const Patient = require('../models/Patient');
const Doctor = require('../models/Doctor');
const Booking = require('../models/Booking');
const Admin = require('../models/Admin'); 
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const Blog = require('../models/Blog');
const Chat = require('../models/Chat');
const Prescription = require('../models/Prescription');
const Notification = require('../models/Notification');
const Insurance = require('../models/Insurance');

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

function isLoggedIn(req, res, next) {
  if (req.session.user && req.session.user.role === 'patient') {
    req.user = req.session.user;
    return next();
  }
  

  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  

  res.redirect('/auth/login');
}



router.get('/patient-index', async (req, res) => {
  try {
    const highPriorityBlogs = await Blog.find({ priority: 'high', verificationStatus: 'Verified' }).limit(5).exec();
      const patientEmail = req.session.user.email; 
      const patient = await Patient.findOne({email: patientEmail}).lean(); 

      res.render('patient-index', { blogs: highPriorityBlogs, patient });
  } catch (error) {
      console.error('Error fetching high-priority blogs:', error);
      res.status(500).send('Internal Server Error');
  }
});

router.get('/profile', isLoggedIn, async (req, res) => {
  try {
    const patientEmail = req.session.user.email;
    const patient = await Patient.findOne({ email: patientEmail }).lean();
    if (!patient) {
      return res.status(404).json({ message: 'Patient not found' });
    }
    res.status(200).json({ patient });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: 'Server Error' });
  }
});


router.get('/edit', isLoggedIn, async (req, res) => {
  try {
    const patientEmail = req.session.user.email;
    const patient = await Patient.findOne({ email: patientEmail }).lean();
    if (!patient) {
      return res.status(404).send('Patient not found');
    }
    res.render('editPatientProfile', { patient });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

router.post('/profile/update', upload.single('profilePicture'), isLoggedIn, async (req, res) => {
  try {
    const patientEmail = req.session.user.email;
    let patient = await Patient.findOne({ email: patientEmail });

    if (!patient) {
      return res.status(404).send('Patient not found');
    }

    const updateData = {
      ...req.body,
      emergencyContacts: Array.isArray(req.body.emergencyContacts) ? req.body.emergencyContacts.map(contact => ({
        name: contact.name,
        relationship: contact.relationship,
        phone: contact.phone,
        email: contact.email
      })) : []
    };

    if (req.file) {
      updateData.profilePicture = {
        data: req.file.buffer,
        contentType: req.file.mimetype
      };
    }

    Object.assign(patient, updateData);

    await patient.save();

    res.redirect('/patient/profile');
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});
router.get('/doctors', async (req, res) => {
  try {
    const sortOption = req.query.sort;
    let sortCriteria;

    switch (sortOption) {
      case 'mostReviewed':
        sortCriteria = { consultationsCompleted: -1 };
        break;
      case 'highestRated':
        sortCriteria = { rating: -1 };
        break;
      case 'mostViewed':
        sortCriteria = { profileViews: -1 };
        break;
      default:
        sortCriteria = {};
    }

    const doctors = await Doctor.find({ verified: 'Verified' })
      .populate({
        path: 'hospitals',
        select: 'name city -_id' 
      })
      .sort(sortCriteria);

    const countries = await Doctor.distinct('country');
    const states = await Doctor.distinct('state');
    const cities = await Doctor.distinct('city');
    const specialities = await Doctor.distinct('speciality');
    const languages = await Doctor.distinct('languages');
    const genders = await Doctor.distinct('gender');

    res.render('patientDoctors', {
      doctors,
      countries,
      states,
      cities,
      specialities,
      languages,
      genders
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});
router.get('/doctors/:id/slots', isLoggedIn, async (req, res) => {
  try {
      const doctorId = req.params.id;
      const doctor = await Doctor.findById(doctorId)
          .populate({
              path: 'reviews.patientId',
              select: 'name'
          });

      if (!doctor) {
          return res.status(404).send('Doctor not found');
      }

      const insurances = await Insurance.find({ '_id': { $in: doctor.insurances } }).select('name logo');
      const blogs = await Blog.find({ authorId: doctorId, verificationStatus: 'Verified' });

      if (req.accepts('html')) {
          res.render('doctorProfileView', { doctor, insurances, blogs });
      } else if (req.accepts('json')) {
          res.json({ doctor, insurances, blogs });
      } else {
          res.status(406).send('Not Acceptable');
      }
  } catch (error) {
      console.error(error.message);
 if (req.accepts('json')) {
          res.status(500).json({ error: 'Server Error' });
      } else {
          res.status(406).send('Not Acceptable');
      }
  }
});

router.post('/book', isLoggedIn, async (req, res) => {
  try {
      const { doctorId, date, startTime, consultationType } = req.body;
      const patientId = req.session.user._id;

   
      console.log('Request body:', req.body);
      console.log('Patient ID:', patientId);

      const doctor = await Doctor.findById(doctorId);
      if (!doctor) {
          return res.status(404).json({ error: 'Doctor not found' });
      }

 

      const requestDateString = new Date(date).toDateString();

      const slot = doctor.timeSlots.find(slot =>
          new Date(slot.date).toDateString() === requestDateString && slot.startTime === startTime
      );

      if (!slot) {
          return res.status(400).json({ error: 'Time slot not found' });
      }

      const booking = new Booking({
          patient: patientId,
          doctor: doctorId,
          date: new Date(date),
          time: `${slot.startTime} - ${slot.endTime}`,
          consultationType: consultationType,
          status: 'waiting',
          hospital: {
              name: slot.hospital,
              location: slot.hospitalLocation
          }
      });
      console.log('Booking data to save:', booking);
      await booking.save();

      slot.status = 'booked';
      await doctor.save();

      res.status(200).json({ message: 'Booking successful' });
  } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Server error' });
  }
});


router.get('/bookings', isLoggedIn, async (req, res) => {
  try {
    const bookings = await Booking.find({ patient: req.session.user._id }).populate('doctor');
    res.json({ bookings });
    console.log({bookings});
    
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Server Error' });
  }
});


router.get('/review/:doctorId/:bookingId', isLoggedIn, async (req, res) => {
  try {
    const doctor = await Doctor.findById(req.params.doctorId);
    const booking = await Booking.findById(req.params.bookingId);

    if (!doctor || !booking) {
      return res.status(404).send('Doctor or booking not found');
    }

    res.render('reviewForm', { doctor, booking });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});

router.post('/review/:doctorId/:bookingId', isLoggedIn, async (req, res) => {
  try {
    const { rating, reviewText } = req.body;

    const doctor = await Doctor.findById(req.params.doctorId);
    const booking = await Booking.findById(req.params.bookingId);

    if (!doctor || !booking) {
      return res.status(404).send('Doctor or booking not found');
    }

    doctor.reviews.push({
      patientId: req.session.user._id,
      rating,
      reviewText
    });

    await doctor.save();

    res.redirect('/patient/bookings'); 
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});

router.post('/add-to-favorites', isLoggedIn, async (req, res) => {
  try {
    const { doctorId } = req.body;
    const patientId = req.session.user._id;

    const patient = await Patient.findById(patientId);
    const doctor = await Doctor.findById(doctorId);

    if (!patient || !doctor) {
      return res.status(404).send('Patient or Doctor not found');
    }

    if (!patient.favoriteDoctors) {
      patient.favoriteDoctors = []; 
    }

    if (patient.favoriteDoctors.includes(doctorId)) {
      return res.status(400).send('Doctor already in favorites');
    }

    patient.favoriteDoctors.push(doctorId);
    await patient.save();

    res.redirect('/patient/doctors'); 
  } catch (error) {
    console.error('Error adding to favorites:', error);
    res.status(500).send('Server error');
  }
});


router.get('/favorites', isLoggedIn, async (req, res) => {
  try {
    const patientId = req.session.user._id;
    const patient = await Patient.findById(patientId).populate({
      path: 'favoriteDoctors',
      model: 'Doctor'
    });

    if (!patient) {
      return res.status(404).send('Patient not found');
    }

    res.render('patientFavorites', { favoriteDoctors: patient.favoriteDoctors });
  } catch (error) {
    console.error('Error fetching favorite doctors:', error);
    res.status(500).send('Server error');
  }
});


router.get('/calendar', isLoggedIn, async (req, res) => {
  try {
      const patientId = req.session.user._id; 
      const patient = await Patient.findById(patientId);
      if (!patient) {
          return res.status(404).send('Patient not found');
      }

      const currentDate = new Date();
      let currentMonth = parseInt(req.query.month) || currentDate.getMonth();
      let currentYear = parseInt(req.query.year) || currentDate.getFullYear();

      if (currentMonth < 0 || currentMonth > 11) {
          currentMonth = currentDate.getMonth();
      }
      if (currentYear < 1900 || currentYear > 2100) {
          currentYear = currentDate.getFullYear();
      }

      const daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();

      const bookings = await Booking.find({
          patient: patientId,
          date: {
              $gte: new Date(currentYear, currentMonth, 1),
              $lte: new Date(currentYear, currentMonth, daysInMonth, 23, 59, 59)
          },
          status: 'accepted'
      });

      res.render('patientCalendar', {
          patient,
          currentMonth,
          currentYear,
          daysInMonth,
          bookings,
          today: currentDate,
          months: [
              'January', 'February', 'March', 'April', 'May', 'June',
              'July', 'August', 'September', 'October', 'November', 'December'
          ]
      });
  } catch (error) {
      console.error('Error fetching calendar data:', error);
      res.status(500).send('Server error');
  }
});

router.get('/blogs/view/:id', isLoggedIn, async (req, res) => {
  try {
      const blogId = req.params.id;
      const blog = await Blog.findById(blogId).lean();

      if (!blog) {
          return res.status(404).send('Blog not found');
      }

      res.render('PatientViewBlog', { blog });
  } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
  }
});



router.post('/blogs/comment/:id', isLoggedIn, async (req, res) => {
  try {
      const { comment } = req.body;
      const blogId = req.params.id;
      const blog = await Blog.findById(blogId);

      if (!blog) {
          return res.status(404).send('Blog not found');
      }
      console.log(req.session.user.name)
      blog.comments.push({
          username: req.session.user.name, 
          comment: comment
      });

      await blog.save();

      req.flash('success_msg', 'Comment added successfully');
      res.redirect(`/patient/blogs/view/${blogId}`);
  } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
  }
});

router.get('/author/:id', async (req, res) => {
  try {
    const authorId = req.params.id;

    let author = await Doctor.findById(authorId);

    if (!author) {
      author = await Admin.findById(authorId);
    }

    if (!author) {
      return res.status(404).send('Author not found');
    }

    const blogCount = await Blog.countDocuments({ authorId });

    res.render('author-info', {
      author,
      blogCount
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});
router.get('/priority-blogs', async (req, res) => {
    try {
      const blogs = await Blog.find({ priority: 'high', verificationStatus: 'Verified' }).lean();

      res.render('priorityblogs', { blogs });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  });

router.get('/blogs', async (req, res) => {
  try {
    let filter = { verificationStatus: 'Verified' }; 

    if (req.query.search) {
      const regex = new RegExp(escapeRegex(req.query.search), 'gi'); 

      filter = {
        verificationStatus: 'Verified',
        $or: [
          { title: regex },
          { categories: regex },
          { hashtags: regex }
        ]
      };
    }

    const verifiedBlogs = await Blog.find(filter).lean();

    res.render('blogs', { blogs: verifiedBlogs, searchQuery: req.query.search });

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

function escapeRegex(text) {
  return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
}

router.get('/dashboard', isLoggedIn, async (req, res) => {
  try {
    const patient = await Patient.findOne({ email: req.user.email }).lean();
    if (!patient) {
      return res.status(404).send('Patient not found');
    }

    const chats = await Chat.find({ patientId: patient._id })
      .populate('doctorId', 'name')
      .sort({ updatedAt: -1 })
      .lean();

    chats.forEach(chat => {
      chat.unreadCount = chat.messages.filter(message => 
        !message.read && message.senderId.toString() !== patient._id.toString()
      ).length;
    });

    return res.json({ patient, chats });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: 'Server Error' });
  }
});
router.get('/chat/:id', isLoggedIn, async (req, res) => {
  try {
    const chatId = req.params.id;
    const chat = await Chat.findById(chatId).populate('doctorId').lean();

    if (!chat) {
      return res.status(404).send('Chat not found');
    }

    chat.messages.forEach(message => {
      if (message.senderId.toString() !== req.user._id.toString() && !message.read) {
        message.read = true;
      }
    });

    await Chat.updateOne({ _id: chatId }, { $set: { messages: chat.messages } });
    
    res.json({ chat });
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: 'Server Error' });
  }
});

router.post('/chats/:chatId/send-message', isLoggedIn, async (req, res) => {
  try {
    const { message } = req.body;
    const patient = await Patient.findOne({ email: req.session.user.email });
    const chatId = req.params.chatId;

    if (!patient) {
      return res.status(404).send('Patient not found');
    }

    let chat = await Chat.findOneAndUpdate(
      { _id: chatId, patientId: patient._id },
      { $push: { messages: { senderId: patient._id, text: message, timestamp: new Date(), read: false } } },
      { new: true }
    ).populate('doctorId');

    if (chat.doctorId) {
      await Notification.create({
        userId: chat.doctorId._id,
        message: `New message from ${patient.name}`,
        type: 'chat',
        read: false,
        createdAt: new Date()
      });
    }

    res.json({ chat });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ error: 'Server Error' });
  }
});

router.get('/prescriptions', isLoggedIn, async (req, res) => {
  try {
    const patientId = req.session.user._id;
    const patientPrescriptions = await Prescription.find({ patientId: patientId })
      .sort({ createdAt: 'desc' });

    res.json(patientPrescriptions); // Send the data as JSON
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});


const fontPaths = {
  regular: path.join(__dirname, '../fonts/Matter-Regular.ttf'),
  bold: path.join(__dirname, '../fonts/Matter-Bold.ttf'),
  italic: path.join(__dirname, '../fonts/Matter-RegularItalic.ttf'),
  boldItalic: path.join(__dirname, '../fonts/Matter-BoldItalic.ttf'),
  semiBold: path.join(__dirname, '../fonts/Matter-SemiBold.ttf'),
  medium: path.join(__dirname, '../fonts/Matter-Medium.ttf')
};

router.get('/prescriptions/:id/download', isLoggedIn, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id)
      .populate('doctorId', 'name speciality')
      .exec();

    if (!prescription) {
      return res.status(404).send('Prescription not found');
    }

    const doctor = prescription.doctorId;
    const booking = await Booking.findOne({
      patient: prescription.patientId,
      doctor: prescription.doctorId
    });

    if (!booking) {
      return res.status(404).send('Booking not found');
    }

    const hospital = booking.hospital;
    const doc = new PDFDocument({ margin: 40 });
    const fileName = `prescription-${prescription._id}.pdf`;
    const prescriptionsDir = path.join(__dirname, '../public/prescriptions');

    if (!fs.existsSync(prescriptionsDir)) {
      fs.mkdirSync(prescriptionsDir, { recursive: true });
    }

    const filePath = path.join(prescriptionsDir, fileName);

    doc.registerFont('Matter-Regular', fontPaths.regular);
    doc.registerFont('Matter-Bold', fontPaths.bold);
    doc.registerFont('Matter-Italic', fontPaths.italic);
    doc.registerFont('Matter-BoldItalic', fontPaths.boldItalic);
    doc.registerFont('Matter-SemiBold', fontPaths.semiBold);
    doc.registerFont('Matter-Medium', fontPaths.medium);

    doc.info.Title = 'E-Prescription';
    doc.info.Author = 'MedxBay';

    const backgroundColor = '#F4F7FC';
    const textColor = '#272848';
    const lineColor = '#b0baca'; 

    const addHeaderFooter = () => {
      doc.rect(0, 0, doc.page.width, doc.page.height).fill(backgroundColor);

      const logoX = 40;
      const titleX = 45;
      const doctorInfoX = 400;
      const headerY = 40;
      const watermarkX = (doc.page.width - 225) / 2;
      const watermarkY = (doc.page.height - 115) / 2;

      doc.opacity(0.08).image('logo.png', watermarkX, watermarkY, { width: 220 }).opacity(1);

      doc.image('logo.png', logoX, headerY, { width: 115 })
        .font('Matter-Medium')
        .fontSize(18)
        .fillColor(textColor)
        .text('E-Prescription', titleX, headerY, { align: 'center' })
        .fontSize(10)
        .font('Matter-Regular')
        .text('MedxBay', titleX, headerY + 19, { align: 'center' })
        .font('Matter-Italic')
        .fontSize(10)
        .text('Your Trusted Health Partner', titleX, headerY + 31, { align: 'center' })
        .moveDown(1.5);

      doc.font('Matter-SemiBold').fontSize(12).fillColor(textColor)
        .text(` ${doctor.name}`, doctorInfoX, headerY, { align: 'right' })
        .font('Matter-Regular')
        .text(`${doctor.speciality.join(', ')}`, doctorInfoX, headerY + 15, { align: 'right' })
        .font('Matter-Italic')
        .text(`${prescription.doctorEmail}`, doctorInfoX, headerY + 30, { align: 'right' })
        .moveDown(2);

        doc.fillColor(lineColor).moveTo(40, headerY + 60).lineTo(570, headerY + 60).stroke(lineColor);
    };

    addHeaderFooter();

    const patientName = `Patient Name: ${prescription.patientName}`;
    const patientAge = `Patient Age: ${prescription.patientAge}`;
    const consultationDate = `Consultation Date: ${prescription.meetingDate.toISOString().split('T')[0]}`;
    const consultationTime = `Consultation Time: ${prescription.meetingTime}`;

    doc.font('Matter-Regular').fontSize(12).fillColor(textColor)
      .text(patientName, 40)
      .moveDown(0.5)
      .text(patientAge)
      .moveDown(0.5)
      .text(consultationDate)
      .moveDown(0.5)
      .text(consultationTime)
      .moveDown(1.5);

    doc.fontSize(14).font('Matter-Medium').fillColor(textColor)
      .text('Medicines', { underline: true })
      .moveDown()
      .font('Matter-Regular').fontSize(12);

    const medicineLineSpacing = 0.5;
    let medicineCount = 0;

    prescription.medicines.forEach((medicine) => {
      if (medicineCount >= 4 || (doc.y + 60 > doc.page.height - 100)) {
        doc.addPage();
        addHeaderFooter();
        medicineCount = 0;
      }

      doc.font('Matter-SemiBold').fillColor(textColor)
        .text(`• Name: ${medicine.name}`)
        .moveDown(medicineLineSpacing)
        .font('Matter-Regular')
        .text(`  - Dosage: ${medicine.dosage}`)
        .moveDown(medicineLineSpacing)
        .text(`  - Before Food: ${medicine.beforeFood ? 'Yes' : 'No'}`)
        .moveDown(medicineLineSpacing)
        .text(`  - After Food: ${medicine.afterFood ? 'Yes' : 'No'}`)
        .moveDown(medicineLineSpacing)
        .text(`  - Timing: Morning: ${medicine.timing.morning ? 'Yes' : 'No'}, Afternoon: ${medicine.timing.afternoon ? 'Yes' : 'No'}, Night: ${medicine.timing.night ? 'Yes' : 'No'}`)
        .moveDown(1);

      medicineCount++;
    });

    doc.moveDown(2).font('Matter-SemiBold').fillColor(textColor)
      .text('Doctor\'s Signature')  
      .moveDown(0.4)
      .font('Matter-Italic')
      .text(doctor.name, { fontSize: 14 }); 

      const footerY = doc.page.height - 90; 

      doc.moveTo(40, footerY).lineTo(570, footerY).stroke();

    doc.y = footerY + 10;
    doc.moveDown(0.5).font('Matter-Medium').fontSize(12).fillColor(textColor)
      .text(hospital.name, { align: 'center' })
      .moveDown(0.4)
      .font('Matter-Italic').fontSize(10)
      .text(
        `${hospital.location.street}, ${hospital.location.city}, ${hospital.location.state}, ${hospital.location.country} - ${hospital.location.zip}`,
        { align: 'center' }
      );

    doc.pipe(fs.createWriteStream(filePath)).on('finish', () => {
      res.setHeader('Content-disposition', 'attachment; filename=' + fileName);
      res.setHeader('Content-type', 'application/pdf');
      fs.createReadStream(filePath).pipe(res);
    });

    doc.end();
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});

router.get('/notifications', isLoggedIn, async (req, res) => {
  try {
      const notifications = await Notification.find({ userId: req.user._id }).lean();
      res.render('patientNotifications', { notifications });
  } catch (error) {
      console.error(error);
      res.status(500).send('Server Error');
  }
  });
  
router.post('/notifications/:id/mark-read', isLoggedIn, async (req, res) => {
    try {
        await Notification.findByIdAndUpdate(req.params.id, { read: true });
        res.redirect('/patient/notifications');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});
  
  
router.post('/notifications/:id/delete', isLoggedIn, async (req, res) => {
    try {
        await Notification.findByIdAndDelete(req.params.id);
        res.redirect('/patient/notifications');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});

module.exports = router;