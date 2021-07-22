const express = require('express');
const app = express();

const path = require('path');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');
// there are lot of strategy in passport package for authentication
// like local stratgey(authenticate from db), fb strategry, google etc.. 
const LocalStrategy = require('passport-local').Strategy;

//Requiring user route
const userRoutes = require('./routes/users');

// //Requiring user model
const User = require('./models/usermodel');

dotenv.config({path : './config.env'});

mongoose.connect(process.env.DATABASE_LOCAL, {
    useNewUrlParser : true,
    useUnifiedTopology : true,
    useCreateIndex : true
});

//middleware for session
app.use(session({
    secret : 'Just a simple login/sign up application.',
    resave : true,
    saveUninitialized : true
}));

app.use(passport.initialize());
app.use(passport.session());  
passport.use(new LocalStrategy({usernameField : 'email'}, User.authenticate()));
// serializeUser and deserializeUser is uded to give access to user based on session mainded 
// by express. 
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


//middleware flash messages
app.use(flash());

//setting middlware globally
app.use((req, res, next)=> {
    res.locals.success_msg = req.flash(('success_msg'));
    res.locals.error_msg = req.flash(('error_msg'));
    res.locals.error = req.flash(('error'));
    res.locals.currentUser = req.user;
    next();
});

app.use(bodyParser.urlencoded({extended:true}));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static('public'));

app.use(userRoutes);

app.listen(process.env.PORT, ()=> {
    console.log('Server is started');
});  





/*

When you fresh start terminal , no need to install these packages at all .
these are the req packages 
npm init -y
npm i express path body-parser dotenv connect-flash mongoose express-session passport passport-local nodemailer async crypto -sve
npm i ejs--sve


*/


