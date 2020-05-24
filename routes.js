const express = require('express')
const mongoose = require('mongoose')
const bodyparser = require('body-parser')
const bcrypt = require('bcryptjs')
const user = require('./model.js')
const passport = require('passport')
const session = require('express-session');
const cookieParser  = require('cookie-parser')
const flash = require('connect-flash')

const routes = express.Router()


routes.use(cookieParser('secret'))
routes.use(session({
    secret : 'secret',
    maxAge : 3600000,
    resave : true,
    saveUninitialized : true
}))

routes.use(flash())
//Global varriable 

routes.use(function(req, res, next){
    res.locals.success_message = req.flash('success_message')
    res.locals.error_message = req.flash('error_message')
    res.locals.error = req.flash('error')
    next();
})


const checkAuthenticeted = function(req, res, next){
    if(req.isAuthenticated()){
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0')
        return next();
    }else{
        res.redirect('/login')
    }
}

routes.use(bodyparser.urlencoded({extended : true}))
routes.use(passport.initialize())
routes.use(passport.session())

mongoose.connect('mongodb+srv://root:root@cluster0-c0wuh.mongodb.net/userDB?retryWrites=true&w=majority', {
    useNewUrlParser : true, useUnifiedTopology : true
}).then(()=> console.log('database connected')
);


routes.get('/', (req, res)=>{
    res.render('register')
})

routes.post('/register', (req, res)=>{
    const { email, username, password, confirmpassword } = req.body

    let err;
    if(!email || !username || !password || !confirmpassword){
        err = "please fill up the field"
        res.render('register', { 'err' : err })
    }

    if(password != confirmpassword){
        err = "Password Doesn't Match"
        res.render('register', {'err' : err, 'email': email, 'username': username})
    }
    if(typeof err == 'undefined'){
        user.findOne( { email : email }, function(err, data){
            if(err) throw err;
            if(data){
                console.log('email already exist');
                err = "Password Doesn't Match"
                res.render('register', {'err' : err, 'email': email, 'username': username})
            } else {
                bcrypt.genSalt(10, (err, salt) =>{
                    if(err) throw err;
                    bcrypt.hash(password, salt, (err, hash)=>{
                        if(err) throw err;                
                        const password = hash;
                        user({
                            email,
                            username,
                            password,
                        }).save((err, data)=>{
                            if(err) throw err;
                            req.flash('success_message', "Registered Successfully....Login to continue")
                            res.redirect('/login')
                        })
                    })
                })
            }
        })
    } 
})


// authentication

var LocalStrategy = require('passport-local').Strategy
passport.use(new LocalStrategy({usernameField : 'email'}, (email, password, done)=> {
    user.findOne( {email : email }, (err, data)=>{
        if(err) throw err;
        if(!data){
            return done(null, false, {message : "User doesn't exist...."})
        }
        bcrypt.compare(password, data.password, (err, match)=>{
            if(err){
                return done(null, false)
            }
            if(!match){
                return done(null, false, {message : "Password doesn't match"})
            }
            if(match){
                return done(null, data)
            }
        })
    })
}))



passport.serializeUser(function(user, cb){
    cb(null, user.id)
})

passport.deserializeUser(function(id, cb){
    user.findById(id, function(err, user){
        cb(err, user)
    })
})

// user authentication 

routes.get('/login', (req, res)=>{
    res.render('login')
})

routes.post('/login', (req, res, next)=>{
    passport.authenticate('local', {
        failureRedirect : '/login',
        successRedirect : '/success',
        failureFlash : true
    })(req, res, next);
})

routes.get('/success', checkAuthenticeted, (req, res)=>{
    res.render('success', { 'user' : req.user })
})

routes.get('/logout',(req, res)=>{
    req.logout();
    res.redirect('/login')
})

routes.post('/addmsg', checkAuthenticeted, (req, res)=>{
    user.findOneAndUpdate(
        { email : req.user.email },
        { $push : {
            messages : req.body['msg']
        }}, (err, suc) => {
            if(err) throw err;
            if(suc) console.log('Added Succesfully.....');
            
        }
    )
    res.redirect('/success')
})

module.exports = routes