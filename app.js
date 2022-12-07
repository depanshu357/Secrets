//jshint esversion:6
require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser')
const ejs = require('ejs')
const app = express()
const mongoose = require('mongoose');
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')
// const md5 = require('md5')
// const encrypt  = require('mongoose-encryption')
// const bcrypt = require('bcrypt')
// saltRounds = 10

app.use(session({
    secret: "SomeSecret",
    resave: false,
    saveUninitialized: false,
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://localhost:27017/UserDB");

// console.log(process.env)

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret:String,
})

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

// var encKey = "kuchtohhai";
// var sigKey = "bahutkuchhai";
// const secretKey=process.env.SECRETKEY
// userSchema.plugin(encrypt, {secret:secretKey ,encryptedFields:['password']});
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username, name: user.name });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile)
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'displayName', 'photos', 'email']
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile)   
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.use(express.static("public"));
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/", function (req, res) {
    res.render("home")
})
app.get("/login", function (req, res) {
    res.render("login")
})

app.post("/login", function (req, res) {
    const user = req.body.username;
    const password = req.body.password;
    const userData = new User({
        username: user,
        password: password
    })
    req.login(userData, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function (err, user) {
                if (err) console.log(err)
                else {
                    res.redirect("/secrets");
                }
            })
        }
    })
})
// User.findOne({ email: user }, function (err, foundUser) {
//     if (!err) {
//         if (foundUser) {
//             bcrypt.compare(password, foundUser.password, function (err, result) {
//                 if (result == true) {
//                     res.render("secrets")
//                 } else {
//                     res.send("Password does not match")
//                 }
//             });
//         } else {
//             res.send("No user found")
//         }
//     }
// })

app.get("/register", function (req, res) {
    res.render("register")
})

app.post("/register", function (req, res) {
    const email = req.body.username;
    // const password = md5(req.body.password);
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    })
})

app.get("/secrets", function (req, res) {
    // if (req.isAuthenticated()) {
    //     res.render("secrets");
    // } else {
    //     res.redirect("/login")
    // }
    User.find({secret:{$ne:null}},function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                res.render("secrets",{foundUser:foundUser});
            }else{
                res.send("NO secrets yet!");
            }
        }
    })
})

app.get("/submit",function(req,res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login")
    }
})

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;
    console.log(req.user)
    User.findById(req.user.id,function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                })
            }
        }
    })
})

app.get("/logout", function (req, res, next) {
    req.logout(function (err) {
        if (err) console.log(err);
        else {
            res.redirect("/")   
        }
    });
})

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get('/auth/facebook',
    passport.authenticate(('facebook'),{scope:["user_friends"]}));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

// bcrypt.hash(req.body.password, saltRounds, function (err1, hash) {
//     if (!err1) {

//         const newUser = new User({
//             email: email,
//             password: hash
//         })
//         newUser.save(function (err) {
//             if (err) {
//                 console.log(err)
//             } else {
//                 res.render("secrets")
//             }
//         })
//     }
// })


app.listen(3000, function () {
    console.log("Successfully started port on 3000");
})