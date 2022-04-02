const express = require('express');
const bodyParser = require('body-parser');
const fileUpload = require('express-fileupload');
const mongoose = require('mongoose');
const nunjucks = require('nunjucks');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const emailvalidator = require('email-validator');
const session = require('express-session');
const MongodbSession = require('connect-mongodb-session')(session);


const User = require("./models/user");
const Projects = require("./models/projects");

require('dotenv').config();


const JWT_SECRETE = process.env.JWT_SECRETE;

const app = express();


app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(fileUpload());
nunjucks.configure("views", { autoescape: true, express: app });


const { type } = require('os');

const port = process.env.PORT || 4000;
const localURL = "mongodb://localhost:27017/findyourproject";

mongoose.connect(localURL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
mongoose.connection.on('connected', (err) => {
    if(err) {
        console.log(err.kind);
    } else {
        console.log('Connected to MongoDB');
    }
});

const store = new MongodbSession({
  uri: localURL,
  collection: "sessions",
});

app.use(
  session({
    secret: process.env.secret,
    resave: false,
    saveUninitialized: false,
    store:store
  })
);

const isAuth = (req, res, next) => {
  if (req.session.isAuth) {
    next();
  } else {
    res.redirect("/login");
  }
}


app.get("/", (req, res) => {
    res.render("main.html");
})


app.get("/profile",isAuth, (req, res) => {

    console.log(req.session.userid) 
    res.render("profile.html");
})

app.get("/login", (req, res) => {
  if (req.session.isAuth) {
      res.redirect("/profile");
  } else {
     res.render("login.html");
  }
 
});

app.get("/register", (req, res) => {
  if (req.session.isAuth) {
    res.redirect("/profile");
  } else {
    res.render("signup.html");
  }
    
});


app.post("/register", async (req, res) => {
    const { username,email, password: pw } = req.body;
  if (!emailvalidator.validate(email)) {
    return res.send({status:'error', msg: 'Invalid email'});
  }
    if (typeof username !== 'string' || typeof pw !== 'string') {
        return res.send("invalid username or password");
     }
    const password = await bcrypt.hash(pw, 10);
    try {
        const response = await User.create({
          username,
          email,
          password
        });
        return res.send({ status: "success", msg: "Account created successfully","url": "/login" });
        
    } catch (err) {
      console.log(err);
        if (err.code === 11000) {
            return res.send({ status: "error", msg: "Username already taken" });
        } else {
            return res.send({ status: "error", msg: "Error saving account details" });
        }
    }
})


app.post("/login", async (req, res) => {

    const user = await User.findOne({ username: req.body.username });
    if (!user) {
         return res.json({ status: "error", msg: "Invalid username/password" });
    }
    const isValid = await bcrypt.compare(req.body.password, user.password); 
    if (!isValid) {
        return res.json({ status: "error", msg: "Invalid password" });
    }
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRETE);
  req.session.isAuth = true;  
  req.session.userid = user.username;
    res.json({ status: "success",msg:"login successful",url:'/profile', token});
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.log(err);
    } else {
      res.redirect('/login');
    }
  });
})

app.post("/addproject", async (req, res) => {
  if (req.session.isAuth) {
    const { name, description, link } = req.body;
    var username = req.session.userid;
    try {
      const project = await Projects.create({
      username,
      name,
      description,
      link
      });
      return res.send({ status: "success", msg: "Project added successfully" });
    } catch (err) {
      return res.send({ status: "error", msg: "Error saving project details" });
    }
  } else {
    return res.redirect("/login");
  }
})


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});