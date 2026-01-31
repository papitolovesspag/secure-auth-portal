import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import flash from "connect-flash";
import connectPg from "connect-pg-simple"; // <--- NEW
const PostgresqlStore = connectPg(session); // <--- NEW

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(flash()); // <--- ACTIVATE FLASH MESSAGES

app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
  // This makes 'user' available to ALL EJS files automatically
  res.locals.user = req.user; 
  next();
});

// --- DATABASE CONNECTION ---
let db;
if (process.env.DATABASE_URL) {
  // PRODUCTION (Render)
  db = new pg.Pool({ // <--- CHANGED FROM Client TO Pool
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
} else {
  // LOCAL (Your Laptop)
  db = new pg.Pool({ // <--- CHANGED FROM Client TO Pool
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  });
}
// db.connect(); <--- DELETE THIS LINE (Pools connect automatically)

app.use(
  session({
    // Tell it to store sessions in our Postgres DB
    store: new PostgresqlStore({
      pool: db, // Connects to our new pg.Pool
      createTableIfMissing: true // Automatically creates the "session" table
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Changed to false (Best practice for login systems)
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 // 1 Day
    }
  })
);

// --- ROUTES ---

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  // Pass any error messages to the view
  res.render("login.ejs", { error: req.flash("error") });
});

app.get("/register", (req, res) => {
  // Pass any error messages to the view
  res.render("register.ejs", { error: req.flash("error") });
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT secret FROM users WHERE email = $1", [
        req.user.email
      ]);
      const secret = result.rows[0]?.secret; // Safe navigation
      
      res.render("secrets.ejs", { 
        user: req.user, 
        secret: secret 
      });
    } catch (err) {
      console.log(err);
      res.redirect("/login");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs", { user: req.user });
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;
  if (!submittedSecret) return res.redirect("/secrets");
  
  try {
    await db.query("UPDATE users SET secret = $1 WHERE email = $2", [
      submittedSecret,
      req.user.email,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
    res.redirect("/secrets");
  }
});

// --- AUTHENTICATION ROUTES ---

app.get("/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
    failureFlash: true // <--- Enable flash for Google errors too
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
    failureFlash: true, // <--- This tells Passport to flash "Incorrect password"
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      // User exists: Send them to login with a message
      req.flash("error", "Email already registered. Please log in.");
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.redirect("/register");
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
    req.flash("error", "Registration failed. Try again.");
    res.redirect("/register");
  }
});

// --- PASSPORT STRATEGIES ---

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              // Pass 'false' and a message for invalid password
              return cb(null, false, { message: "Incorrect password" }); 
            }
          }
        });
      } else {
        // Pass 'false' and a message for user not found
        return cb(null, false, { message: "User not found" });
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      // DYNAMIC CALLBACK URL
      callbackURL: process.env.NODE_ENV === "production" 
        ? "https://secure-auth-portal.onrender.com/auth/google/secrets" // We will get this URL soon
        : "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});