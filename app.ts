import express, { NextFunction, Request, Response } from "express";
import "express-async-errors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import passport from "passport";
import passportJWT from "passport-jwt";
import cookieParser from "cookie-parser";
import multer from "multer";
import { WebSocketServer } from 'ws';
import http from "http";
import path from "path";
import db from "./db";

const { Strategy, ExtractJwt } = passportJWT;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, "public"));
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
})
const upload = multer({ storage });

dotenv.config();

const app = express();
const server = http.createServer(app);

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

passport.use(new Strategy({
    jwtFromRequest: ExtractJwt.fromExtractors([req => req.cookies.token]),
    secretOrKey: process.env.JWT_SECRET!
}, async function (payload, done) {
    const user = await db.user.findUnique({
        where: {
            id: payload.id
        }
    });
    if (!user) {
        return done(null, false);
    }
    return done(null, user);
}));

function isLoggedIn(req: Request, res: Response, next: NextFunction) {
    passport.authenticate("jwt", { session: false, failureRedirect: "/login" })(req, res, next);
}

app.get("/", isLoggedIn, function (req, res) {
    res.render("index", { title: "Home Page", auth: req.user ? true : false });
});

app.get("/login", function (req, res) {
    res.render("login", { title: "Login Page", auth: req.user ? true : false, error: null });
});

app.get("/logout", function (req, res) {
    res.clearCookie("token");
    res.redirect("/");
});

/* app.post("/register", async function (req, res) {
    const { email, password } = req.body;
    if (!email || !password) {
        res.send("Email and Password are required");
        return;
    }

    const userExists = await db.user.findUnique({
        where: {
            email
        }
    });
    if (userExists) {
        res.send("User already exists");
        return;
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await db.user.create({
        data: {
            email,
            password: hashedPassword
        }
    });
    res.send("User created successfully");
}); */

app.post("/login", async function (req, res) {
    const { email, password } = req.body;
    if (!email || !password) {
        res.render("login", { title: "Login Page", auth: req.user ? true : false, error: "Email and Password are required" });
        return;
    }

    const user = await db.user.findUnique({
        where: {
            email
        }
    });
    if (!user) {
        res.render("login", { title: "Login Page", auth: req.user ? true : false, error: "User does not exist" });
        return;
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        res.render("login", { title: "Login Page", auth: req.user ? true : false, error: "Invalid Password" });
        return;
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET!);
    res.cookie('token', token, { httpOnly: true, expires: new Date(Date.now() + 1000 * 60 * 60 * 24) });
    res.redirect("/");
});

app.get("/register-user", isLoggedIn, async function (req, res) {
    const fingerprint = await db.registeredFingerprint.findMany({
        where: {
            user: { isSet: false }
        }
    });
    res.render("registerUser", { title: "Register User", auth: true, error: null, fingerprint });
});

app.post("/register-user", isLoggedIn, upload.single("picture"), async function (req, res) {
    const user = await db.registeredFingerprint.findUnique({
        where: {
            fingerprint: req.body.fingerprintId
        }
    });
    if (!user) {
        res.render("registerUser", { title: "Register User", auth: true, error: "Fingerprint ID does not exist", fingerprint: null });
        return;
    }
    await db.registeredFingerprint.update({
        where: {id: user.id},
        data: {
            user: {
                name: req.body.name,
                id: req.body.personnelNumber,
                phone: req.body.phone,
                DOB: new Date(req.body.dob),
                nextOfKins: req.body.nextOfKins,
                address: req.body.address,
                photo: req.file?.filename!
            }
        }
    })
    res.redirect("/register-user");
});

app.get("/search", isLoggedIn, async function (req, res) {
    let result = null;
    if (req.query.fingerprintId) {
        result = await db.registeredFingerprint.findUnique({
            where: {
                fingerprint: req.query.fingerprintId as string
            }
        });
    }
    res.render("search", { title: "Search", auth: true, error: null, result });
});

app.delete("/delete/:id", isLoggedIn, async function (req, res) {
    await db.registeredFingerprint.delete({
        where: {
            id: req.params.id as string
        }
    });
    res.json({
        success: true,
    });
});

const wss = new WebSocketServer({ server });

wss.on("connection", function(ws) {
    ws.on("message", async function(data) {
        const id = data.toString();

        const idExists = await db.registeredFingerprint.findUnique({
            where: {
                fingerprint: id
            }
        });
        if (idExists) {
            ws.send("Already registered");
            return;
        }
        await db.registeredFingerprint.create({
            data: {
                fingerprint: id
            }
        });
        ws.send("Registered successfully");
    })
});

// app.use(errorLogger);
// app.use(errorResponder);
// app.use(invalidPathHandler);

server.listen(process.env.PORT || 3000, () => {
    console.log("Server is running on port 3000");
});