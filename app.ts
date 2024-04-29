import express, { NextFunction, Request, Response } from "express";
import "express-async-errors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import passport from "passport";
import passportJWT from "passport-jwt";
import cookieParser from "cookie-parser";
import multer from "multer";
import { v2 as cloudinary, UploadApiResponse } from "cloudinary";
import { v4 as uuidv4 } from "uuid";
import { WebSocketServer } from "ws";
import http from "http";
import path from "path";
import fs from "fs/promises";
import os from "os";
import db from "./db";
import { errorLogger, errorResponder, invalidPathHandler } from "./middlewares/errorHandlers";

const { Strategy, ExtractJwt } = passportJWT;
dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = multer.diskStorage({
    destination: async function (req, file, cb) {
        cb(null, os.tmpdir());
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});
const upload = multer({ storage });

const app = express();
const server = http.createServer(app);

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
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

    const uploadedFile = await cloudinary.uploader.upload(req.file?.path!, {
        allowed_formats: ["jpg", "png"],
        public_id: uuidv4(),
        folder: "fingerprint"
    });
    await db.registeredFingerprint.update({
        where: { id: user.id },
        data: {
            user: {
                name: req.body.name,
                id: req.body.personnelNumber,
                phone: req.body.phone,
                DOB: new Date(req.body.dob),
                nextOfKins: req.body.nextOfKins,
                address: req.body.address,
                photo: uploadedFile.secure_url,
                public_id: uploadedFile.public_id
            }
        }
    });
    await fs.unlink(req.file?.path!);
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
    const user = await db.registeredFingerprint.delete({
        where: {
            id: req.params.id as string
        }
    });
    await cloudinary.uploader.destroy(user.user?.public_id!);
    res.json({
        success: true,
    });
});

app.post("/update/:id", isLoggedIn, upload.single("picture"), async function (req, res) {
    const user = await db.registeredFingerprint.findUnique({
        where: {
            id: req.params.id
        }
    });
    let file: UploadApiResponse | null = null;
    if (req.file) {
        file = await cloudinary.uploader.upload(req.file?.path!, {
            allowed_formats: ["jpg", "png"],
            public_id: user?.user?.public_id,
            folder: "fingerprint"
        });
    }

    await db.registeredFingerprint.update({
        where: { id: req.params.id },
        data: {
            user: {
                name: user?.user?.name!,
                id: user?.user?.id!,
                phone: req.body.phone,
                DOB: new Date(req.body.DOB),
                nextOfKins: req.body.nextOfKins,
                address: req.body.address,
                photo: req.file ? file?.secure_url! : user?.user?.photo!,
                public_id: req.file ? file?.public_id! : user?.user?.public_id!
            }
        }
    });

    res.redirect(`/search?fingerprintId=${user?.fingerprint}`);
});

const wss = new WebSocketServer({ server });

wss.on("connection", function (ws) {
    ws.on("message", async function (data) {
        try {
            const id = data.toString();

            const idExists = await db.registeredFingerprint.findUnique({
                where: {
                    fingerprint: id
                }
            });
            if (idExists) {
                if (!idExists.user) {
                    ws.send("Registered");
                    return;
                }
                ws.send("Already registered");
                return;
            }
            await db.registeredFingerprint.create({
                data: {
                    fingerprint: id
                }
            });
            ws.send("Registered");
        } catch (err) {
            ws.send("Error");
        }
    });
});

app.use(errorLogger);
app.use(errorResponder);
app.use(invalidPathHandler);

server.listen(process.env.PORT || 3000, () => {
    console.log("Server is running on port 3000");
});