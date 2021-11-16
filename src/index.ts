import mongoose from "mongoose";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import passport from "passport";
import passportLocal from "passport-local";
import cookieParser from "cookie-parser";
import session from "express-session";
import bcrypt from "bcryptjs";
import User from "./User";
import dotenv from "dotenv";
import {
  UserInterface,
  DatabaseUserInterface,
} from "./Interfaces/UserInterface";
const LocalStrategy = passportLocal.Strategy;
dotenv.config();
mongoose.connect(
  `${process.env.dbUrl}`,
  {
    useCreateIndex: true,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  (err) => {
    if (err) throw err;
    console.log("Connected To Mongo");
  }
);
// Middleware
const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(
  session({
    secret: "secretcode",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());
// Passport
passport.use(
  new LocalStrategy((username: string, password: string, done) => {
    User.findOne(
      { username: username },
      (err: Error, user: DatabaseUserInterface) => {
        if (err) throw err;
        if (!user) return done(null, false);
        bcrypt.compare(password, user.password, (err, result: boolean) => {
          if (err) throw err;
          if (result === true) {
            return done(null, user);
          } else {
            return done(null, false);
          }
        });
      }
    );
  })
);

passport.serializeUser((user: DatabaseUserInterface, cb) => {
  cb(null, user._id);
});

passport.deserializeUser((id: string, cb) => {
  User.findOne({ _id: id }, (err: Error, user: DatabaseUserInterface) => {
    const userInformation: UserInterface = {
      username: user.username,
      isAdmin: user.isAdmin,
      id: user._id,
    };
    cb(err, userInformation);
  });
});
//Router
app.post(
  "/register",
  async (req: Request, res: Response, next: NextFunction) => {
    //register
    const { username, password } = req?.body;
    if (
      !username ||
      !password ||
      typeof username !== "string" ||
      typeof password !== "string"
    ) {
      res.send("Improper Values");
      return;
    }
    User.findOne(
      { username },
      async (err: Error, doc: DatabaseUserInterface) => {
        if (err) throw err;
        if (doc) res.send("User Already Exists");
        if (!doc) {
          const hashedPassword = await bcrypt.hash(password, 10);
          const newUser = new User({
            username,
            password: hashedPassword,
            isAdmin: true
          });
          await newUser.save();
          res.send("success");
        }
      }
    );
  }
);
app.post("/login", passport.authenticate("local"), (req:Request, res:Response) => {
  res.send("success");
});

app.get("/user", (req:Request, res:Response) => {
  res.send(req.user);
});
app.get("/", (req:Request, res:Response) => {
  res.send("Hello World");
});

app.get("/logout", (req:Request, res:Response) => {
  req.logout();
  res.send("success");
});
const isAdministratorMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { user }: any = req;
  if (user) {
    User.findOne(
      { username: user.username },
      (err: Error, doc: DatabaseUserInterface) => {
        if (err) throw err;
        if (doc?.isAdmin) {
          next();
        } else {
          res.send("Sorry, only admin's can perform this.");
        }
      }
    );
  } else {
    res.send("Sorry, you arent logged in.");
  }
};
app.post("/deleteuser", isAdministratorMiddleware, async (req:Request, res:Response) => {
  try {
    const { id } = req?.body;
    await User.findByIdAndDelete(id);
    res.send("success");
  } catch (err) {
    res.send("error");
  }
});
app.get("/getallusers", isAdministratorMiddleware, async (req:Request, res:Response) => {
  await User.find({}, (err, data: DatabaseUserInterface[]) => {
    if (err) throw err;
    const filteredUsers: UserInterface[] = [];
    data.forEach((item: DatabaseUserInterface) => {
      const userInformation = {
        id: item._id,
        username: item.username,
        isAdmin: item.isAdmin,
      };
      filteredUsers.push(userInformation);
    });
    res.send(filteredUsers);
  });
});
app.listen(8000, () => {
  console.log("Server started on port 8000");
});
