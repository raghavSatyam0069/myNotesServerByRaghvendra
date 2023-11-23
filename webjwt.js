let express = require("express");
const cors = require("cors");
const { hashSync, compareSync } = require("bcrypt");
let passport = require("passport");
let JWTStrategy = require("passport-jwt").Strategy;
let ExtractJWT = require("passport-jwt").ExtractJwt;
let app = express();
app.use(express.json());
app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS, PUT, PATCH, DELETE, HEAD"
  );
  res.header("Access-Control-Expose-Headers", "X-Auth-Token");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept,Authorization"
  );
  next();
});
var port = process.env.port || 2410;
app.listen(port, () => console.log(`Listening on port ${port}!`));
let { userData } = require("./empCookieTask-5_2_Data.js");

app.use(
  cors({
    credentials: true,
    origin: true,
  })
);
const { MongoClient } = require("mongodb");
let { ObjectId } = require("mongodb");
const url =
  "mongodb+srv://RaghavSatyam0069:Raghav@cluster0.9sxrc2a.mongodb.net/?retryWrites=true&w=majority";
const dbName = "notes";
const client = new MongoClient(url);

async function getData() {
  let result = await client.connect();
  let db = result.db(dbName);
  let collection = db.collection("notesUser");
  let response = await collection.find().toArray();
  console.log(response);
}
// getData();
app.use(passport.initialize());
const params = {
  jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
  secretOrKey: "jwtsecret23568747",
};
const jwtExpirySeconds = 300000;

let strategyAll = new JWTStrategy(params, async function (token, done) {
  console.log("In JWTStrategy", token);
  let result = await client.connect();
  let db = result.db(dbName);
  let collection = db.collection("notesUser");
  let user1 = await collection.findOne({ email: token.email });
  // console.log("user1", user1);
  if (!user1)
    return done(null, false, {
      message: "Incorrect Username or Password",
    });
  else {
    return done(null, user1);
  }
});

passport.use("roleAll", strategyAll);
// passport.use("roleAdmin", strategyAdmin);
const jwt = require("jsonwebtoken");
const jwt_key = "secrectkey234759";
const jwtExpiryTime = 3000;
let cookieName = "jwtToken";

app.post("/login", async function (req, res) {
  let { email, password } = req.body;
  //   console.log(req.body);
  let result = await client.connect();
  let db = result.db(dbName);
  let collection = db.collection("notesUser");

  collection
    .findOne({
      email: email,
    })
    .then((user) => {
      if (!user) {
        return res.status(401).send({
          success: false,
          message: "Could not find the user",
        });
      }
      if (!compareSync(password, user.password)) {
        return res.status(401).send({
          success: false,
          message: "Incorrect Password",
        });
      }

      let payload = { email: user.email };
      let token = jwt.sign(payload, params.secretOrKey, {
        algorithm: "HS256",
        expiresIn: jwtExpiryTime,
      });
      res.setHeader("X-Auth-Token", token);
      // console.log(token);
      res.send(token);
    });
});
app.post("/register", async function (req, res) {
  let { email } = req.body;
  let password = hashSync(req.body.password, 10);
  // console.log("In POST /user", req.user);
  let result = await client.connect();
  let db = result.db(dbName);
  let collection = db.collection("notesUser");
  collection.findOne({ email: email }).then((user) => {
    if (user) {
      res.status(409).send("Email is already existed");
    } else {
      collection
        .insertOne({
          email: email,
          password: password,
        })
        .then((user) => {
          // console.log(user);
        });
      // console.log(response);
      res.send("Registration SuccessFul");
    }
  });
});

app.put(
  "/myNotes/:index",
  passport.authenticate("roleAll", { session: false }),
  async function (req, res) {
    const body = req.body;
    const { index } = req.params;
    // console.log("index", index);
    // console.log("In PUT /user", req.user);
    let result = await client.connect();
    let db = result.db(dbName);
    let collection = db.collection("notesUser");
    collection.findOne({ email: req.user.email }).then((user) => {
      user.notes[index] = body;
      collection.updateOne({ _id: req.user._id }, { $set: user });
      res.send("Notes Modified succesfully");
    });
  }
);
app.delete(
  "/delNote/:index",
  passport.authenticate("roleAll", { session: false }),
  async function (req, res) {
    const { index } = req.params;
    // console.log("index", index);
    // console.log("In PUT /user", req.user);
    let result = await client.connect();
    let db = result.db(dbName);
    let collection = db.collection("notesUser");
    collection.findOne({ email: req.user.email }).then((user) => {
      user.notes.splice(index, 1);
      collection.updateOne({ _id: req.user._id }, { $set: user });
      res.send("Note Deleted Successfully!");
    });
  }
);
app.post(
  "/myNotes",
  passport.authenticate("roleAll", { session: false }),
  async function (req, res) {
    let body = req.body;
    // console.log("In POST Notes", req.user);
    let result = await client.connect();
    let db = result.db(dbName);
    let collection = db.collection("notesUser");

    collection.findOne({ email: req.user.email }).then((user) => {
      if (!user.notes) {
        user.notes = [body];
      } else {
        user.notes.unshift(body);
      }
      collection.updateOne({ _id: req.user._id }, { $set: user });
      res.send("Notes added succesfully");
    });
  }
);

app.get(
  "/myNotes",
  passport.authenticate("roleAll", { session: false }),
  async function (req, res) {
    // console.log("In GET /user", req.user);
    let result = await client.connect();
    let db = result.db(dbName);
    db.collection("notesUser")
      .findOne({ email: req.user.email })
      .then((user) => {
        if (!user.notes) {
          res.send([]);
        } else {
          res.send(user.notes);
        }
      });
  }
);
