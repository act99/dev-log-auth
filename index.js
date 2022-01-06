require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const { User } = require("./models/User");
const { auth } = require("./middleware/auth");

const app = express();

const { PORT, MONGO_URI } = process.env;

// app.use(express.static("public"));

// application/x-www-form-urlencoded 라는걸 가져올 수 있음
app.use(bodyParser.urlencoded({ extended: true }));
// application/json 을 가져올 수 있게 만듬
app.use(bodyParser.json());
app.use(cookieParser());

// CONNECT TO MONGODB SERVER
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Successfully connected to mongodb"))
  .catch((e) => console.error(e));

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));

app.get("/", (req, res) =>
  res.send(`Hello world! This server listening on port ${PORT}`)
);

app.post("/api/users/register", (req, res) => {
  const user = new User(req.body);
  user.save((err, userInfo) => {
    if (err) return res.json({ success: false, err });
    return res.status(200).json({ success: true });
  });
});

app.post("/api/users/login", (req, res) => {
  // 요청된 이메일이 데이터베이스에 있는지 찾는다.
  User.findOne({ email: req.body.email }, (err, user) => {
    if (!user) {
      return res.json({
        loginSuccess: false,
        message: "입력하신 이메일에 해당하는 유저가 없습니다.",
      });
    }
    // 요청된 이메일이 데이터베이스에 있다면 비밀번호가 맞는 비밀번호인지 확인.
    user.comparePassword(req.body.password, (err, isMatch) => {
      if (!isMatch) {
        return res.json({
          loginSuccess: false,
          message: "비밀번호가 틀렸습니다.",
        });
      } else {
        // 비밀번호까지 맞다면 토큰 생성
        user.generateToken((err, user) => {
          if (err) return res.status(400).send(err);
          // 토큰을 저장한다. 어디에? 선택할 수 있음. 쿠키 또는 로컬스토리지에. 어디에 저장하면 안전한지는 아직 논란거리.
          res
            .cookie("x_auth", user.token)
            .status(200)
            .json({ loginSuccess: true, userId: user._id });
        });
      }
    });
  });
});

// role = > 일반유저, role 0 이 아니면 관리자

app.get("/api/users/auth", auth, (req, res) => {
  // 여기까지 미들웨어를 통과해왔다는 얘기는 Authentication 이 True 라는 말.
  res.status(200).json({
    _id: req.user._id,
    isAdmin: req.user.role === 0 ? false : true,
    isAuth: true,
    email: req.user.email,
    name: req.user.name,
    role: req.user.role,
  });
});

app.get("/api/users/logout", auth, (req, res) => {
  User.findOneAndUpdate({ _id: req.user._id }, { token: "" }, (err, user) => {
    if (err) return res.json({ success: false, err });
    return res.status(200).send({ success: true });
  });
});
