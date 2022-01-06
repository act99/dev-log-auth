const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50,
  },
  email: {
    type: String,
    trim: true,
    unique: 1,
  },
  password: {
    type: String,
    maxlength: 100,
  },
  role: {
    type: Number,
    default: 0,
  },
  image: String,
  token: {
    type: String,
  },
  tokenExp: {
    type: Number,
  },
});
userSchema.pre("save", function (next) {
  var user = this;
  if (user.isModified("password")) {
    // 비밀번호를 암호화 시킨다.
    bcrypt.genSalt(saltRounds, function (err, salt) {
      if (err) return next(err);
      bcrypt.hash(user.password, salt, function (err, hash) {
        if (err) return next(err);
        user.password = hash;
        next();

        // Store hash in your password DB.
      });
    });
  } else {
    next();
  }
});

userSchema.methods.comparePassword = function (plainPassword, callbackFunc) {
  // painPassword => 입력한 그대로의 비밀번호 / 암호돠된 비밀번호 => 해쉬형태 #asdF!@#ASFDS2123sdF@!~
  bcrypt.compare(plainPassword, this.password, function (err, isMatch) {
    if (err) return callbackFunc(err);
    callbackFunc(null, isMatch);
  });
};

userSchema.methods.generateToken = function (callbackFunc) {
  var user = this;
  // jsonWebtoken 을 이용해 token 생성
  // user._id + 'secretToken' => token
  var token = jwt.sign(user._id.toHexString(), "secretToken");
  user.token = token;
  user.save(function (err, user) {
    if (err) return callbackFunc(err);
    callbackFunc(null, user);
  });
};

userSchema.statics.findByToken = function (token, callbackFunc) {
  var user = this;
  // 토큰을 decode 한다. 토큰에서 secretToken을 가지고 디코드해 Id값을 추출시킴
  jwt.verify(token, "secretToken", function (err, decoded) {
    // 유저 아이디를 이용해 유저를 찾은 뒤
    // 클라이언트에서 가져온 token 과 DB에 보관된 토큰이 일치하는지 확인
    user.findOne({ _id: decoded, token: token }, function (err, user) {
      if (err) return callbackFunc(err);
      callbackFunc(null, user);
    });
  });
};

const User = mongoose.model("User", userSchema);

module.exports = { User };
