const express = require("express");
const bcrypt = require("bcryptjs"); // 패스워드 해싱을 위한 패키지 require

const db = require("../data/database");

const router = express.Router();

router.get("/", function (req, res) {
  res.render("welcome");
});

router.get("/signup", function (req, res) {
  let sessionInputData = req.session.inputData;
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: '',
      confirmEmail: '',
      password: ''
    };
  }
  req.session.inputData = null; 

  res.render("signup", {inputData : sessionInputData});
});

router.get("/login", function (req, res) {
  let sessionInputData = req.session.inputData;

  if(!sessionInputData){
    sessionInputData = {
      hasError: false,
      email: '',
      password: '',
    };
  }
  res.render("login",{inputData : sessionInputData});
});

// signup 경로로 post 요청 전달 시.
router.post("/signup", async function (req, res) {
  // 요청에서 데이터들을 받아서 각 변수에 할당
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredConfirmEmail = userData["confirm-email"];
  const enteredPassword = userData.password;

  // 입력값들의 조건 및 임계치 설정
  if (
    !enteredEmail ||
    !enteredConfirmEmail ||
    !enteredPassword ||
    enteredPassword.trim().length < 6 ||
    enteredEmail !== enteredConfirmEmail ||
    !enteredEmail.includes("@")
  ) {
    req.session.inputData = {
      hasError: true,
      message: "Invalid input",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };
    req.session.save(function () {
      res.redirect("/signup"); // 다시 signup 경로로 리다이렉트
    });
    return;
  }

  // DB에 사용자가 입력한 이메일이 존재하는지 확인함.
  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  // DB에 이미 사용자가 입력한 이메일이 존재하면 다시 리다이렉트
  if (existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "User exists already!",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };
    req.session.save(function (){
      res.redirect("/signup");
    });
    return;
  }

  const hashedPassword = await bcrypt.hash(enteredPassword, 12); // bcryptjs를 이용하여 요청에서 받은 password를 해싱함.

  // users 컬렉션에 저장하기 위해, email에 입력받은 이메일, password에 입력받은 비밀번호를 해싱한 hashedPassword를 저장
  const user = {
    email: enteredEmail,
    password: hashedPassword,
  };

  await db.getDb().collection("users").insertOne(user); // users 컬렉션에 해당 데이터 삽입. 즉, 회원가입 완료가 되어 회원의 정보가 DB에 저장됨.

  res.redirect("/login"); // 로그인 경로로 리다이렉트
});

// 로그인 POST 요청 시
router.post("/login", async function (req, res) {
  // 로그인 INPUT에서 들어온 데이터들을 각 변수에 할당
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredPassword = userData.password;

  req.session.inputData = {
    enteredEmail: enteredEmail,
    enteredPassword: enteredPassword,
  };

  // 로그인 할 때 입력받은 이메일 정보가 DB에 있는지 확인.
  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  // 만약 존재하지 않는다면 다시 리다이렉트
  if (!existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - please check your info",
      email: enteredEmail,
      password: enteredPassword,
    };
    return res.redirect("/login");
  }

  // 입력받은 비밀번호(해쉬 안됨)와 DB에 저장된 비밀번호(해쉬 됨)을 COMPARE 메소드로 비교함. 같으면 TRUE, 다르면 FALSE 반환
  const passwordAreEqual = await bcrypt.compare(
    enteredPassword,
    existingUser.password
  );

  // 비밀번호가 불일치 시, 다시 리다이렉트
  if (!passwordAreEqual) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - please check your info",
      email: enteredEmail,
      password: enteredPassword,
    };
    req.session.save(function(){
      res.redirect('/login');
    });
    return;
  }

  req.session.user = { id: existingUser._id, email: existingUser.email}; // session의 user에 사용자가 로그인 정보를 저장.
  req.session.isAuthenticated = true; // 인증유무를 확인하는 isAuthenticated를 true로 설정
  req.session.save(function (err) {
    // 에러 발생시 콘솔 로그 출력 후, 로그인 경로로 리다이렉트
    if (err) {
      console.error("error", err);
      return res.redirect("/login");
    }
    // session 데이터베이스에 해당 데이터들 저장 후, 어드민 경로로 리다이렉트.
    res.redirect("/profile");
  });
});

// admin 경로로 GET 요청 받을 시,
router.get("/admin", async function (req, res) {
  if (!res.locals.isAdmin) {
    console.log("error");
    return res.status("401").render("401");
  }

  const user = await db.getDb().collection('users').findOne({_id:req.session.user.id});

  if(!user || !user.isAdmin){
    return res.status(403).render("403")
  }
  res.render("admin"); // 세션의 isAuthenticated가 true면 admin 페이지를 렌더.
});

router.post("/logout", function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect("/");
});

router.get("/profile", function (req, res) {
  if (!res.locals.isAuth) {
    return res.status("401").render("401");
  }
  res.render("profile"); // 세션의 isAuthenticated가 true면 admin 페이지를 렌더.
});


module.exports = router;
