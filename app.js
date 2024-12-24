const path = require('path'); 

const express = require('express');
const session = require('express-session'); // 세션 사용 패키지 require
const mongodbStore = require('connect-mongodb-session'); // 세션 정보와 mongoDB를 연동하기 위한 패키지 require

const db = require('./data/database');


const MongoDBStore = mongodbStore(session); // 세션과 mongoDB를 연동

// 사용할 mongoDB 정보와, 컬렉션 정보를 입력. 세션을 저장하도록 설정.
const sessionStore = new MongoDBStore({
  url: 'mongodb://localhost:27017',
  databaseName : 'auth-demo',
  collection: 'sessions'
});

const app = express();
const demoRoutes = require('./routes/demo');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: 'super-secret',
  resave: false,
  saveUninitialized: false,
  store: sessionStore
})); // 미들웨어 express-session을 사용하도록 설정

app.use(async function(req, res, next){
  const user = req.session.user;
  const isAuth = req.session.isAuthenticated;

  if(!user  || !isAuth){
    return next();
  }

  const userDoc = await db.getDb().collection('users').findOne({_id: user.id});
  const isAdmin = userDoc.isAdmin;

  res.locals.isAuth = isAuth;
  res.locals.isAdmin = isAdmin;

  next();
});

app.use(demoRoutes);

app.use(function(error, req, res, next) {
  res.render('500');
})

db.connectToDatabase().then(function () {
  app.listen(3000);
});
