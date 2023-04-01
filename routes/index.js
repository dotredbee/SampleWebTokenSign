var express = require('express');
var router = express.Router();
const csurf = require('csurf');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const redis = require('redis')
const _redis = redis.createClient({
  password: process.env.REDIS_PASSWORD,
    socket: {
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT
    }
})
_redis.connect()

const accessKey = process.env.ACCESS_TOKEN_KEY
const refrehKey = process.env.REFRESH_TOKEN_KEY

/**
 * 
 * web token 유효성 검증 토큰
 * access token 유효하지 않다면 refresh 유효성 검증 후 access token 재발급
 * 
 * @param {express.Request} req 
 * @param {express.Response} res 
 * @param {express.NextFunction} next 
 * @returns 
 */
const verifyTokenMiddleware = async (req, res, next) => {
  let token = null;
  if(!req.cookies.hasOwnProperty('accessToken') || !req.cookies.hasOwnProperty('refreshToken')) 
      return res.status(403).json({
        status : 403, 
        success : false,
        message : "인증 토큰이 없습니다."
      })

  try{
      let token = req.cookies.accessToken;
      
      await jwt.verify(token, accessKey)
      next()
  }catch(err){
      res.clearCookie('accessToken')

      // if access token is invalid 
      try{
          const refreshToken = req.cookies.refreshToken

          let decode = await jwt.verify(refreshToken, refrehKey)
          const { userId } = decode;

          const _refreshToken = await _redis.get(userId)
          
          // redis server에 refresh token이 없다면 
          if(!_refreshToken || refreshToken !== _refreshToken) throw new Error('Invalid refresh token')


          token = await jwt.sign(decode, accessKey)
          res.cookie('accessToken', token, {
            httpOnly : true,
            sameSite : 'strict'
          })

          req.cookies.accessToken = token
          next()         
        }catch(err){
          res.status(403).json({
            status : 403,
            success : false,
            message : "다시 로그인해주세요."
          })
      }
  }
}

/**
 * mongoose 
 */

const mongoose = require('mongoose');
mongoose.connect('mongodb://127.0.0.1:27017/test')
const User = require('../models/user');

// jwt salt round 
const saltRound = 10;

// protect the csrf attack 
const csrfProtection = csurf({
  cookie : { 
    httpOnly : true,
    sameSite : 'strict',
  }
})

// csrf 토큰 발급 
router.get('/csrf', csrfProtection, (req, res, next) => {
  res.cookie('csrfToken', req.csrfToken(), {
    httpOnly : true,
    sameSite : 'strict'
  })

  res.status(200).json({
    status : 200,
    success : true,
    message : 'CSRF Token 발급 성공'
  })
})

// 로그인
router.post('/signup', csrfProtection, async (req, res, next) => {
  
  const { username, password } = req.body;  
  try{
    const hashed = await bcrypt.hash(password, saltRound)
    
    await User.create({
      username,
      password : hashed
    })
    
    res.status(200).json({
      status : 200,
      success : true,
      message : '회원가입되었습니다.'
    })
  }catch(err){
    res.status(200).json({
      status : 401, 
      success : false, 
      message : "잘못된 형식의 요청입니다."
    })
  }
})

router.post('/login', csrfProtection, async (req, res, next) => {
  const { username, password } = req.body;
  try{
    const recode = await User.findOne({ username })
    
    if(!recode)
      return res.status(200).json({
        status : 403,
        success : false,
        message : "일치하는 아이디가 없습니다."
      })

    const ret = await bcrypt.compare(password, recode.password)
    
    if(!ret)
      return res.status(200).json({
        status : 403,
        success : false,
        message : "비밀번호가 일치하지 않습니다."
      })
    const userId = recode._id.toString()

    const payload = {
      userId,
      username : recode.username 
    }
    
    const accessToken = await jwt.sign(payload, accessKey)
    const refreshToken = await jwt.sign(payload, refrehKey)

    res.cookie('accessToken', accessToken, {
      httpOnly : true,
      secure : false,
      sameSite : 'strict',
    })

    res.cookie('refreshToken', refreshToken, {
      httpOnly : true,
      secure : false, 
      sameSite : 'strict'
    })

    await _redis.set(userId, refreshToken)
    
    res.status(200).json({
      status : 200, 
      success : true,
      message : "로그인 되었습니다."
    })
    
  }catch(err){
    res.status(200).json({
      status : 401,
      success : false, 
      message : "잘못된 형식의 요청입니다."
    })
  }
})

// api service need : cookies(web tokens info)
router.get('/api', verifyTokenMiddleware, passport.authenticate('jwt', { session : false }), (req, res, next) => {
  try{
    
    console.log('hello api service')
    res.status(200).json({
      status : 200,
      success : true,
      message : "요청에 성공하셨습니다."
    })
  }catch(err) {
    res.status(200).json({
      status : 401,
      success : false, 
      message : "잘못된 형식의 요청입니다."
    })
  }
})
/* GET home page. */
router.get('/',function(req, res, next) {
  res.render('index', { title: 'Express' });
});


module.exports = router;
