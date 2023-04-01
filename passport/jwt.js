const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const User = require('../models/user')


const cookieExtractor = (req) => { 
    let token = null;

    if(req && req.cookies) {
        token = req.cookies.accessToken;
    }
    console.log(token)
    return token 
}

/**
 * 
 * access token 유효성을 검사한 값을 반환합니다.. 
 * 
 * @param {Object} passport 초기화 설정된 passport 객체
 */
module.exports = (passport) => { 
    passport.use(new JwtStrategy({
        jwtFromRequest : ExtractJwt.fromExtractors([cookieExtractor]),
        secretOrKey : process.env.ACCESS_TOKEN_KEY
    }, async (payload, done) => { 
        const username = payload.username;
        try{
            const user = await User.findOne({ username })
            
            if(user) return done(null, user) 
            done(null, false)
        }catch(err) {
            done(err, false)
        }
    }))
}
