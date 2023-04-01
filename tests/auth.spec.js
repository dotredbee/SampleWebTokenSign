const request = require('supertest')
const { expect } = require('expect')
const app = require('../app')
describe("Auth test", () => {
    it('should status 403 code with wrong username', (done) => {
        request(app)
            .get('/csrf')
            .expect(200)
            .end((err, res) => {
                if(err) done(err)
                
                const cookie = res.headers['set-cookie']
                const csrf = cookie[1].split(";")[0].split("=")[1];
                
                request(app)
                    .post('/login')
                    .set('Cookie', cookie)
                    .send({
                        username : 'unknown',
                        password : 'unknown',
                        _csrf : csrf
                    })
                    .end((err, res) => {
                        if(err) done(err)
                        expect(res.body.status).toEqual(403)
                        expect(res.body.success).toEqual(false)
                        done()
                    })
                
            })       
    })
    
    it('should status 403 code without the csrf token' , (done) => {
        request(app)
            .post('/signup')
            .send({
                username : 'tester1',
                password : 'tester1',
            })
            .end((err, res) => {
                if(err) done(err)
                expect(res.status).toEqual(403)
                done()
            })
    })

    it('should status 200 code with the csrf token', (done) => {
        request(app)
            .get('/csrf')
            .expect(200)
            .end((err, res) => {
                if(err) done(err)
                
                const cookie = res.headers['set-cookie']
                const csrf = cookie[1].split(";")[0].split("=")[1];
                
                request(app)
                    .post('/signup')
                    .set('Cookie', cookie)
                    .send({
                        username : 'tester1',
                        password : 'tester1',
                        _csrf : csrf
                    })
                    .end((err, res) => {
                        if(err) done(err)
                        expect(res.body.status).toEqual(200)
                        expect(res.body.success).toEqual(true)
                        done()
                    })
                
            })       
    })
    

    it('should status 200 code', (done) => {
        request(app)
        .get('/csrf')
        .expect(200)
        .end((err, res) => {
            if(err) done(err)
            
            const cookie = res.headers['set-cookie']
            const csrf = cookie[1].split(";")[0].split("=")[1];
            
            request(app)
                .post('/login')
                .set('Cookie', cookie)
                .send({
                    username : 'tester1',
                    password : 'tester1',
                    _csrf : csrf
                })
                .end((err, res) => {
                    if(err) done(err)
                    expect(res.body.status).toEqual(200)
                    expect(res.body.success).toEqual(true)
                    done()
                })
            
        })       
    })

    let _cookie = []
    beforeEach((done) => {
        request(app)
            .get('/csrf')
            .expect(200)
            .end((err, res) => {
                if(err) done(err)
                
                const cookie = res.headers['set-cookie']
                const csrf = cookie[1].split(";")[0].split("=")[1];
                request(app)
                    .post('/login')
                    .set('Cookie', cookie)
                    .send({
                        username : 'tester1',
                        password : 'tester1',
                        _csrf : csrf
                    })
                    .end((err, res) => {
                        if(err) return done(err) 
                        _cookie = res.headers['set-cookie']
                        done()
                    })
            })
    })

    it('should return 200 status code using api service with accessToken', (done) => {
        request(app)
            .get('/api')
            .set('Cookie', _cookie)
            .expect(200)
            .end((err, res) => {
                if(err) return done(err)
                expect(res.body.status).toEqual(200)
                expect(res.body.success).toEqual(true)
                done()
            })
    })

    /**
     * 만료된 access token 일 경우 
     */
    it('should return 200 status code using api service with invalid accessToken', (done) => {
        const wrongAccessCookie = Array.from(_cookie)
        wrongAccessCookie[0] = 'accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3RlcjEiLCJpYXQiOjE2ODAyNDc4NTh9.l3OcMuqXHQAxOsDuD1rQTCl1J515ejLhGVlllSXALkWY; Path=/; HttpOnly; SameSite=Strict'
        request(app)
            .get('/api')
            .set('Cookie', wrongAccessCookie)
            .expect(200)
            .end((err, res) => {
                if(err) return done(err)
                expect(res.body.status).toEqual(200)
                expect(res.body.success).toEqual(true)
                done()
            })
        
    })
})