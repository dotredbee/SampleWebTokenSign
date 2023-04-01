const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    username : {
        type : String,
        requried : true,
        unique : true, 
    },
    password : {
        type : String,
        required : true,
    }
},{
    timestamps : true 
})


module.exports = mongoose.model("User", userSchema)