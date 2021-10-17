const mongoose = require('mongoose');


let otpSchema = new mongoose.Schema({
    email: {
        type: String
    },
    otpCode: {
        type: String
    },
    OTPTimeStamp:{
        type: Date,
        default: new Date()
    }
});


let otpCodeModel = mongoose.model('OTP', otpSchema);

module.exports = otpCodeModel;



