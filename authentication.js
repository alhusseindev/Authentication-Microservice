const express = require('express');
const app = express();
const nodemailer = require('nodemailer');
const uuid = require('uuid');
const otpCodeModel = require('./Model/AuthModel');

const mongoose = require('mongoose');
const fs = require('fs');
const jwt = require('jsonwebtoken');
//const crypto = require('crypto');
const dotenv = require('dotenv').config({path: require('find-config')('.env')});
const path = require('path');
const cors = require('cors');
const protectedRoute = require('./ProtectedRoute');
//const redis = require('redis');


//Email Sending Service
const sendGrid = require("@sendgrid/mail");

sendGrid.setApiKey(process.env.NuspireSendGridKey);



const router = express.Router();




/** connecting to database */


try {


    const dbURL = mongoose.connect(process.env.DB_URL, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useFindAndModify: true

    }).then((response) =>{
        fs.appendFile('otp-request.log', `Connection Successful\n${response}\n`, (err) =>{
            if(err) {
                fs.appendFile('otp-request-error.log', `Error Occurred When writing to error log file:\n${err}`);
            }
        });
    }).catch((error) =>{
        fs.appendFile('otp-request-error.log', `Error Connecting to Database: ${error}\n`, (err) =>{
            if(err) {
                fs.appendFile('otp-request-error.log', `Error When Writing to Error log file:\n${err}`);
            }
        })
    });


}catch(error){
    fs.appendFile('otp-request-error.log', `Error Connecting to Database:\n${error}\n`, (err) =>{
        if(err) {
            fs.appendFile('otp-request-error.log', `Error When Writing to Error log file:\n${err}`);
        }
    });
}



//method to generate access tokens.

function generateAccessTokens(user){
    return jwt.sign({_id:user._id}, process.env.SECRET_CODE, {expiresIn: 60*59, });
}


//method to generate refresh tokens.

function refreshAccessTokens(user) {
    return jwt.sign({_id:user._id}, process.env.REFRESH_SECRET_CODE, {expiresIn: '1d'}); //refresh code should never expire
}





/***** JSON Web Tokens ***** */
// a route for verifying jwt tokens issued
router.post("/token/verify", (request, response) =>{
    try{
        accessToken = request.body.accessToken;
        //jwt header.payload.signature
        //a jwt token signature is a mix of header + payload + secret code
        jwt.verify(accessToken, process.env.SECRET_CODE, (err, data) =>{
            if(err){return response.status(400).json({message: `${err}`});}
            else{return response.status(200).json({message: `${JSON.stringify(data)}`});}
        });
    }catch(err){
        return response.status(400).json({message: `${err}`});
    }
});





// a route for deleting all access tokens in a database

router.delete('/delete/all', async (request, response) =>{
    try {
        await otpCodeModel.find().deleteMany();
        return response.status(200).json({message: 'Deleted Successfully'});
    }catch(err){
        return response.status(406).json({message:`${err}`});
    }
});



// a route for deleting specific access tokens in a database

router.delete('/delete/:id', async (request, response) =>{
    try {
        let myOTPCode = await otpCodeModel.findByIdAndDelete(request.params.id);
        return response.status(202).json({message:`Item Deleted Successfully`});
    }catch(error){
        return response.status(403).json({message:`Error Deleting Item: ${error}`});
    }
});













//nodemailer
const mailTransporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    //accessToken: 'AIzaSyAT7QLqQjDOn6FrMYFmHUENAT4PZRzuHYY',
    ignoreTLS: false,
    secure: false,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
});






/** An endpoint for generating passwords */
router.post('/generate-passcode', async (request, response) => {
    let randomCounter;
    let emailParameter = request.body.email;
    let emailToken;
    let emailDomain;
    let savedOTPCode;
    randomCounter = uuid.v4();

    if(emailParameter === undefined){
        return response.status(400).json({message: "Cannot Process undefined data, please make sure you are entering valid data!"});
    }

    if (emailParameter !== undefined) {
        emailToken = emailParameter.split('@');
        emailDomain = String(emailToken[1]);
    }

    console.log(emailToken);
    console.log('email_domain ' + emailDomain);


    try {


        let myOTPCodeModel = new otpCodeModel({email: emailParameter, otpCode: randomCounter});
        try {
            savedOTPCode = await myOTPCodeModel.save();
        } catch (error) {
            return response.status(404).json({message: `Error Saving {Email:Code} pair to database:\n${error}`});
        }


        /** Sending Email  */

        try {
            let emailToSend = {
                'from': process.env.EMAIL,
                'to': `${emailParameter}`.toString(),
                'subject': `Nuspire Logging & Reporting - Your Secret PassCode is: ${randomCounter}`,
                'text': `Hey ${emailToken[0]},\n\nYour Secret Passcode is: ${randomCounter}\n\n\nCheers,\nNuspire Team\n\n`
            };

            sendGrid.send(emailToSend)
                .then(() => {
                    console.log(`Message Sent Successfully!`);
                    return response.status(200).json({message: `Code Generated Successfully, Email Sent with the Code!`});
                }).catch((err) => {
                return response.status(422).json({message: `${err}`});
            });

        } catch (error) {
            return response.status(422).json({message: `Error 400! Could Not Send Email!${error}`});
        }
        //}
    }catch(err){
        return response.status(406).json({message: `${err}`});
    }

});





//a route for listing all generated passcodes.


router.get('/list', protectedRoute,  async (request, response) =>{
    try{

        let myOTPCodeList = await otpCodeModel.find();
        return response.status(202).json(myOTPCodeList);

    }catch(error){
        return response.status(400).json({message: `Error Occurred:\n${error}`});
    }
});


// a route for refreshing the tokens.
router.post('/refreshtoken/renew', async (request, response) =>{
    let email = request.headers.email;
    let refreshToken = request.headers.refreshToken;
    await jwt.verify(refreshToken, process.env["REFRESH_SECRET_CODE "], (err, data) =>{
        if(err){
            return response.status(400).json({message: `${err}`});
        }else {
            refreshAccessTokens(email);
            return response.status(200).json({message: `Refresh Token verified successfully. Refresh Token Extended! ${data}`});
        }
    });

});




/********************************************************************************** */
//an endpoint for confirming the passcode sent basically the (login) function here.
//the user posts the email and we compare the sent passcode that is stored in DB,
//which is associated with the user's email with the passcode the user enters.
//here it only uses the email to look up the passcode associated

router.post('/findbyemail', async (request, response) =>{
    try {

        let requestEmail = request.body.email;
        let requestOTPCode = request.body.otpcode;

        let verified = false;

        console.log(`Request Email: ` + requestEmail);

        let sentCode;
        let timeStamp;
        let timeNow = new Date().getTime(); //.toISOString();
        console.log("time now: " + timeNow);
        let latestOTP;
        let emailPresentInDB;


        if(requestEmail === undefined || requestOTPCode === undefined){
            return response.status(400).json({message: "Received Undefined Data, please input the correct credentials!"});
        }

        /** if requestEmail && requestOTPCode are present in the request's body
         *  then lookup the DB by email for the associated OTP code
         */

        console.log(`status: ${requestEmail && requestOTPCode}`);
        if(requestEmail && requestOTPCode) {
            latestOTP = await otpCodeModel.find({email:requestEmail}).sort({_id: -1}).limit(1); //{_id:-1} for newest - {_id:1} for oldest


            //iterating over the object's values  //note: for(let i in latestOTP) iterates over the object's keys
            for(let i of latestOTP){
                emailPresentInDB = i.email;
                sentCode = i.otpCode;
                timeStamp = i.OTPTimeStamp.getTime();
            }

        }

        /**V3: added this as well */
        console.log(`email verification: ${emailPresentInDB === requestEmail}` + `passcode verification: ${sentCode === requestOTPCode}`);
        if(emailPresentInDB === requestEmail && sentCode === requestOTPCode){
            verified = true;
        }


        console.log("time stamp: " + timeStamp);
        let resultTime =  calculateTimeInHours(timeNow, timeStamp);
        console.log("result in hours after subtracting both times: " + resultTime);

        if(emailPresentInDB !== requestEmail){
            return response.status(404).json({message: "No OTP Pass Code was sent to that email / OTP Code Expired!"});
        }


        /**if((resultTime > 0.59 || resultTime < 0) && emailPresentInDB) {
            return response.json({message: "OTP Code Expired! Please Generate A New One!"});
        } */


        //authenticate user
        /*** do some authentication */
        //now, if(authenticated){
        //then generate access tokens..............................................


        /** serialize with JsonWebTokens (JWT) */
        if(verified){
            //if verified the user is issued an access token with short expiry time
            //and a refresh token that has a long expiry time.
            //the refresh token should be used to obtain new Refresh token, by POSTing
            //the user credentials (email, password)
            //and not having to logout the user.
            const accessToken = generateAccessTokens(requestEmail);
            const refreshToken = refreshAccessTokens(requestEmail);

            response.setHeader("accesstoken", accessToken);
            response.setHeader("refreshtoken", refreshToken);
            //storing accesstoken as a cookie
            response.cookie("accesstoken", accessToken, {secure: true, httpOnly: true});

            //putting those fields in the request headers
            response.set("email", requestEmail);
            response.set("otpcode", sentCode);

            /** We do not need to store the token in the database,
             * because what's the purpose of using a JWT token then
             * All we need to do is just validate/decode/verify the token.
             */


            return response.status(201).json({message: "User Verified, Access Tokens Generated Successfully!"});

        }else{
            return response.status(404).json({message: "Invalid Credentials, No Access Tokens Granted!"});
        }



    }catch(error){
        return response.status(400).json({message: `${error}`});
    }
});



let calculateTimeInHours = (currentTime, passedTime) =>{
    // 60 * 60 * 1000 converts miliseconds returned object to hours.
    // Note: 36e5 = 60 * 60 * 1000

    let result = (currentTime - passedTime) / (60 * 60 * 1000);

    result < 24
    return result;
}





// an endpoint for listing otp code by user

router.get('/listbyuser/:user', async (request, response) =>{
    try{
        let itemsByUserEmail = request.params.user;
        let myOTPCodeList = await otpCodeModel.find({email:itemsByUserEmail});
        return response.status(202).json(myOTPCodeList);
    }catch(error){
        return response.status(400).json({ErrorMessage: `Error Occurred:\n${error}`});
    }
});




module.exports = router;
