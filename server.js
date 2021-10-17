const express = require("express");
const app = express();
const cors = require("cors");
const authServer = require("./authentication");

app.use(express.json());

app.use("/auth", authServer);


app.use(cors({
   origin: ["http://localhost:3000", "http://127.0.0.1:3000"],  //my frontend's url
   exposedHeaders: ['accessToken', 'accesstoken', 'AccessToken', "email", "otpcode"],
   credentials: true
}));



app.listen(process.env.PORT || 5000, () =>{
   console.log(`App is listening on port ${process.env.PORT}`);
});


module.exports = app;
