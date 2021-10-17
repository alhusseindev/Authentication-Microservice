const jwt = require('jsonwebtoken');


//we will pass this verifyToken function in the routes that we want to protect
module.exports = function authenticateRoute(request, response, next){
    //let's access the authorization header /** Note I changed the Authorization header to 'auth-token'
    const authToken = request.header('auth-token');  //the header will have BEARER TOKEN, split by a space
    if(!authToken){
        //tell the user you do not have access
        return response.status(401).json({message: "Access Denied!"});
    }
    console.log(authToken);

    try{
        const verifiedToken = jwt.verify(authToken, process.env.SECRET_CODE);
        //if the user is verified
        request.user = verifiedToken;
        next(); //move on
    }catch(error){
        response.status(404).json({message: `${error}`});
    }

}
