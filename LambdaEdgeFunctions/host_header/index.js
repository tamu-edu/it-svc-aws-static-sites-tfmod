'use strict';
module.exports.handler = (event, context, callback) => {
    const request = event.Records[0].cf.request;
    const host = request.headers["host"][0].value;

    // Add an alternate way for the origin request Lambda to get the host header
    // without causing problems for S3 origin requests
    request.headers["x-forwarded-host"] = [{
        key: "X-Forwarded-Host",
        value: host
    }]; 
    
    callback(null, request);
};