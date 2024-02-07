const {
    GetObjectCommand,
	S3Client
} = require("@aws-sdk/client-s3");

const { 
    CloudFrontClient, 
    CreateInvalidationCommand,
    ListDistributionsCommand
} = require("@aws-sdk/client-cloudfront");

module.exports.handler = async (event, context, callback) => {
    const event_source = event.Records[0].eventSource;

    if (event_source !== 'aws:s3') {
        console.log(`Invalid event source: ${event_source}; expected 'aws:s3'`);
        callback(null, event);
    }
    const bucket_name = event.Records[0].s3.bucket.name;
    const object_key = event.Records[0].s3.object.key;

    if (object_key !== 'invalidate_cache.txt') {
        console.log(`Ignoring object key: ${object_key}; expected 'invalidate_cache.txt'`);
        callback(null, event);
    }

    // Determine which CloudFront distribution to invalidate based on the bucket ARN
    cf_client = new CloudFrontClient({});
    // Get all of the distributions
    const cf_list_request = new ListDistributionsCommand({});
    const cf_distributions = await cf_client.send(cf_list_request);
    // console.log(`Found distributions: ${JSON.stringify(cf_distributions, null, 2)}`);


    // Go through each distribution and find the one with the matching bucket name
    let distribution_id = null;
    for (let distribution of cf_distributions.DistributionList.Items) {
        if (distribution.Origins.Items[0].Id == bucket_name) {
            distribution_id = distribution.Id;
            break;
        }
    }

    if (distribution_id === null) {
        console.error(`No distribution found for bucket ${bucket_name}`);
        callback(null, event);
    }

    console.log(`Found distribution ${distribution_id} for bucket ${bucket_name}`);

    const s3_client = new S3Client({});

    // Fetch the object contents
    const s3_request = new GetObjectCommand({
        Bucket: bucket_name,
        Key: object_key
    });
    let object_data = null;
    try {
        const s3_response = await s3_client.send(s3_request);
        object_data = (await s3_response.Body.transformToString()).trim();
        console.log(`Object ${object_key} was successfully retrieved from bucket ${bucket_name}: ${object_data}`);
    } catch (err) {
        console.error(`Error retrieving object ${object_key} from bucket ${bucket_name}: ${err}`);
        callback(null, event)
    }

    // Parse the object contents
    const invalidation_paths = object_data.split('\n');
    // Delete the top line of the object data, which is the timestamp
    invalidation_paths.shift();

    console.log(`Invalidating the following paths: ${invalidation_paths}`);
    cf_invalidation_request = new CreateInvalidationCommand({
        DistributionId: distribution_id,
        InvalidationBatch: {
            CallerReference: Date.now().toString(),
            Paths: {
                Quantity: invalidation_paths.length,
                Items: invalidation_paths
            }
        }
    }); 
    cf_invalidation_response = await cf_client.send(cf_invalidation_request);
    
    callback(null, event);
};