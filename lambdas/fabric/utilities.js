const { GetObjectCommand, S3Client } = require('@aws-sdk/client-s3');
const { GetSecretValueCommand, PutSecretValueCommand, SecretsManagerClient, } = require('@aws-sdk/client-secrets-manager');

const s3Client = new S3Client();
const smClient = new SecretsManagerClient();

// Extracts CA Name from a CA Endpoint
function getCaName(caEndpoint) {
    const caName = caEndpoint.split('.')[1].split('-');
    caName[1] = caName[1].toUpperCase();
    return caName.join('-');
}

// Retrieve object from S3 bucket
async function getS3Object(bucketName, key) {    
    const objectData = await s3Client.send(new GetObjectCommand({Bucket: bucketName, Key: key}));
    return streamToString(objectData.Body);
}

// Retrieve secret from secret manager
async function getSecret(secretArn) {
    const secretData = await smClient.send( new GetSecretValueCommand({ SecretId: secretArn }));
    return secretData.SecretString;
}

// Stores secret to secret manager
async function putSecret(secretArn, secret) {    
    return smClient.send(new PutSecretValueCommand({ SecretId: secretArn, SecretString: secret}));;
}

// Converts a ReadableStream to a string.
async function streamToString(stream) {
    stream.setEncoding('utf8');
    let data = '';
    for await (const chunk of stream) {
        data += chunk;
    }
    return data;
}  
  
  module.exports = { getCaName, getS3Object, getSecret, putSecret };