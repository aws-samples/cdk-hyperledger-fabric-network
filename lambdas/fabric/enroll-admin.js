const FabricCAClient = require('fabric-ca-client');
const utilities = require('./utilities');

// Extract environment variables
const adminPasswordArn = process.env.ADMIN_PASSWORD_ARN;
const caEndpoint = process.env.CA_ENDPOINT;
const privateKeyArn = process.env.PRIVATE_KEY_ARN;
const signedCertArn = process.env.SIGNED_CERT_ARN;
const tlsCertBucket = process.env.TLS_CERT_BUCKET;
const tlsCertKey = process.env.TLS_CERT_KEY; 

const caUrl = `https://${caEndpoint}`;
const caName = utilities.getCaName(caEndpoint);


exports.handler = async function (event) {
    const requestType = event.RequestType;

    // Enroll the admin only on Create
    if (requestType === 'Create') 
    {
        try {

            // Get the TLS cert from S3 bucket
            const caTlsCert = await utilities.getS3Object(tlsCertBucket, tlsCertKey);
            
            // Get the admin credentials from the secrets manager
            const adminPwd = await utilities.getSecret(adminPasswordArn);

            // Create a new CA client for interacting with the CA.
            const ca = new FabricCAClient(caUrl, { trustedRoots: caTlsCert, verify: false }, caName);
    
            // Enroll the admin user, and import the new identity into secret manager.
            const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: adminPwd });
            await utilities.putSecret(privateKeyArn, enrollment.key.toBytes());
            await utilities.putSecret(signedCertArn, enrollment.certificate);
    
            return;
        } catch (error) { console.error(`Failed to enroll admin user "admin": ${error}`); }
    }
    else return;

}