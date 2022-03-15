const FabricCAClient = require('fabric-ca-client');
const { User } = require('fabric-common');
const utilities = require('./utilities');

// Extract environment variables
const caEndpoint = process.env.CA_ENDPOINT;
const orgName = process.env.MEMBER_NAME;
const privateKeyArn = process.env.PRIVATE_KEY_ARN;
const signedCertArn = process.env.SIGNED_CERT_ARN;
const tlsCertBucket = process.env.TLS_CERT_BUCKET;
const tlsCertKey = process.env.TLS_CERT_KEY; 

const adminId = 'admin';
const caUrl = `https://${caEndpoint}`;
const caName = utilities.getCaName(caEndpoint);
const mspId = `${orgName}Msp`; 

exports.handler = async function (event) {

    const requestType = event.RequestType;
    const userData = event.ResourceProperties;
    const userId = userData.userId;
    const affiliation = userData.affiliation;

    // Register and enroll users only on Create
    if (requestType === 'Create') 
    {
        try {     
            
            // Get the TLS cert from S3 bucket
            const caTlsCert = await utilities.getS3Object(tlsCertBucket, tlsCertKey);

            // Get the admin credentials from the secrets manager
            const adminPrivateKey = await utilities.getSecret(privateKeyArn);
            const adminSignedCert = await utilities.getSecret(signedCertArn);

            // Create a new CA client for interacting with the CA.
            const ca = new FabricCAClient(caUrl, { trustedRoots: caTlsCert, verify: false }, caName);

            // Create User object for the Admin. Password argument on createUser method 
            // is not really used in creating the SignedIdentity, so defaulting it to empty string
            const adminUser = User.createUser(adminId, '', mspId, adminSignedCert, adminPrivateKey);

            // Check if user is already registered; return if exist
            const identityService = ca.newIdentityService();
            const identityObject = await identityService.getAll(adminUser);
            const userResult = identityObject.result;
            if (userResult.identities && userResult.identities.find(e => e.id === userId)) {
                console.log(`${userId} already exist.`);
                return;
            }

            // Admin user has the org(member) as the root affiliation by default. 
            // If other affiliation is requested check for existence and add if not exist.
            if (affiliation !== orgName) {
                const affObject = ca.newAffiliationService()
                const affRequest = await affObject.getAll(adminUser);
                const affResult = affRequest.result;
                if (!affResult.affiliations || !affResult.affiliations.find(e => e.name === affiliation)) await affObject.create({name: affiliation}, adminUser);
            }

            // Register and enroll the user as client, and import the new identity into secret manager.
            const userSecret = await ca.register({ enrollmentID: userId, role: 'client', affiliation}, adminUser);
            const userEnroll = await ca.enroll({ enrollmentID: userId, enrollmentSecret: userSecret});
            await utilities.putSecret(userData.passwordArn, userSecret);
            await utilities.putSecret(userData.privateKeyArn, userEnroll.key.toBytes());
            await utilities.putSecret(userData.signedCertArn, userEnroll.certificate); 

            return;
        } catch (error) { console.error(`Failed to enroll user ${userId}: ${error}`); }
    }
    else return;
}