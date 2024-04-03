import { CommunicationIdentityClient, TokenScope } from "@azure/communication-identity";
import { TableClient } from "@azure/data-tables";
import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";

const tokenScopes: TokenScope[] = ["chat", "voip"];
const minExpiryInMs = 1000 * 60 * 60; // 1 hour

interface TableRow {
    IdentityProvider: string;
    AcsUserId: string;
    AcsUserToken: string;
    AcsUserTokenExpiry: string;
}

export async function exchangeForAcsToken(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
    context.log(`Http function processed request for url "${request.url}"`);

    const easyAuthUserId = request.headers.get('X-MS-CLIENT-PRINCIPAL-ID');
    const identityProvider = request.headers.get('X-MS-CLIENT-PRINCIPAL-IDP');
    if (!easyAuthUserId || !identityProvider) {
        return {
            status: 401,
            body: "Azure Function Easy Auth headers not found."
        }
    }

    const identityClient = new CommunicationIdentityClient(process.env.CommunicationConnectionString);
    const tableClient = TableClient.fromConnectionString(process.env.TableStorageConnectionString, 'UserMappings', {
        allowInsecureConnection: process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0"
    });
    await tableClient.createTable();
    
    let isNewUser = false;
    let tokenFromCache = true;
    let userRecord: TableRow | undefined = undefined;

    try {
        userRecord = await tableClient.getEntity<TableRow>(easyAuthUserId, easyAuthUserId);    
    }
    catch {
        console.log("User not found in table storage");
    }

    if (!userRecord || !userRecord.AcsUserId) {
        const { expiresOn, token, user} = await identityClient.createUserAndToken(tokenScopes);
        
        userRecord = {
            IdentityProvider: identityProvider,
            AcsUserId: user.communicationUserId,
            AcsUserToken: token,
            AcsUserTokenExpiry: expiresOn.toISOString()
        };
        isNewUser = true;
        tokenFromCache = false;
    }

    const minExpiry = new Date(Date.now() + minExpiryInMs);
    if (!userRecord.AcsUserToken || new Date(userRecord.AcsUserTokenExpiry) < minExpiry) {
        const { expiresOn, token } = await identityClient.getToken({ communicationUserId: userRecord.AcsUserId }, tokenScopes);
        
        userRecord = {
            IdentityProvider: identityProvider,
            AcsUserId: userRecord.AcsUserId,
            AcsUserToken: token,
            AcsUserTokenExpiry: expiresOn.toISOString()
        };
        tokenFromCache = false;
    }

    if (isNewUser || !tokenFromCache) {
        await tableClient.upsertEntity({ ...userRecord, partitionKey: easyAuthUserId, rowKey: easyAuthUserId });
    }

    return {
        jsonBody: {
            userId: userRecord.AcsUserId,
            token: userRecord.AcsUserToken,
            expiresOn: userRecord.AcsUserTokenExpiry,
            isNewUser,
            tokenFromCache
        }
    };
};

app.http('exchangeForAcsToken', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: exchangeForAcsToken
});