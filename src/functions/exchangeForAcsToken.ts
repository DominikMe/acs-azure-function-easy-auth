import { CommunicationAccessToken, CommunicationIdentityClient, CommunicationUserToken, TokenScope } from "@azure/communication-identity";
import { HttpRequest, HttpResponseInit, InvocationContext, app, input, output } from "@azure/functions";

const tokenScopes: TokenScope[] = ["chat", "voip"];
const minExpiryInMs = 1000 * 60 * 60; // 1 hour

interface TableRow {
    PartitionKey: string;
    RowKey: string;
    AcsUserId: string;
    AcsUserToken: string;
    AcsUserTokenExpiry: string;
}

const tableInput = input.table({
    tableName: 'UserMappings',
    connection: 'TableStorageConnectionString',
    partitionKey: '{headers.x-zumo-auth}',
    rowKey: '{headers.x-zumo-auth}'
});

const tableOutput = output.table({
    tableName: 'UserMappings',
    connection: 'TableStorageConnectionString'
});

export async function exchangeForAcsToken(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
    context.log(`Http function processed request for url "${request.url}"`);

    const rows = context.extraInputs.get(tableInput) as TableRow[];
    const minExpiry = new Date(Date.now() + minExpiryInMs);

    if (rows.length > 1) {
        return {
            status: 500,
            body: "Found more than user entry!"
        }
    }

    let isNewUser = false;
    let AcsUserId = "";
    let AcsUserToken = "";
    let AcsUserTokenExpiry = "";

    if (rows.length === 1) {
        AcsUserId = rows[0].AcsUserId;
        AcsUserToken = rows[0].AcsUserToken;
    }
    
    const easyAuthUserId = request.headers.get('x-zumo-auth');

    if (!AcsUserId) {
        const { expiresOn, token, user} = await createAcsUserAndToken();
        
        AcsUserId = user.communicationUserId;
        AcsUserToken = token;
        AcsUserTokenExpiry = expiresOn.toISOString();

        context.extraOutputs.set(tableOutput, {
            PartitionKey: easyAuthUserId,
            RowKey: easyAuthUserId,
            AcsUserId,
            AcsUserToken,
            AcsUserTokenExpiry
        });

        isNewUser = true;
    }

    if (!AcsUserToken || new Date(AcsUserTokenExpiry) < minExpiry) {
        const { expiresOn, token } = await issueAcsToken(AcsUserId);
        
        AcsUserToken = token;
        AcsUserTokenExpiry = expiresOn.toISOString();

        context.extraOutputs.set(tableOutput, {
            PartitionKey: easyAuthUserId,
            RowKey: easyAuthUserId,
            AcsUserId,
            AcsUserToken,
            AcsUserTokenExpiry
        });
    }

    return {
        jsonBody: {
            userId: AcsUserId,
            token: AcsUserToken,
            expiresOn: AcsUserTokenExpiry,
            isNewUser
        }
    };
};

const createAcsUserAndToken = async(): Promise<CommunicationUserToken> => {
    const identityClient = new CommunicationIdentityClient(process.env.CommunicationConnectionString);
    return await identityClient.createUserAndToken(tokenScopes);
}

const issueAcsToken = async(userId: string): Promise<CommunicationAccessToken> => {
    const identityClient = new CommunicationIdentityClient(process.env.CommunicationConnectionString);
    return await identityClient.getToken({ communicationUserId: userId }, tokenScopes);
}

app.http('exchangeForAcsToken', {
    methods: ['POST'],
    authLevel: 'anonymous',
    extraInputs: [tableInput],
    extraOutputs: [tableOutput],
    handler: exchangeForAcsToken
});