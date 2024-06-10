const {
    ConnectionsModule,
    DidsModule,
    V2ProofProtocol,
    V2CredentialProtocol,
    ProofsModule,
    AutoAcceptProof,
    AutoAcceptCredential,
    CredentialsModule,
    WsOutboundTransport,
    Agent,
    HttpOutboundTransport,
    KeyType, ConnectionEventTypes, DidExchangeState, TypedArrayEncoder, ProofEventTypes, ProofState, DidDocument,
    DifPresentationExchangeProofFormatService, JsonLdCredentialFormatService, JwaSignatureAlgorithm, DidDocumentBuilder,
    getEd25519VerificationKey2018, W3cCredentialsModule, CredentialEventTypes, SignatureSuiteRegistry,
    getEd25519VerificationKey2020, W3cJsonLdVerifiableCredential, CredentialState, W3cJsonLdVerifiablePresentation,
    JsonTransformer, W3cCredentialService
} = require('@credo-ts/core')
const {
    AnonCredsCredentialFormatService,
    AnonCredsModule,
    AnonCredsProofFormatService,
    LegacyIndyCredentialFormatService,
    LegacyIndyProofFormatService,
    V1CredentialProtocol,
    V1ProofProtocol, DataIntegrityCredentialFormatService,
} = require('@credo-ts/anoncreds')
const QRCode = require('qrcode')
const {agentDependencies, HttpInboundTransport} = require('@credo-ts/node')
const {IndyVdrIndyDidResolver, IndyVdrAnonCredsRegistry, IndyVdrModule} = require('@credo-ts/indy-vdr')
const {indyVdr} = require('@hyperledger/indy-vdr-nodejs')
const {ariesAskar} = require('@hyperledger/aries-askar-nodejs')
const {AskarModule} = require('@credo-ts/askar')
const {anoncreds} = require('@hyperledger/anoncreds-nodejs')
const {AnonCredsRsModule} = require('@credo-ts/anoncreds')
const sys_config = require('config');
const getGenesisTransaction = async (url) => {
    const response = await fetch(url)
    return await response.text()
}
const initializeIssuerAgent = async (ledgerUrl, endPoint) => {

    const genesisTransactionsBCovrinTestNet = await getGenesisTransaction(ledgerUrl)

    const config = {
        label: sys_config.get('wallet.id'),
        walletConfig: {
            id: sys_config.get('wallet.id'),
            key: sys_config.get('wallet.key'),
        },
        endpoints: [endPoint],
        autoUpdateStorageOnStartup: true,
    }

    // A new instance of an agent is created here
    const agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet)
    })

    // Register a simple `WebSocket` outbound transport - not needed
    // agent.registerOutboundTransport(new WsOutboundTransport())

    // Register a simple `Http` outbound transport
    agent.registerOutboundTransport(new HttpOutboundTransport())

    // Register a simple `Http` inbound transport
    agent.registerInboundTransport(new HttpInboundTransport({port: 3010}))


    // Initialize the agent
    await agent.initialize()


    try {
        // Try to create the key for the wallet, if it already exists then jump these instructions
        const ed25519Key = await agent.wallet.createKey({
            keyType: KeyType.Ed25519,
            privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
        })

        const did = `did:key:${ed25519Key.fingerprint}`
        console.log(did)
        const builder = new DidDocumentBuilder(did)
        const ed25519VerificationMethod2020 = getEd25519VerificationKey2020({
            key: ed25519Key,
            id: `${did}#${ed25519Key.fingerprint}ab`,
            controller: did,
        })


        builder.addVerificationMethod(ed25519VerificationMethod2020)
        builder.addAuthentication(ed25519VerificationMethod2020.id)
        builder.addAssertionMethod(ed25519VerificationMethod2020.id)


        await agent.dids.create({
            method: 'key',
            didDocument: builder.build(),
            options: {
                keyType: KeyType.Ed25519,
                privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
            }
        })
    } catch (e) {


    }


    return agent
}

let agent

async function startEverything() {
    agent = await initializeIssuerAgent(sys_config.get('wallet.ledger_url'), sys_config.get('wallet.endpoint'));
    //await activateListener(agent, false, true)
}

async function activateListener(agent, issuing, verify) {

    agent.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({payload}) => {
        if (payload.connectionRecord.state === DidExchangeState.Completed) {
            await agent.basicMessages.sendMessage(payload.connectionRecord.id, "Hello, we can start to communicate")

            /* Start by sending an offer, if we want to release the credentials */

            if (issuing) {
                await agent.credentials.offerCredential({
                    connectionId: payload.connectionRecord.id,
                    protocolVersion: 'v2',
                    credentialFormats: {
                        jsonld: {
                            credential: {
                                "@context": [
                                    'https://www.w3.org/2018/credentials/v1',
                                    'https://w3id.org/citizenship/v1',
                                    'https://w3id.org/security/bbs/v1',
                                ],
                                id: 'https://example.com/credentials/3732',
                                type: ['VerifiableCredential', 'PermanentResidentCard'],
                                issuer: "did:key:z6Mkw4VsQTL36g5t4AA27M38ZgpEJE6ESas468vhZNhZJqjA",
                                issuanceDate: "2010-01-01T19:23:24Z",
                                credentialSubject: {
                                    id: 'did:key:z6MkjiobbuCnEED7VRkNjWtVmPFmPEGULAG1AgvWMxeXMreY',
                                    alumniOf: 'test',
                                    type: ['PermanentResident', 'Person'],
                                    givenName: 'JOHN',
                                    familyName: 'SMITH',
                                    gender: 'Male',
                                    image: 'data:image/png;base64,iVBORw0KGgokJggg==',
                                    playerOf: 'Napoli'

                                },
                            },
                            options: {
                                proofPurpose: 'assertionMethod',
                                proofType: "Ed25519Signature2018"
                            }
                        }

                        ,
                    },
                })
            }

            /* Start by sending a proof request, if we want to assess the identity */
            if (verify) {
                const proof_request = await agent.proofs.requestProof({
                    protocolVersion: 'v2',
                    connectionId: payload.connectionRecord.id,
                    proofFormats: {
                        presentationExchange: {
                            presentationDefinition: {
                                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                                "input_descriptors": [
                                    {
                                        "id": "wa_driver_license",
                                        "name": "Washington State Business License",
                                        "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
                                        "constraints": {
                                            "fields": [
                                                {
                                                    "path": [
                                                        "$.credentialSubject.alumniOf",
                                                        "$.credentialSubject.claims.alumniOf",
                                                    ]
                                                }
                                            ]
                                        }
                                    }
                                ],
                                "format": {
                                    "ldp_vc": {
                                        "proof_type": [
                                            "JsonWebSignature2020",
                                            "Ed25519Signature2018",
                                            "EcdsaSecp256k1Signature2019",
                                            "RsaSignature2018"
                                        ]
                                    },
                                    "ldp_vp": {
                                        "proof_type": ["Ed25519Signature2018"]
                                    },
                                    "ldp": {
                                        "proof_type": ["RsaSignature2018"]
                                    }
                                }
                            }

                        }

                    }
                });
            }
        }
        /* Set up the listener for the credential released */
        agent.events.on(CredentialEventTypes.CredentialStateChanged, ({payload}) => {
            /* If the credential offer has been accepted, we have to release these credentials */
            if (payload.credentialRecord.state === CredentialState.RequestReceived) {
                agent.credentials.acceptRequest({credentialRecordId: payload.credentialRecord.id})
            }
        })

        /* Set up the listener for the proof requested */
        agent.events.on(ProofEventTypes.ProofStateChanged, async ({payload}) => {
            /* If the presentation of the credentials has been completed, we can show the credentials exchanged */
            if (payload.proofRecord.state === ProofState.Done) {
                let info = await agent.proofs.getById(payload.proofRecord.id)
                console.log(JSON.stringify(await agent.proofs.getFormatData(payload.proofRecord.id)))
                console.log(JSON.stringify(info))
            }
        });

    })
}

const express = require('express');
const {randomUUID} = require("crypto");
const domain = require("domain");
const {W3cIssuerOptions} = require("@credo-ts/core/build/modules/vc/models/credential/W3cIssuer");
const {SingleOrArray} = require("@credo-ts/core/build/utils");
const {JsonObject} = require("@credo-ts/core/build/types");
const vc_1 = require("@credo-ts/core/build/modules/vc");
const {W3cJsonLdCredentialService} = require("@credo-ts/core/build/modules/vc/data-integrity/W3cJsonLdCredentialService");

const app = express();
const PORT = 8080;
startEverything().then(result => {
    console.log("Here")
})
app.use(express.static('public'))
var bodyParser = require('body-parser');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.get('/', (req, res) => {
    res.status(200);
    //let url = `/index.html?user=${user}&application=${application}&vcissuer=${vcissuer}&nonce=${encodeURIComponent(nonce)}&domain=${domain}&redirect_uri=${redirect_uri}&code=${encodeURIComponent(code)}`;
    let url = 'index.html'
    res.redirect(url);
});

app.get('/generateInvitation', async (req, res) => {
    res.status(200);
    const outOfBandRecord = await agent.oob.createInvitation()
    console.log(outOfBandRecord);
    const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({domain: sys_config.get('wallet.endpoint')})
    let qrcode_png
        await QRCode.toDataURL(invitationUrl, {version: 22}).then(qrcode_generated => {
            qrcode_png = qrcode_generated
        })
        res.json({url: invitationUrl, connectionId: outOfBandRecord.id, qrcode: qrcode_png})
});


app.post('/requestUserCredential', async (req, res) => {
    res.status(200);

    console.log(req.body.challenge)
    /* To attach the listner only to the current connection, checks on outOfBandId field  */
    agent.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({payload}) => {
        if (payload.connectionRecord.state === DidExchangeState.Completed && payload.connectionRecord.outOfBandId === req.body.connectionId) {
            await agent.basicMessages.sendMessage(payload.connectionRecord.id, "Hello, we can start to communicate")
            /* Start by sending a proof request, if we want to assess the identity */


            const proof_request = await agent.proofs.requestProof({
                protocolVersion: 'v2',
                connectionId: payload.connectionRecord.id,
                proofFormats: {
                    presentationExchange: {
                        presentationDefinition: {
                            "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                            "input_descriptors": [
                                {
                                    "id": "wa_driver_license",
                                    "name": "Washington State Business License",
                                    "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
                                    "constraints": {
                                        "fields": [
                                            {
                                                "path": [
                                                    "$.credentialSubject.alumniOf",
                                                    "$.credentialSubject.claims.alumniOf",
                                                ]
                                            }
                                        ]
                                    }
                                }
                            ],
                            "format": { // Which format we want for the signature? Currently, we are using ldp_vp
                                "ldp_vc": {
                                    "proof_type": [
                                        "JsonWebSignature2020",
                                        "Ed25519Signature2018",
                                        "EcdsaSecp256k1Signature2019",
                                        "RsaSignature2018"
                                    ]
                                },
                                "ldp_vp": {
                                    "proof_type": ["Ed25519Signature2018"]
                                },
                                "ldp": {
                                    "proof_type": ["RsaSignature2018"]
                                }
                            }
                        },
                        options: {
                            challenge: req.body.challenge,
                            domain: req.body.domain
                        }


                    }

                }
            });


            /* Set up the listener for the proof requested */
            agent.events.on(ProofEventTypes.ProofStateChanged, async ({payload}) => {
                /* If the presentation of the credentials has been completed, we can show the credentials exchanged */
                if (payload.proofRecord.state === ProofState.Done && proof_request.id === payload.proofRecord.id ) {
                    let entire_vp = await agent.proofs.getFormatData(payload.proofRecord.id)
                    res.send(JSON.stringify(entire_vp.presentation.presentationExchange))
                }
            });

        }
    })
})

app.listen(PORT, (error) => {
        if (!error)
            console.log("Server is Successfully Running, and App is listening on port " + PORT)
        else
            console.log("Error occurred, server can't start", error);
    }
);


function getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet) {
    const legacyIndyCredentialFormatService = new LegacyIndyCredentialFormatService()
    const legacyIndyProofFormatService = new LegacyIndyProofFormatService()

    return {
        connections: new ConnectionsModule({
            autoAcceptConnections: true,
        }),
        credentials: new CredentialsModule({
            autoAcceptCredentials: AutoAcceptCredential.Never,
            credentialProtocols: [
                new V1CredentialProtocol({
                    indyCredentialFormat: legacyIndyCredentialFormatService,
                }),
                new V2CredentialProtocol({
                    credentialFormats: [legacyIndyCredentialFormatService, new AnonCredsCredentialFormatService(), new DataIntegrityCredentialFormatService(), new JsonLdCredentialFormatService()],
                }),
            ],
        }),
        proofs: new ProofsModule({
            autoAcceptProofs: AutoAcceptProof.ContentApproved,
            proofProtocols: [
                new V1ProofProtocol({
                    indyProofFormat: legacyIndyProofFormatService,
                }),
                new V2ProofProtocol({
                    proofFormats: [legacyIndyProofFormatService, new AnonCredsProofFormatService(), new DifPresentationExchangeProofFormatService()],
                }),
            ],
        }),
        anoncreds: new AnonCredsModule({
            registries: [new IndyVdrAnonCredsRegistry()],
        }),
        indyVdr: new IndyVdrModule({
            indyVdr,
            networks: [{
                // Need unique network id as we will have multiple agent processes in the agent
                id: randomUUID(),
                genesisTransactions: genesisTransactionsBCovrinTestNet,
                indyNamespace: 'bcovrin:test',
                isProduction: false,
                connectOnStartup: true,
            }],
        }),
        dids: new DidsModule({
            resolvers: [new IndyVdrIndyDidResolver()],
        }),
        askar: new AskarModule({
            ariesAskar,
        }),
        w3cCredentials: new W3cCredentialsModule(),
    }
}
