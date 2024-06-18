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
    JsonTransformer, W3cCredentialService, WebDidResolver, DidDocumentService, ConnectionService, DidCommV1Service,
    ConsoleLogger, LogLevel, RoutingService, HandshakeProtocol, MediationRecipientService, MediatorPickupStrategy,
    MediationRecipientModule, MediatorService, MediatorModule, OutOfBandEventTypes, PeerDidNumAlgo, ClaimFormat,
    CREDENTIALS_CONTEXT_V1_URL, WRAPPER_VP_CONTEXT_URL, W3cPresentationRequest
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

const prompt = require('prompt-sync')();
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
        logger: new ConsoleLogger(LogLevel.debug)
    }

    // A new instance of an agent is created here
    const agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet)
    })

    // Register a simple `WebSocket` outbound transport - not needed
    agent.registerOutboundTransport(new WsOutboundTransport())

    // Register a simple `Http` outbound transport
    agent.registerOutboundTransport(new HttpOutboundTransport())

    // Register a simple `Http` inbound transport
    agent.registerInboundTransport(new HttpInboundTransport({port: 3010}))


    // Initialize the agent
    await agent.initialize()


    const did = `did:web:secureapp.solidcommunity.net:public`
    try {
        // Try to create the key for the wallet, if it already exists then jump these instructions
        const ed25519Key = await agent.wallet.createKey({
            keyType: KeyType.Ed25519,
            privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
        })

        const builder = new DidDocumentBuilder(did)
        const ed25519VerificationMethod2018 = getEd25519VerificationKey2018({
            key: ed25519Key,
            id: `${did}#${ed25519Key.fingerprint}`,
            controller: did,
        })

        builder.addService(new DidCommV1Service({
            "id": "#inline-0",
            "serviceEndpoint": sys_config.get('wallet.endpoint'),
            "type": "did-communication",
            "recipientKeys": [`${did}#${ed25519Key.fingerprint}`],
            "routingKeys": [`${did}#${ed25519Key.fingerprint}`]
        }));


        builder.addVerificationMethod(ed25519VerificationMethod2018)
        builder.addAuthentication(ed25519VerificationMethod2018.id)
        builder.addAssertionMethod(ed25519VerificationMethod2018.id)
        console.log(JSON.stringify(builder.build()));

        await agent.dids.create({
            method: 'web',
            didDocument: builder.build(),
            options: {
                keyType: KeyType.Ed25519,
                privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
            }
        })
    } catch (e) {
        let didResp = await agent.dids.resolve(did);
        let u = await agent.dids.resolveDidDocument(did)

        await agent.dids.import({
            did,
            didDocument: didResp.didDocument,
            overwrite: true,
            options: {
                keyType: KeyType.Ed25519,
                privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
            }
        })
        let created_dids = await agent.dids.getCreatedDids({method: 'web'});
        console.log("This is the App Wallet, it has this DID: " + created_dids[0].did);

    }


    return agent
}

let agent

async function startEverything() {
    agent = await initializeIssuerAgent(sys_config.get('wallet.ledger_url'), sys_config.get('wallet.endpoint'));
    //await activateListener(agent, false, true)
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
    /* Empty */
})
app.use(express.static('public'))
var bodyParser = require('body-parser');
const OutOfBandEvents_1 = require("@credo-ts/core/build/modules/oob/domain/OutOfBandEvents");

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
    let med = await agent.mediationRecipient.getRouting();

    const outOfBandRecord = await agent.oob.createInvitation({
        autoAcceptConnection: true,
        handshake: true,
        invitationDid: "did:web:secureapp.solidcommunity.net:public",
    })

    //const outOfBandRecord = await agent.oob.createInvitation();

    //console.log(JSON.stringify(outOfBandRecord, undefined, 2));
    //let url_invitation = prompt("Insert the invitation URL to begin a communication: ")
    //await setuplistener(agent);
    //await agent.oob.receiveInvitationFromUrl(url_invitation, {
    //    handshake: true,

    //    ourDid: 'did:web:secureapp.solidcommunity.net:public'
    //})
    //await agent.oob.receiveInvitationFromUrl(url_invitation)
    // Dovremmo creare un DIDDocument per il nuovo did, per evitare di fare questo allora si fa uso di did:peer che incorpora tutto.

    const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({domain: sys_config.get('wallet.endpoint')})
    let qrcode_png
    await QRCode.toDataURL(invitationUrl, {version: 22}).then(qrcode_generated => {
        qrcode_png = qrcode_generated
    })
    res.json({url: invitationUrl, connectionId: outOfBandRecord.id, qrcode: qrcode_png})
});

async function ourListener(payload, req, res) {

    if (payload.connectionRecord.state === DidExchangeState.Completed) {
        console.log(JSON.stringify(payload));
        //console.log(await agent.connections.rotate({connectionId: payload.connectionRecord.id}));
        await agent.basicMessages.sendMessage(payload.connectionRecord.id, "Hello, we can start to communicate")
        /* Start by sending a proof request, if we want to assess the identity */
        /* todo: get my_did from created did */
        let my_did = "did:key:z6Mkw4VsQTL36g5t4AA27M38ZgpEJE6ESas468vhZNhZJqjA";
        /* TODO: Insert a field in the VPR that identify the application, by modifying PEX library */

        /* MAYBE_TODO: By now we have a list of authorized did from the holder, but in the future implementation we may have a protocol for exchanging app DID and add new dids to the list */

        /* Check if the request contains a proof field, if yes we have to create a wrapper rather than the simple request */

        /* We have to improve here, it is possible that we only sign the request, as well as only the ACP Context, as well as wrap it*/
        if (req.body.vpr === undefined) {
            const proof_request = await agent.proofs.requestProof({
                protocolVersion: 'v2',
                connectionId: payload.connectionRecord.id,
                proofFormats: {
                    presentationExchange: {
                        type: ["VerifiablePresentationRequest"],
                        '@context': ["https://bboi.solidcommunity.net/public/schemas/2024/presexchange.jsonld"],
                        presentationDefinition: {
                            "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                            "input_descriptors": JSON.parse(req.body.input_descriptors),
                            "format": { // Which format we want for the signature? Currently, we are using ldp_vp
                                "ldp_vc": {
                                    "proof_type": [
                                        "JsonWebSignature2020",
                                        "Ed25519Signature2018",
                                    ]
                                },
                                "ldp_vp": {
                                    "proof_type": ["Ed25519Signature2018"]
                                },
                            },
                            "requestACP": {
                                "type": ["ACPContext"],
                                "target": req.body.target,
                                "agent": req.body.agent,
                                "creator": req.body.creator,
                                "owner": req.body.owner,
                                "client": req.body.client,
                                "issuer": req.body.issuer
                            }
                        },
                        options: {
                            challenge: req.body.challenge,
                            domain: req.body.domain,
                        },
                        signPresentationRequest: true,
                    }

                }
            });
        } else {
            let vpr_obj = JSON.parse(req.body.vpr)
            let wrapperVPR = new W3cPresentationRequest(vpr_obj)
            let wrapped_VPR = await agent.w3cCredentials.createPresentationRequestWrapper({
                id: "https://example.com/wrappedVPR/321122",
                vpr: wrapperVPR,
                termsAndCondition: wrapperVPR.presentation_definition.requestACP,
            })
            let wrappedVPRSigned = await agent.w3cCredentials.signWrappedPresentationRequest(
                {
                    wrappedVPR: wrapped_VPR,
                    proofType: 'Ed25519Signature2018',
                    verificationMethod: 'did:web:secureapp.solidcommunity.net:public#z6Mkg4kRxcfvWfqTV86RdBKHjTks5thJe7R4xsGTs5zASrB7',
                }
            )
            /* Send it to the user */
            await agent.proofs.requestWrappedProof({
                protocolVersion: 'v2',
                connectionId: payload.connectionRecord.id,
                requestWrapper: wrappedVPRSigned,
                proofFormats: {
                    presentationExchange: {
                        // Empty, it is just for interop and to say that we want DifExchange
                    }
                }
            })

        }

        /* Set up the listener for the proof requested */
        agent.events.on(ProofEventTypes.ProofStateChanged, async ({payload}) => {

            console.log(payload);
            /* If the presentation of the credentials has been completed, we can show the credentials exchanged */
            if (payload.proofRecord.state === ProofState.Done) {
                if (payload.proofRecord.isVerified === true) {
                    /* We are sure that the presentation has been signed and contains the same challenge and we can now produce a new VP containing our singature or maybe not*/
                    let entire_vp = await agent.proofs.getFormatData(payload.proofRecord.id)

                    const presentationParsed = JsonTransformer.fromJSON(entire_vp.presentation.presentationExchange, W3cJsonLdVerifiablePresentation);
                    let wrapPresentation = true;
                    let presentationToSend = presentationParsed
                    if (wrapPresentation) {
                        let wrappedVP = await agent.w3cCredentials.createPresentationWrapper({
                            id: "https://example.com/wrappedVP/321122",
                            vp: presentationParsed
                        })
                        presentationToSend = await agent.w3cCredentials.signWrappedPresentation({
                            presentation: wrappedVP,
                            format: ClaimFormat.LdpVp,
                            verificationMethod: 'did:web:secureapp.solidcommunity.net:public#z6Mkg4kRxcfvWfqTV86RdBKHjTks5thJe7R4xsGTs5zASrB7',
                            challenge: presentationParsed.proof.challenge,
                            domain: presentationParsed.proof.domain,
                            proofType: "Ed25519Signature2018",
                        })
                    }

                    res.json(presentationToSend)
                    //console.log(JSON.stringify(entire_vp.presentation))
                    agent.events.off(ProofEventTypes.ProofStateChanged, () => {
                    });
                    agent.events.off(ConnectionEventTypes.ConnectionStateChanged, () => {
                    });
                }
            }
        });

    }
}

app.post('/requestUserCredential', async (req, res) => {
    res.status(200);


    /* Is the domain what we want for the request (VPR)? */
    /* To attach the listner only to the current connection, checks on outOfBandId field  */
    /*agent.events.on(OutOfBandEventTypes.HandshakeReused, async ({payload}) => {
            await agent.connections.rotate({connectionId: payload.connectionRecord.id})
    });*/

    agent.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({payload}) => {
        await ourListener(payload, req, res);
    });
    agent.events.on(OutOfBandEventTypes.HandshakeReused, async ({payload}) => {
        //await ourListener(payload, req, res);
    });

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
    /* Il problema della */
    return {
        connections: new ConnectionsModule({
            autoAcceptConnections: true,
            peerNumAlgoForDidRotation: PeerDidNumAlgo.GenesisDoc,
            peerNumAlgoForDidExchangeRequests: PeerDidNumAlgo.GenesisDoc
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
            resolvers: [new IndyVdrIndyDidResolver(), new WebDidResolver()],
        }),
        askar: new AskarModule({
            ariesAskar,
        }),
        w3cCredentials: new W3cCredentialsModule(),
    }
}
