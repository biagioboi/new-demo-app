const searchBar = document.querySelector('#searchBar');
const getBtn = document.querySelector('#getBtn');
const responseArea = document.querySelector('#responseArea');
let appName;
let user;
let issuer;

//VP may be in the URL parameters after redirecting from User to App
let params = new URLSearchParams(location.search);

getBtn.onclick = function () {

    user = "did:web:bboi.solidcommunity.net:public";
    issuer = "did:web:secureissuer.solidcommunity.net:public";
    appName = "did:web:secureapp.solidcommunity.net:public";

    //Send requests following protocol
    VcBasedrequests();
    //Send requests following protocol - without user input and measure average time taken
    //speedTests(500);
};

async function VcBasedrequests() {
    let url = searchBar.value;
    //If we have a VP and just arrived from a redirect, use it to send a request for the resource from CSS server
    if (params.get("vp")) {
        let VP = params.get("vp");
        console.log('Sending request for the resource with a VP...');
        let resource = await requestWithVP(url, VP);
        console.log(resource);
        responseArea.innerHTML = resource;
        //Otherwise, send first request and follow protocol to acquire VP
    } else {
        console.log("Sending first request for the resource...");
        //Message containing the app, issuer and user, requesting the resource at the url entered in the input box
        let response = await fetch(url, {
            method: "POST",
            headers: {
                'vc': 'true'//So the server's VcHttpHandler component handles it
            },
            body: JSON.stringify({
                'VPCompliant': false,
                'agent': user,
                'client': appName,
                'issuer': issuer,
            })
        });
        let result = await response.json();
        console.log(result);
        responseArea.innerHTML = syntaxHighlight(JSON.stringify(result, null, 2));
        let VPrequest = result;

        let obj_new_request;
        if (VPrequest.VerifiablePresentation !== undefined) { // Classical, no agent used
            obj_new_request = {
                challenge: VPrequest.VerifiablePresentation.challenge,
                domain: VPrequest.VerifiablePresentation.domain,
                owner: VPrequest.VerifiablePresentation.query.credentialQuery.owner.id,
                issuer: VPrequest.VerifiablePresentation.query.credentialQuery.issuer.id,
                creator: VPrequest.VerifiablePresentation.query.credentialQuery.creator.id,
                client: VPrequest.VerifiablePresentation.query.credentialQuery.client.id,
                agent: VPrequest.VerifiablePresentation.query.credentialQuery.agent.id
            }
        } else {
            obj_new_request = {
                challenge: VPrequest.options.challenge,
                domain: VPrequest.options.domain,
                target: VPrequest.presentation_definition.requestACP.target,
                owner: VPrequest.presentation_definition.requestACP.owner,
                issuer: VPrequest.presentation_definition.requestACP.issuer,
                creator: VPrequest.presentation_definition.requestACP.creator,
                client: VPrequest.presentation_definition.requestACP.client,
                agent: VPrequest.presentation_definition.requestACP.agent,
                input_descriptors: JSON.stringify(VPrequest.presentation_definition.input_descriptors)
            }
            if (VPrequest.type[0] === "VerifiablePresentationRequest") {
                // It is signed, so, we have almost all the fields, except for the new proof field
                obj_new_request.vpr = JSON.stringify(VPrequest)
            }
        }
        console.log(obj_new_request);
        $(".label-loader").html("Copy the code and accept the request on your mobile phone").fadeIn();
        $(".loader").fadeIn();
        if (url === obj_new_request.target) {
            //Send request to User to acquire VP (after 1 second delay)
            window.setTimeout(async () => {
                let connectionId;
                $.ajax({
                    method: "GET",
                    url: "http://localhost:8080/generateInvitation",
                    success: async function (data) {
                        obj_new_request.connectionId = data.connectionId;
                        $("#invitation").html(data.url)
                        $("#invitation").append("<img src=\"" + data.qrcode + "\">");
                        $.ajax({
                            method: "POST",
                            url: "http://localhost:8080/requestUserCredential",
                            data: obj_new_request,
                            success: async function (data) {
                                $("#invitation").html("");
                                $(".label-loader").css("display", "none").html("Proof accepted, sending the request to the server").fadeIn();
                                $(".loader").css("display", "none").addClass("loader-almost-load").fadeIn();
                                $("#responseVP").html(syntaxHighlight(JSON.stringify(data, undefined, 2)));
                                let resource = await requestWithVP(url, JSON.stringify(data));
                                responseArea.innerHTML = resource;
                                window.setTimeout(() => {
                                    $(".loader-loaded").css("display", "none")
                                }, 500);
                            }
                        })
                    }
                })
            }, 1000);
        } else {
            alert("Server is not sending the right domain, they don't match.");
        }
    }
}

//Sends request to User app and ask for a VP
//Gets redirected to User HTML page and should return to App with VP
async function getVP(nonce, domain) {
    console.log("Sending request to the User app...");
    let url = 'http://localhost:8081/vprequest';
    let response = await fetch(url, {
        redirect: "follow",
        method: "POST",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            user: user,
            application: appName,
            vcissuer: issuer,
            nonce: nonce,
            domain: domain,
            redirect_uri: window.location.href
        })
    });
    if (response.url !== undefined) {
        window.location = response.url;
    } else {
        console.log('Redirect URI not included in response.');
        return;
    }
}

async function requestWithVP(url, vpJwt) {
    let msg = {
        method: "GET",
        headers: {
            'vp': vpJwt,
            'Cache-Control': 'no-cache'
        }
    }
    let response2 = await fetch(url, msg);
    console.log(`Sent second request: ${JSON.stringify(msg)}`);

    $(".label-loader").css("display", "none").html("Server accepted the proof, showing the content").fadeIn();
    $(".loader-almost-load").css("display", "none").addClass("loader-loaded").fadeIn();
    let res = await response2.text();
    return res;
}

//full protocol from start to finish
async function speedTest() {
    let startTime = performance.now();
    //console.log(`Start Time: ${startTime}`);

    let url = searchBar.value;
    //Send first request and follow protocol to acquire VP
    //console.log("Sending first request for the resource...");
    //Message containing the app, issuer and user, requesting the resource at the url entered in the input box
    let response = await fetch(url, {
        method: "POST",
        headers: {
            'vc': 'true'//So the server's VcHttpHandler component handles it
        },
        body: JSON.stringify({
            'user': user,
            'app': appName,
            'vcissuer': issuer,
        })
    });
    let result = await response.json();
    responseArea.innerHTML = JSON.stringify(result);
    let VPrequest = result;
    let nonce = undefined;
    let domain = undefined;
    try {
        nonce = VPrequest.VerifiablePresentation.challenge;
        domain = VPrequest.VerifiablePresentation.domain;
    } catch (e) {
        console.log("No nonce or domain received in response");
        return;
    }
    //Send request to User to acquire VP
    console.log("Sending request to the User app...");
    let uri = 'http://localhost:8081/vprequest_speed_test';
    let res = await fetch(uri, {
        method: "POST",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            user: user,
            application: appName,
            vcissuer: issuer,
            nonce: nonce,
            domain: domain,
        })
    });

    //Request resource with VP
    let VP = await res.text();
    //console.log(VP);
    //console.log('Sending request for the resource with a VP...');
    let resource = await requestWithVP(url, VP);
    //console.log(resource);
    responseArea.innerHTML = resource;
    let endTime = performance.now();
    //console.log(`End Time: ${endTime}`);
    let timeTaken = endTime - startTime;
    //console.log(`Time Taken: ${timeTaken} milliseconds`);
    return timeTaken;
}

async function speedTests(sampleSize) {
    console.log(`Sending ${sampleSize} requests using VC-based protocol...`)
    let i = 1;
    let totalTime = 0;
    while (i <= sampleSize) {
        console.log(`Request ${i}:`);
        totalTime += await speedTest();
        i++;
    }
    let averageTime = totalTime / sampleSize;
    console.log(`Average Time: ${averageTime}`);
}

function syntaxHighlight(json) {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        var cls = 'number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'key';
            } else {
                cls = 'string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'boolean';
        } else if (/null/.test(match)) {
            cls = 'null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}
