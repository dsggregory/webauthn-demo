let regid = undefined

function checkUserRegistrationCeremony() {
    // the regid is generated when a user is provisioned by another admin user and is only intended for registering an admin user
    const urlParams = new URLSearchParams(window.location.search);
    const qp = urlParams.get('regid');
    if (qp !== null) {
        regid = qp
    }
}

function registerUser() {

    username = $("#username").val()
    if (username === "") {
        var elem = document.getElementById("error");
        elem.textContent = "please enter a username";
        return;
    }

    let state = "register.begin";

    let query = ""
    if (regid !== undefined) {
        query="?regid=" + regid
    }
    $.get(
        '/register/begin/' + username + query,
        null,
        function (data) {
            return data
        },
        'json')
        .then((credentialCreationOptions) => {
            state = "register.options.challenge"
            credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
            state = "register.options.userID"
            credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
            state = "register.options.excludeCredentials"
            if (credentialCreationOptions.publicKey.excludeCredentials) {
                for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
                    credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
                }
            }

            state = "register.options.create"
            return navigator.credentials.create({
                publicKey: credentialCreationOptions.publicKey
            })
        })
        .then((credential) => {
            state = "register.credential.finish"
            let attestationObject = credential.response.attestationObject;
            let clientDataJSON = credential.response.clientDataJSON;
            let rawId = credential.rawId;

            $.post(
                '/register/finish/' + username,
                JSON.stringify({
                    id: credential.id,
                    rawId: bufferEncode(rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bufferEncode(attestationObject),
                        clientDataJSON: bufferEncode(clientDataJSON),
                    },
                }),
                function (data) {
                    return data
                },
                'json')
                .fail(function (response) {
                    console.log(response.responseText);
                    var elem = document.getElementById("error")
                    elem.textContent = response.responseText;
                })
                .then((success) => {
                    var elem = document.getElementById("error")
                    elem.textContent = "Successfully registered " + username + "! You may now login."
                })
        })
        .catch((error) => {
            console.log(error);
            var elem = document.getElementById("error");
            elem.textContent = "failed to register " + username + " state: " + state + " Error: " + error;
        })
}

// Base64 to ArrayBuffer
function bufferDecode(value) {
    let s = window.atob(value.replace(/-/g, '+').replace(/_/g, '/'))
    let bytes = Uint8Array.from(s, c => c.charCodeAt(0))
    return bytes.buffer
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
    let s = String.fromCharCode.apply(null, new Uint8Array(value))
    return window.btoa(s).replace(/\+/g, '-').replace(/\//g, '_');
}

function loginUser() {

    username = $("#username").val()
    if (username === "") {
        var elem = document.getElementById("error")
        elem.textContent = "please enter a username";
        return;
    }

    $.get(
        '/login/begin/' + username,
        null,
        function (data) {
            return data
        },
        'json')
        .then((credentialRequestOptions) => {
            credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
            credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
                listItem.id = bufferDecode(listItem.id)
            });

            return navigator.credentials.get({
                publicKey: credentialRequestOptions.publicKey
            })
        })
        .then((assertion) => {
            let authData = assertion.response.authenticatorData;
            let clientDataJSON = assertion.response.clientDataJSON;
            let rawId = assertion.rawId;
            let sig = assertion.response.signature;
            let userHandle = assertion.response.userHandle;

            $.post(
                '/login/finish/' + username,
                JSON.stringify({
                    id: assertion.id,
                    rawId: bufferEncode(rawId),
                    type: assertion.type,
                    response: {
                        authenticatorData: bufferEncode(authData),
                        clientDataJSON: bufferEncode(clientDataJSON),
                        signature: bufferEncode(sig),
                        userHandle: bufferEncode(userHandle),
                    },
                }),
                function (data) {
                    // data is response body, not the response itself
                    return data
                },
                'json')
                .then((success) => {
                    //alert("successfully logged in " + username + "!")
                    window.location = "/dashboard";
                })
                .catch((error) => {
                    console.log(error)
                    var elem = document.getElementById("error")
                    elem.textContent = "login failed " + username
                })
        })
        .catch((error) => {
            console.log(error)
            var elem = document.getElementById("error")
            elem.textContent = "login failed " + username
        })
}

function getAuthenticationOptions() {
    let p, resp
    try {
        p = $.get('/discoverable/begin',
        null,
        function (data) {
            resp = data
            return resp
        },
        'json')
        .then((success) => {
            let credentialCreationOptions = resp
            credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
            return credentialCreationOptions.publicKey
        })
        .catch((error) => {
            console.log("getAuthenticationOptions: " + error)
        })
    } catch (e) {
        console.log("discover begin error")
    }
    return p
}
function verifyAutoFillResponse(resp) {
    let credAssertion;
    credAssertion = $.extend(credAssertion, resp);
    let js = JSON.stringify({
        authenticatorAttachment: credAssertion.authenticatorAttachment,
        id: credAssertion.id,
        rawId: bufferEncode(credAssertion.rawId),
        type: credAssertion.type,
        response: credAssertion.response,
        response: {
            authenticatorData: bufferEncode(credAssertion.response.authenticatorData),
            clientDataJSON: bufferEncode(credAssertion.response.clientDataJSON),
            signature: bufferEncode(credAssertion.response.signature),
            userHandle: bufferEncode(credAssertion.response.userHandle),
        },
    });
    return $.post('/discoverable/finish',
        js,
        function (data) {
            return data
        },
        'json')
        .then((success) => {
            return
        })
        .fail(function (response) {
            console.log(response.responseText);
            var elem = document.getElementById("error")
            elem.textContent = response.responseText;
        });
}

/* Autofill UI (e.g. discoverable credentials) for passkeys. Requires `autocomplete="username webauthn"` on text element.
 */
async function autofillUI() {
    if (
        typeof window.PublicKeyCredential !== 'undefined'
        && typeof window.PublicKeyCredential.isConditionalMediationAvailable === 'function'
    ) {
        const available = await PublicKeyCredential.isConditionalMediationAvailable();

        if (available) {
            try {
                // TODO: Retrieve authentication options for `navigator.credentials.get()`
                // from your server.
                const authOptions = await getAuthenticationOptions();
                // This call to `navigator.credentials.get()` is "set and forget."
                // The Promise will only resolve if the user successfully interacts
                // with the browser's autofill UI to select a passkey.
                const webAuthnResponse = await navigator.credentials.get({
                    mediation: "conditional",
                    publicKey: {
                        ...authOptions,
                        // see note about userVerification below
                        userVerification: "preferred",
                    }
                });
                // TODO Send the response to your server for verification and
                // authenticate the user if the response is valid.
                await verifyAutoFillResponse(webAuthnResponse);
                window.location = "/dashboard";
            } catch (err) {
                console.error('Error with conditional UI:', err);
            }
        }
    }
}
