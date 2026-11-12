/* nginx-auth WebAuthn client. No inline handlers, no dialogs. */
(function () {
    'use strict';

    var body = document.body;
    var authUrl = body.getAttribute('data-auth-url');
    var csrf = body.getAttribute('data-csrf');
    var mode = body.getAttribute('data-mode');
    var contextId = body.getAttribute('data-ctx');

    function toBuffer(value) {
        var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        var binary = atob(base64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function toBase64Url(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function decodeDescriptors(list) {
        return (list || []).map(function (descriptor) {
            var copy = Object.assign({}, descriptor);
            copy.id = toBuffer(descriptor.id);
            return copy;
        });
    }

    function decodeOptions(publicKey) {
        var options = Object.assign({}, publicKey);
        options.challenge = toBuffer(publicKey.challenge);
        if (publicKey.user) {
            options.user = Object.assign({}, publicKey.user, {id: toBuffer(publicKey.user.id)});
        }
        if (publicKey.excludeCredentials) {
            options.excludeCredentials = decodeDescriptors(publicKey.excludeCredentials);
        }
        if (publicKey.allowCredentials) {
            options.allowCredentials = decodeDescriptors(publicKey.allowCredentials);
        }
        return options;
    }

    function encodeCredential(credential) {
        var response = credential.response;
        var out = {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            type: credential.type,
            response: {clientDataJSON: toBase64Url(response.clientDataJSON)},
            clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
        };
        if (credential.authenticatorAttachment) {
            out.authenticatorAttachment = credential.authenticatorAttachment;
        }
        if (response.attestationObject) {
            out.response.attestationObject = toBase64Url(response.attestationObject);
            out.response.transports = response.getTransports ? response.getTransports() : [];
        } else {
            out.response.authenticatorData = toBase64Url(response.authenticatorData);
            out.response.signature = toBase64Url(response.signature);
            if (response.userHandle) {
                out.response.userHandle = toBase64Url(response.userHandle);
            }
        }
        return out;
    }

    function post(action, payload) {
        return fetch(authUrl + '/webauthn/' + action, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
            body: JSON.stringify(payload)
        }).then(function (response) {
            return response.json().catch(function () {
                return {ok: false, error: 'Unexpected server response'};
            });
        }).then(function (result) {
            if (!result.ok) {
                throw new Error(result.error || 'Request failed');
            }
            return result;
        });
    }

    function show(id, text) {
        var element = document.getElementById(id);
        if (!element) {
            return;
        }
        element.textContent = text || '';
        element.hidden = !text;
    }

    function keyName() {
        var input = document.getElementById('key-name');
        return input ? input.value : '';
    }

    function ceremony(step) {
        var options = decodeOptions(step.publicKey);
        var pending = step.type === 'create'
            ? navigator.credentials.create({publicKey: options})
            : navigator.credentials.get({publicKey: options});
        return pending.then(function (credential) {
            if (!credential) {
                throw new Error('No security key response');
            }
            return post('finish', {
                transactionId: step.transactionId,
                purpose: step.purpose,
                credential: encodeCredential(credential),
                name: keyName()
            });
        }).then(function (result) {
            if (result.ceremony) {
                show('webauthn-status', step.type === 'get' ? 'Confirmed. Now use the new security key.' : '');
                return ceremony(result.ceremony);
            }
            return result;
        });
    }

    function run(payload, button) {
        if (!window.PublicKeyCredential || !navigator.credentials) {
            show('webauthn-error', 'This browser does not support security keys.');
            return;
        }
        show('webauthn-error', '');
        show('webauthn-status', '');
        if (button) {
            button.disabled = true;
        }
        post('start', payload).then(function (result) {
            return ceremony(result.ceremony);
        }).then(function (result) {
            if (result.message) {
                show('webauthn-status', result.message);
            }
            if (result.redirect) {
                window.location.assign(result.redirect);
            }
        }).catch(function (error) {
            var message = error && error.name === 'NotAllowedError'
                ? 'The operation was cancelled or timed out. Press the button to try again.'
                : (error && error.message) || 'Security key operation failed';
            show('webauthn-error', message);
        }).then(function () {
            if (button) {
                button.disabled = false;
            }
        });
    }

    var start = document.getElementById('webauthn-start');
    if (start) {
        var payload = {purpose: mode === 'step_up' ? 'step_up' : mode, contextId: contextId || null};
        start.addEventListener('click', function () {
            run(payload, start);
        });
        if (mode === 'login' || mode === 'step_up') {
            run(payload, start);
        }
    }

    var register = document.getElementById('webauthn-register');
    if (register) {
        register.addEventListener('click', function () {
            run({purpose: 'register'}, register);
        });
    }

    Array.prototype.forEach.call(document.querySelectorAll('[data-remove]'), function (button) {
        button.addEventListener('click', function () {
            var confirmLast = document.getElementById('confirm-last');
            run({
                purpose: 'delete_credential',
                credentialId: button.getAttribute('data-remove'),
                confirmLast: !!(confirmLast && confirmLast.checked)
            }, button);
        });
    });
})();
