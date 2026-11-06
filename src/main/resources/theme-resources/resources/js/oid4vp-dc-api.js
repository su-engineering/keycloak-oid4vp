/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
// Signs in with a wallet in this browser through the W3C Digital Credentials API
// (OpenID4VP 1.0 Appendix A, and ISO/IEC 18013-7 Annex C for mdoc).
// The button stays hidden in browsers without the API.
(function() {
    function parseConfig(root) {
        if (!root) {
            return null;
        }
        var data = root.dataset;
        if (!data.requestUrl || !data.responseUrl || !data.requestHandle) {
            return null;
        }
        return {
            requestUrl: data.requestUrl,
            responseUrl: data.responseUrl,
            requestHandle: data.requestHandle,
            cancelledMessage: data.cancelledMessage || "",
            errorMessage: data.errorMessage || ""
        };
    }

    function isSupported() {
        return typeof window.DigitalCredential === "function"
            && !!navigator.credentials
            && typeof navigator.credentials.get === "function";
    }

    function post(url, params) {
        return fetch(url, {
            method: "POST",
            cache: "no-store",
            credentials: "same-origin",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams(params).toString()
        }).then(function(response) {
            return response.json()
                .catch(function() { return {}; })
                .then(function(body) { return { ok: response.ok, body: body || {} }; });
        });
    }

    function failure(body) {
        var error = new Error((body && (body.error_description || body.error)) || "request failed");
        error.name = "Oid4vpDcApiError";
        return error;
    }

    function initOid4vpDcApi(config) {
        var section = document.getElementById("oid4vp-dc-api");
        var button = document.getElementById("oid4vp-dc-api-button");
        var status = document.getElementById("oid4vp-dc-api-status");
        if (!config || !button || !isSupported()) {
            return null;
        }
        if (section) {
            section.hidden = false;
        }
        button.hidden = false;

        var busy = false;

        function setStatus(message) {
            if (status) {
                status.textContent = message || "";
                status.hidden = !message;
            }
        }

        function present() {
            return post(config.requestUrl, { request_handle: config.requestHandle }).then(function(created) {
                if (!created.ok || !Array.isArray(created.body.requests) || !created.body.requests.length) {
                    throw failure(created.body);
                }
                var request = created.body;
                // One request per protocol (OpenID4VP, and ISO mdoc when the query allows it);
                // the browser and wallet choose which one to answer.
                return navigator.credentials.get({
                    mediation: "required",
                    digital: { requests: request.requests }
                }).then(function(credential) {
                    if (!credential || credential.data === undefined || credential.data === null) {
                        throw failure({ error: "no_credential" });
                    }
                    var data = typeof credential.data === "string" ? credential.data : JSON.stringify(credential.data);
                    return post(config.responseUrl, {
                        request_handle: config.requestHandle,
                        state: request.state,
                        protocol: credential.protocol || "",
                        response: data
                    });
                });
            }).then(function(result) {
                if (result.body.redirect_uri) {
                    window.location.href = result.body.redirect_uri;
                    return;
                }
                throw failure(result.body);
            });
        }

        button.addEventListener("click", function(event) {
            event.preventDefault();
            if (busy) {
                return;
            }
            busy = true;
            button.disabled = true;
            setStatus("");
            present().catch(function(error) {
                busy = false;
                button.disabled = false;
                // The user closing the browser dialog rejects with AbortError or NotAllowedError.
                var cancelled = error && (error.name === "AbortError" || error.name === "NotAllowedError");
                setStatus(cancelled ? config.cancelledMessage : config.errorMessage);
            });
        });

        return { present: present };
    }

    window.initOid4vpDcApi = initOid4vpDcApi;
    initOid4vpDcApi(parseConfig(document.getElementById("oid4vp-dc-api-config")));
})();
