/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
// Polls the cross-device status endpoint until the wallet completes the login on another device,
// then moves the browser to the completion URL. Each poll is a short, ordinary request.
(function() {
    var MAX_ERROR_DELAY_MS = 15000;

    function parseConfig(root) {
        if (!root) {
            return null;
        }
        var statusUrl = root.dataset.statusUrl || "";
        var requestHandle = root.dataset.requestHandle || "";
        if (!statusUrl || !requestHandle) {
            return null;
        }
        var pollIntervalMs = parseInt(root.dataset.pollIntervalMs || "", 10);
        return {
            statusUrl: statusUrl,
            requestHandle: requestHandle,
            pollIntervalMs: pollIntervalMs > 0 ? pollIntervalMs : 2000
        };
    }

    function initOid4vpCrossDeviceStatus(config) {
        if (!config || !config.statusUrl || !config.requestHandle) {
            return null;
        }

        var statusUrl = config.statusUrl + "?request_handle=" + encodeURIComponent(config.requestHandle);
        var stopped = false;
        var timer = null;
        var errorDelayMs = config.pollIntervalMs;

        window.__oid4vpCrossDeviceReady = false;

        function stop() {
            stopped = true;
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
        }

        function schedule(delayMs) {
            if (!stopped) {
                timer = setTimeout(poll, delayMs);
            }
        }

        function handleStatus(response) {
            if (response.status === 204) {
                // Unknown, expired, or foreign flow: nothing will ever complete here.
                stop();
                return null;
            }
            if (!response.ok) {
                throw new Error("HTTP " + response.status);
            }
            return response.json();
        }

        function poll() {
            if (stopped) {
                return;
            }
            fetch(statusUrl, {
                cache: "no-store",
                credentials: "same-origin",
                headers: { "Accept": "application/json" }
            })
                .then(handleStatus)
                .then(function(data) {
                    window.__oid4vpCrossDeviceReady = true;
                    if (!data || stopped) {
                        return;
                    }
                    errorDelayMs = config.pollIntervalMs;
                    if (data.status === "complete" && data.redirect_uri) {
                        stop();
                        window.location.href = data.redirect_uri;
                        return;
                    }
                    schedule(config.pollIntervalMs);
                })
                .catch(function() {
                    // Network or server error: keep trying, backing off so an outage is not hammered.
                    errorDelayMs = Math.min(errorDelayMs * 2, MAX_ERROR_DELAY_MS);
                    schedule(errorDelayMs);
                });
        }

        poll();

        return {
            close: stop
        };
    }

    window.initOid4vpCrossDeviceStatus = initOid4vpCrossDeviceStatus;

    var config = parseConfig(document.getElementById("oid4vp-cross-device-status-config"));
    if (config) {
        initOid4vpCrossDeviceStatus(config);
    }
})();
