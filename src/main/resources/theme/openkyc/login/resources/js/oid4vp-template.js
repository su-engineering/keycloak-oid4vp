(function() {
    function initLocaleSelector() {
        var localeSelect = document.getElementById("login-select-toggle");
        if (!localeSelect) {
            return;
        }

        localeSelect.addEventListener("change", function() {
            if (localeSelect.value) {
                window.location.href = localeSelect.value;
            }
        });
    }

    function initPageTransition() {
        var body = document.body;
        if (!body || body.className.indexOf("openkyc-page") === -1) {
            return;
        }

        window.requestAnimationFrame(function() {
            window.requestAnimationFrame(function() {
                body.classList.add("page-ready");
            });
        });
    }

    function init() {
        initLocaleSelector();
        initPageTransition();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();
