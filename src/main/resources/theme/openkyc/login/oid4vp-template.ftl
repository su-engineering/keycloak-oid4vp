<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false>
<!DOCTYPE html>
<html class="${properties.kcHtmlClass!}" lang="${lang}"<#if realm.internationalizationEnabled> dir="${(locale.rtl)?then('rtl','ltr')}"</#if>>
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="color-scheme" content="dark light">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <#if properties.meta?has_content>
        <#list properties.meta?split(' ') as meta>
            <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
        </#list>
    </#if>
    <title>${msg("loginTitle",(realm.displayName!''))}</title>
    <link rel="icon" href="${url.resourcesPath}/img/favicon.ico" />
    <link rel="stylesheet" href="${url.resourcesPath}/css/oid4vp-fonts.css">
    <style>
        :root {
            --color-midnight: #0D0C2B;
            --color-surface: #1A1847;
            --color-border: #2D2A6E;
            --color-sovereign: #12107C;
            --color-sovereign-500: #1A18A0;
            --color-cipher: #00D4AA;
            --color-credit: #FFB800;
            --color-alert: #FF4D6A;
            --color-mist: #B8BADB;
            --color-vault-white: #F7F8FF;
            --shadow-card: 0 24px 64px rgba(0, 0, 0, 0.5);
            --motion-standard: 200ms cubic-bezier(0.4, 0, 0.2, 1);
            --motion-enter: 400ms cubic-bezier(0, 0, 0.2, 1);
            --space-1: 4px;
            --space-2: 8px;
            --space-3: 12px;
            --space-4: 16px;
            --space-6: 24px;
            --space-8: 32px;
            --space-10: 40px;
            --space-12: 48px;
            --radius-button: 10px;
            --radius-panel: 16px;
            --radius-pill: 9999px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html,
        body {
            min-height: 100%;
        }

        body.openkyc-page {
            min-height: 100vh;
            font-family: 'Inter', sans-serif;
            background:
                radial-gradient(circle at 18% 16%, rgba(18, 16, 124, 0.08) 0, rgba(18, 16, 124, 0) 44%),
                radial-gradient(circle at 82% 84%, rgba(0, 212, 170, 0.04) 0, rgba(0, 212, 170, 0) 38%),
                var(--color-midnight);
            color: var(--color-vault-white);
            position: relative;
            overflow-x: hidden;
        }

        body.openkyc-page::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image: radial-gradient(circle, rgba(247, 248, 255, 0.03) 1px, transparent 1px);
            background-size: 28px 28px;
            opacity: 0.45;
            pointer-events: none;
            z-index: 0;
        }

        .openkyc-shell {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: var(--space-8) var(--space-4) var(--space-6);
            position: relative;
            z-index: 1;
        }

        .openkyc-shell__inner {
            width: min(100%, 460px);
            display: grid;
            gap: var(--space-4);
        }

        .openkyc-toolbar {
            display: flex;
            justify-content: flex-end;
        }

        .openkyc-locale {
            appearance: none;
            -webkit-appearance: none;
            width: auto;
            min-width: 112px;
            padding: 10px 36px 10px 12px;
            border-radius: 8px;
            border: 1px solid rgba(45, 42, 110, 0.9);
            background:
                linear-gradient(180deg, rgba(26, 24, 71, 0.92), rgba(13, 12, 43, 0.96)) no-repeat,
                var(--color-surface);
            color: var(--color-mist);
            font: 500 12px/1 'Inter', sans-serif;
            background-image:
                linear-gradient(180deg, rgba(26, 24, 71, 0.92), rgba(13, 12, 43, 0.96)),
                url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6' fill='none'%3E%3Cpath d='M1 1L5 5L9 1' stroke='%23B8BADB' stroke-width='1.25' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
            background-position: center, right 12px center;
            background-size: cover, 10px 6px;
            background-repeat: no-repeat;
            transition: border-color var(--motion-standard), box-shadow var(--motion-standard), color var(--motion-standard);
        }

        .openkyc-locale:hover,
        .openkyc-locale:focus-visible {
            outline: none;
            color: var(--color-vault-white);
            border-color: rgba(0, 212, 170, 0.45);
            box-shadow: 0 0 0 3px rgba(0, 212, 170, 0.12);
        }

        .openkyc-card {
            width: 100%;
            max-width: 460px;
            padding: 40px 48px;
            border-radius: 20px;
            border: 1px solid var(--color-border);
            background: rgba(26, 24, 71, 0.94);
            box-shadow: var(--shadow-card);
            backdrop-filter: blur(18px);
            opacity: 1;
            transform: translateY(0);
            transition: all var(--motion-standard);
        }

        @keyframes card-enter {
            from {
                opacity: 0;
                transform: translateY(12px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @media (prefers-reduced-motion: no-preference) {
            body:not(.page-ready) .openkyc-card {
                opacity: 0;
                transform: translateY(12px);
            }
            
            body.page-ready .openkyc-card {
                animation: card-enter var(--motion-enter) cubic-bezier(0, 0, 0.2, 1) 100ms forwards;
            }
        }

        .openkyc-card__header {
            display: grid;
            justify-items: center;
            gap: var(--space-2);
            padding-bottom: var(--space-6);
            margin-bottom: var(--space-6);
            border-bottom: 1px solid var(--color-border);
            text-align: center;
        }

        .openkyc-card__logo {
            width: auto;
            height: 88px;
            display: block;
        }

        .openkyc-wordmark {
            display: inline-flex;
            align-items: baseline;
            gap: 2px;
            font-size: 28px;
            line-height: 1.05;
            letter-spacing: -0.04em;
        }

        .openkyc-wordmark__open {
            color: var(--color-mist);
            font-family: 'Inter', sans-serif;
            font-weight: 400;
        }

        .openkyc-wordmark__kyc {
            color: var(--color-vault-white);
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-weight: 700;
        }

        .openkyc-tagline {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: var(--color-mist);
            font: 400 13px/1.4 'Inter', sans-serif;
        }

        .openkyc-tagline::before {
            content: '';
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--color-cipher);
            flex: 0 0 auto;
        }

        .openkyc-alert {
            display: grid;
            gap: 6px;
            padding: 14px 16px;
            border-radius: 10px;
            border: 1px solid rgba(255, 77, 106, 0.24);
            background: rgba(255, 77, 106, 0.08);
            margin-bottom: var(--space-6);
        }

        .openkyc-alert--warning {
            border-color: rgba(255, 77, 106, 0.18);
            background: rgba(255, 77, 106, 0.05);
        }

        .openkyc-alert__label {
            color: var(--color-alert);
            font: 400 11px/1.4 'JetBrains Mono', monospace;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .openkyc-alert__text {
            color: var(--color-vault-white);
            font: 500 13px/1.5 'Inter', sans-serif;
        }

        .openkyc-content {
            display: grid;
            gap: var(--space-6);
        }

        .openkyc-requirement {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 12px;
            align-items: center;
            padding: 14px 16px;
            border-radius: 10px;
            border: 1px solid var(--color-border);
            background: rgba(18, 16, 124, 0.3);
        }

        .openkyc-requirement__icon {
            width: 32px;
            height: 32px;
            display: grid;
            place-items: center;
            border-radius: 10px;
            background: rgba(0, 212, 170, 0.08);
            color: var(--color-cipher);
        }

        .openkyc-requirement__icon svg {
            width: 18px;
            height: 18px;
        }

        .openkyc-requirement__meta {
            display: grid;
            gap: 4px;
            min-width: 0;
        }

        .openkyc-requirement__eyebrow {
            font: 400 11px/1.3 'JetBrains Mono', monospace;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--color-mist);
        }

        .openkyc-requirement__name {
            font: 600 13px/1.4 'Inter', sans-serif;
            color: var(--color-vault-white);
            word-break: break-word;
        }

        .openkyc-primary {
            display: grid;
            gap: var(--space-3);
        }

        .openkyc-wallet-button {
            display: flex;
            align-items: center;
            gap: 12px;
            width: 100%;
            min-height: 52px;
            padding: 14px 16px;
            border-radius: 10px;
            border: 1px solid rgba(0, 212, 170, 0.14);
            background: linear-gradient(90deg, #12107C 0%, #1A18A0 100%);
            color: var(--color-vault-white);
            text-decoration: none;
            transition: all var(--motion-standard);
            position: relative;
        }

        .openkyc-wallet-button:hover,
        .openkyc-wallet-button:focus-visible {
            outline: none;
            background: linear-gradient(90deg, #1A18A0 0%, #1A18A0 100%);
            box-shadow: 0 0 0 3px rgba(0, 212, 170, 0.25);
            transform: translateY(-1px);
        }

        .openkyc-wallet-button__icon,
        .openkyc-wallet-button__arrow {
            color: var(--color-cipher);
            flex: 0 0 auto;
        }

        .openkyc-wallet-button__icon svg,
        .openkyc-wallet-button__arrow svg {
            width: 20px;
            height: 20px;
        }

        .openkyc-wallet-button__text {
            flex: 1 1 auto;
            font: 600 15px/1.3 'Plus Jakarta Sans', sans-serif;
            color: var(--color-vault-white);
        }

        .openkyc-credential-link {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            width: 100%;
            color: var(--color-mist);
            text-decoration: none;
            font: 400 13px/1.5 'Inter', sans-serif;
            transition: color var(--motion-standard);
        }

        .openkyc-credential-link:hover,
        .openkyc-credential-link:focus-visible {
            outline: none;
            color: var(--color-vault-white);
        }

        .openkyc-credential-link:hover .openkyc-credential-link__target,
        .openkyc-credential-link:focus-visible .openkyc-credential-link__target {
            text-decoration: underline;
            text-underline-offset: 3px;
        }

        .openkyc-credential-link__icon {
            color: var(--color-cipher);
            flex: 0 0 auto;
        }

        .openkyc-credential-link__icon svg {
            width: 16px;
            height: 16px;
        }

        .openkyc-credential-link__target {
            color: var(--color-cipher);
            font-weight: 500;
        }

        .openkyc-divider {
            display: flex;
            align-items: center;
            gap: 12px;
            color: var(--color-mist);
            font: 400 12px/1.4 'Inter', sans-serif;
            text-transform: none;
        }

        .openkyc-divider::before,
        .openkyc-divider::after {
            content: '';
            height: 1px;
            flex: 1 1 auto;
            background: var(--color-border);
        }

        .openkyc-qr-section {
            display: grid;
            gap: 12px;
            justify-items: center;
        }

        .openkyc-qr-shell {
            position: relative;
            width: 100%;
            max-width: 248px;
            padding: 16px;
            border-radius: 16px;
            border: 1.5px solid var(--color-border);
            background: var(--color-midnight);
        }

        .openkyc-qr-shell::before,
        .openkyc-qr-shell::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            border: 2px solid var(--color-cipher);
            opacity: 0.9;
            animation: qr-pulse 3s ease-in-out infinite;
        }

        .openkyc-qr-shell::before {
            top: 10px;
            left: 10px;
            border-right: 0;
            border-bottom: 0;
            border-radius: 10px 0 0 0;
        }

        .openkyc-qr-shell::after {
            right: 10px;
            bottom: 10px;
            border-top: 0;
            border-left: 0;
            border-radius: 0 0 10px 0;
        }

        @keyframes qr-pulse {
            0%, 100% {
                opacity: 1;
                transform: scale(1);
            }
            50% {
                opacity: 0.6;
                transform: scale(1.04);
            }
        }

        .openkyc-qr-frame {
            display: grid;
            place-items: center;
            width: 100%;
            background: #fff;
            border-radius: 12px;
            overflow: hidden;
        }

        .openkyc-qr-image {
            display: block;
            width: 100%;
            height: auto;
            aspect-ratio: 1;
            object-fit: contain;
        }

        .openkyc-qr-caption {
            text-align: center;
            color: var(--color-mist);
            font: 400 12px/1.5 'Inter', sans-serif;
        }

        .openkyc-qr-toggle {
            display: none;
            text-align: center;
            color: var(--color-mist);
            font: 400 13px/1.5 'Inter', sans-serif;
            text-decoration: none;
            padding: 8px;
            border-radius: 8px;
            transition: all var(--motion-standard);
        }

        .openkyc-qr-toggle:hover {
            color: var(--color-cipher);
            background: rgba(0, 212, 170, 0.08);
        }

        .openkyc-qr-toggle:focus-visible {
            outline: none;
            box-shadow: 0 0 0 2px rgba(0, 212, 170, 0.4);
        }

        @media (max-width: 540px) {
            .openkyc-qr-toggle {
                display: block;
            }

            .openkyc-qr-section {
                display: none;
            }

            .openkyc-qr-section.openkyc-qr-section--visible {
                display: grid;
            }
        }

        .openkyc-steps {
            display: grid;
            gap: 16px;
        }

        .openkyc-steps__title {
            color: var(--color-mist);
            font: 600 12px/1.4 'Inter', sans-serif;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .openkyc-steps__list {
            list-style: none;
            display: grid;
            gap: 16px;
        }

        .openkyc-step {
            display: grid;
            grid-template-columns: 28px 1fr;
            gap: 12px;
            align-items: start;
            opacity: 1;
            transform: translateY(0);
        }

        @keyframes fade-step {
            from {
                opacity: 0;
                transform: translateY(8px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @media (prefers-reduced-motion: no-preference) {
            body:not(.page-ready) .openkyc-step {
                opacity: 0;
                transform: translateY(8px);
            }

            body.page-ready .openkyc-step {
                animation: fade-step 320ms cubic-bezier(0.4, 0, 0.2, 1) forwards;
            }

            body.page-ready .openkyc-step:nth-child(1) { animation-delay: 220ms; }
            body.page-ready .openkyc-step:nth-child(2) { animation-delay: 320ms; }
            body.page-ready .openkyc-step:nth-child(3) { animation-delay: 420ms; }
        }

        .openkyc-step__marker {
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            border: 1px solid rgba(0, 212, 170, 0.3);
            background: rgba(0, 212, 170, 0.1);
            color: var(--color-cipher);
            font: 700 12px/1 'Plus Jakarta Sans', sans-serif;
        }

        .openkyc-step:not(:last-child) .openkyc-step__marker::after {
            content: '';
            position: absolute;
            top: calc(100% + 6px);
            left: 50%;
            width: 1px;
            height: calc(100% + 10px);
            transform: translateX(-50%);
            background-image: linear-gradient(var(--color-border) 50%, rgba(0, 0, 0, 0) 0%);
            background-size: 1px 6px;
            background-repeat: repeat-y;
        }

        .openkyc-step__body {
            display: grid;
            gap: 4px;
            padding-top: 3px;
        }

        .openkyc-step__heading {
            color: var(--color-vault-white);
            font: 600 14px/1.4 'Inter', sans-serif;
        }

        .openkyc-step__description {
            color: var(--color-mist);
            font: 400 12px/1.5 'Inter', sans-serif;
        }

        .openkyc-alt {
            display: grid;
            gap: 12px;
            padding-top: 4px;
        }

        .openkyc-alt__label {
            color: var(--color-mist);
            font: 400 12px/1.4 'Inter', sans-serif;
            text-align: center;
        }

        .openkyc-alt__list {
            display: grid;
            gap: 8px;
        }

        .openkyc-alt__link {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 44px;
            padding: 12px 14px;
            border-radius: 8px;
            border: 1px solid rgba(45, 42, 110, 0.9);
            background: rgba(13, 12, 43, 0.48);
            color: var(--color-vault-white);
            font: 500 13px/1.4 'Inter', sans-serif;
            text-decoration: none;
            transition: all var(--motion-standard);
        }

        .openkyc-alt__link:hover,
        .openkyc-alt__link:focus-visible {
            outline: none;
            border-color: rgba(0, 212, 170, 0.4);
            background: rgba(18, 16, 124, 0.24);
            color: var(--color-vault-white);
        }

        .openkyc-footer {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            text-align: center;
            color: rgba(184, 186, 219, 0.5);
            font: 400 11px/1.5 'Inter', sans-serif;
        }

        .openkyc-footer svg {
            width: 14px;
            height: 14px;
            color: currentColor;
            flex: 0 0 auto;
        }

        .openkyc-visually-hidden {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            border: 0;
            white-space: nowrap;
        }

        @media (max-width: 540px) {
            .openkyc-shell {
                padding: 16px;
            }

            .openkyc-card {
                max-width: 100%;
                padding: 24px 20px;
            }

            .openkyc-card__header {
                padding-bottom: 20px;
                margin-bottom: 20px;
            }

            .openkyc-wordmark {
                font-size: 24px;
            }

            .openkyc-wallet-button {
                min-height: 52px;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation: none !important;
                transition-duration: 0ms !important;
                scroll-behavior: auto !important;
            }
        }
    </style>
    <script nonce="${cspNonce!}" src="${url.resourcesPath}/js/oid4vp-template.js" type="text/javascript"></script>
    <#if properties.scripts?has_content>
        <#list properties.scripts?split(' ') as script>
            <script nonce="${cspNonce!}" src="${url.resourcesPath}/${script}" type="text/javascript"></script>
        </#list>
    </#if>
    <#if scripts??>
        <#list scripts as script>
            <script nonce="${cspNonce!}" src="${script}" type="text/javascript"></script>
        </#list>
    </#if>
    <script nonce="${cspNonce!}">
        (function() {
            function initQrToggle() {
                var toggle = document.getElementById('openkyc-qr-toggle');
                var qrSection = document.getElementById('qr-section');
                
                if (!toggle || !qrSection) {
                    return;
                }
                
                toggle.addEventListener('click', function(e) {
                    e.preventDefault();
                    var isExpanded = toggle.getAttribute('aria-expanded') === 'true';
                    toggle.setAttribute('aria-expanded', !isExpanded);
                    qrSection.classList.toggle('openkyc-qr-section--visible');
                });
            }
            
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', initQrToggle);
            } else {
                initQrToggle();
            }
        })();
    </script>
</head>
<body id="keycloak-bg" class="openkyc-page ${bodyClass}" data-page-id="login-${pageId}">
    <div class="openkyc-shell">
        <div class="openkyc-shell__inner">
            <#if realm.internationalizationEnabled && locale.supported?size gt 1>
                <div class="openkyc-toolbar">
                    <label class="openkyc-visually-hidden" for="login-select-toggle">${msg("languages")}</label>
                    <select aria-label="${msg('languages')}" id="login-select-toggle" class="openkyc-locale">
                        <#list locale.supported?sort_by("label") as l>
                            <option value="${l.url}" ${(l.languageTag == locale.currentLanguageTag)?then('selected','')}>${l.label}</option>
                        </#list>
                    </select>
                </div>
            </#if>

            <main class="openkyc-card" aria-labelledby="okyc-page-title">
                <#nested "header">

                <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
                    <div class="openkyc-alert openkyc-alert--${message.type}">
                        <span class="openkyc-alert__label">${message.type?upper_case}</span>
                        <span class="openkyc-alert__text">${message.summary}</span>
                    </div>
                </#if>

                <#nested "form">
            </main>

            <div class="openkyc-footer" aria-label="OpenKYC trust footer">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M12 3l7 3.6v5.4c0 4.7-3.1 9-7 10.9-3.9-1.9-7-6.2-7-10.9V6.6L12 3z"></path>
                    <path d="M9.3 12.3l1.9 1.9 3.8-3.9"></path>
                </svg>
                <span>${msg("oid4vpFooterTrust", "Secured by OpenKYC · Privacy by Design")}</span>
            </div>
        </div>
    </div>
</body>
</html>
</#macro>
