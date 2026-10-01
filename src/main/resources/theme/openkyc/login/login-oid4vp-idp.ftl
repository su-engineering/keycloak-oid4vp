<#import "oid4vp-template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        <div class="openkyc-card__header">
            <svg class="openkyc-card__logo" viewBox="0 0 1080 1080" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <g transform="matrix(1,0,0,1,6,29)">
                    <path d="M686.443,292.864C641.85,264.123 589.904,248.833 536.851,248.833C385.371,248.833 260.722,373.482 260.722,524.962C260.722,676.442 385.371,801.091 536.851,801.091C688.331,801.091 812.98,676.442 812.98,524.962C812.98,506.077 811.042,487.241 807.198,468.751" style="fill:none;fill-rule:nonzero;stroke:rgb(0,212,170);stroke-width:94.34px;"/>
                </g>
                <path d="M686.443,292.864C641.85,264.123 589.904,248.833 536.851,248.833C385.371,248.833 260.722,373.482 260.722,524.962C260.722,676.442 385.371,801.091 536.851,801.091C688.331,801.091 812.98,676.442 812.98,524.962C812.98,506.077 811.042,487.241 807.198,468.751" style="fill:none;fill-rule:nonzero;stroke:white;stroke-width:94.34px;"/>
            </svg>

            <h1 id="okyc-page-title" class="openkyc-wordmark">
                <span class="openkyc-wordmark__open">open</span><span class="openkyc-wordmark__kyc">KYC</span>
            </h1>
            <span class="openkyc-visually-hidden">${msg("oid4vpLoginTitle")}</span>
        </div>
    <#elseif section = "form">
        <form id="oid4vpForm" action="${formActionUrl!''}" method="post">
            <input type="hidden" id="state" name="state" value="${state!''}"/>
            <input type="hidden" id="requestHandle" value="${requestHandle!''}"/>
            <input type="hidden" id="crossDeviceRequestHandle" value="${crossDeviceRequestHandle!''}"/>
            <input type="hidden" id="vp_token" name="vp_token"/>
            <input type="hidden" id="response" name="response"/>
            <input type="hidden" id="error" name="error"/>
            <input type="hidden" id="error_description" name="error_description"/>
        </form>

        <div class="openkyc-content">
            <section class="openkyc-requirement" aria-label="Required credential">
                <div class="openkyc-requirement__icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 3l7 3.6v5.4c0 4.7-3.1 9-7 10.9-3.9-1.9-7-6.2-7-10.9V6.6L12 3z"></path>
                        <path d="M8.5 11.5V9.8a3.5 3.5 0 0 1 7 0v1.7"></path>
                        <rect x="7" y="11" width="10" height="7" rx="2"></rect>
                    </svg>
                </div>
                <div class="openkyc-requirement__meta">
                    <span class="openkyc-requirement__eyebrow">${msg("oid4vpCredentialRequiredLabel")}</span>
                    <span class="openkyc-requirement__name">${msg("oid4vpCredentialRequiredValue")}</span>
                </div>
            </section>

            <a href="https://openkyc.org" target="_blank" rel="noopener noreferrer" class="openkyc-credential-link">
                <span class="openkyc-credential-link__icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 4h6v6"></path>
                        <path d="M10 14 20 4"></path>
                        <path d="M20 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h5"></path>
                    </svg>
                </span>
                <span>${msg("oid4vpGetCredentialPrompt")} <span class="openkyc-credential-link__target">${msg("oid4vpGetCredentialLink")}</span></span>
            </a>

            <#if (sameDeviceEnabled!false) && (sameDeviceWalletUrl!'')?has_content>
                <div class="openkyc-primary">
                    <a id="oid4vp-open-wallet" href="${sameDeviceWalletUrl!''}" class="openkyc-wallet-button">
                        <span class="openkyc-wallet-button__icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M3 7.5A2.5 2.5 0 0 1 5.5 5H18a2 2 0 0 1 2 2v2H5.5A2.5 2.5 0 0 1 3 6.5v1Z"></path>
                                <path d="M3 7v10a2 2 0 0 0 2 2h15V9H5a2 2 0 0 1-2-2Z"></path>
                                <path d="M16 13.5h3"></path>
                            </svg>
                        </span>
                        <span class="openkyc-wallet-button__text">${msg("oid4vpOpenWithOpenKYCApp")}</span>
                        <span class="openkyc-wallet-button__arrow" aria-hidden="true">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M5 12h14"></path>
                                <path d="M13 5l7 7-7 7"></path>
                            </svg>
                        </span>
                    </a>
                </div>
            </#if>

            <#if (crossDeviceEnabled!false) && (qrCodeBase64!'')?has_content>
                <a href="#" id="openkyc-qr-toggle" class="openkyc-qr-toggle" aria-expanded="false" aria-controls="qr-section">
                    ${msg("oid4vpShowQrToggle")}
                </a>
                <section class="openkyc-qr-section" id="qr-section" aria-label="Wallet QR code">
                    <div class="openkyc-qr-shell">
                        <div class="openkyc-qr-frame">
                            <img
                                id="oid4vp-qr-code"
                                src="data:image/png;base64,${qrCodeBase64!''}"
                                alt="${msg('oid4vpQrCodeAlt')}"
                                data-wallet-url="${crossDeviceWalletUrl!''}"
                                class="openkyc-qr-image"
                            />
                        </div>
                    </div>
                </section>
            </#if>

            <section class="openkyc-steps" aria-labelledby="openkyc-how-it-works-title">
                <h2 id="openkyc-how-it-works-title" class="openkyc-steps__title">${msg("oid4vpHowItWorks")}</h2>
                <ol class="openkyc-steps__list">
                    <li class="openkyc-step">
                        <span class="openkyc-step__marker" aria-hidden="true">1</span>
                        <div class="openkyc-step__body">
                            <h3 class="openkyc-step__heading">${msg("oid4vpStepOneTitle")}</h3>
                            <p class="openkyc-step__description">${msg("oid4vpStepOneDescription")}</p>
                        </div>
                    </li>
                    <li class="openkyc-step">
                        <span class="openkyc-step__marker" aria-hidden="true">2</span>
                        <div class="openkyc-step__body">
                            <h3 class="openkyc-step__heading">${msg("oid4vpStepTwoTitle")}</h3>
                            <p class="openkyc-step__description">${msg("oid4vpStepTwoDescription")}</p>
                        </div>
                    </li>
                    <li class="openkyc-step">
                        <span class="openkyc-step__marker" aria-hidden="true">3</span>
                        <div class="openkyc-step__body">
                            <h3 class="openkyc-step__heading">${msg("oid4vpStepThreeTitle")}</h3>
                            <p class="openkyc-step__description">${msg("oid4vpStepThreeDescription")}</p>
                        </div>
                    </li>
                </ol>
            </section>

            <#assign hasAlternativeProvider = false>
            <#if social.providers?? && social.providers?size gt 0>
                <#list social.providers as p>
                    <#if p.alias != (currentBrokerAlias!'')>
                        <#assign hasAlternativeProvider = true>
                        <#break>
                    </#if>
                </#list>
            </#if>

            <#if hasAlternativeProvider>
                <section class="openkyc-alt" aria-label="Alternative sign in methods">
                    <p class="openkyc-alt__label">${msg("oid4vpAlternativeMethods")}</p>
                    <div class="openkyc-alt__list">
                        <#list social.providers as p>
                            <#if p.alias != (currentBrokerAlias!'')>
                                <a href="${p.loginUrl}" id="social-${p.alias}" class="openkyc-alt__link">${p.displayName!}</a>
                            </#if>
                        </#list>
                    </div>
                </section>
            </#if>
        </div>

        <#if (crossDeviceStatusUrl!'')?has_content && (crossDeviceEnabled!false)>
            <div
                id="oid4vp-cross-device-status-config"
                data-status-url="${crossDeviceStatusUrl!''}"
                data-request-handle="${crossDeviceRequestHandle!''}"
                data-poll-interval-ms="${(crossDevicePollIntervalMs!2000)?c}"
                hidden
            ></div>
            <script nonce="${cspNonce!}" src="${url.resourcesPath}/js/oid4vp-cross-device-status.js"></script>
        </#if>
    </#if>
</@layout.registrationLayout>
