<#import "oid4vp-template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "form">
        <form id="oid4vpForm" action="${formActionUrl!''}" method="post">
            <input type="hidden" id="state" name="state" value="${state!''}">
            <input type="hidden" id="requestHandle" value="${requestHandle!''}">
            <input type="hidden" id="crossDeviceRequestHandle" value="${crossDeviceRequestHandle!''}">
            <input type="hidden" id="vp_token" name="vp_token">
            <input type="hidden" id="response" name="response">
            <input type="hidden" id="error" name="error">
            <input type="hidden" id="error_description" name="error_description">
        </form>
        <#assign showWallet = (sameDeviceEnabled!false) && (sameDeviceWalletUrl!'')?has_content>
        <#assign showQr = (crossDeviceEnabled!false) && (qrCodeBase64!'')?has_content>
        <div class="su-wallet-grid<#if !showQr> su-wallet-grid--single</#if>">
            <section class="su-intro" aria-labelledby="su-page-title">
                <h1 id="su-page-title">${msg("suWalletTitle")}</h1>
                <p class="su-lead"><#if showWallet && showQr>${msg("suWalletDescription")}<#elseif showWallet>${msg("suWalletDescriptionSameDevice")}<#elseif showQr>${msg("suWalletDescriptionCrossDevice")}<#else>${msg("suWalletDescriptionUnavailable")}</#if></p>
                <#if showWallet>
                    <a id="oid4vp-open-wallet" class="su-button" href="${sameDeviceWalletUrl}">
                        <span>${msg("suOpenWallet")}</span>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M4 12h15M13 5l7 7-7 7"/></svg>
                    </a>
                    <p class="su-hint">${msg("suSameDeviceHint")}</p>
                </#if>
                <div class="su-review">
                    <h2>${msg("suReviewTitle")}</h2>
                    <p>${msg("suReviewDescription")}</p>
                </div>
                <#if !showWallet && !showQr>
                    <div class="su-alert" role="alert">${msg("suUnavailable")}</div>
                </#if>
            </section>
            <#if showQr>
                <section class="su-qr-panel" aria-labelledby="su-qr-title">
                    <h2 id="su-qr-title">${msg("suQrTitle")}</h2>
                    <p>${msg("suQrDescription")}</p>
                    <div class="su-qr-frame">
                        <img id="oid4vp-qr-code" width="240" height="240"
                             src="data:image/png;base64,${qrCodeBase64}"
                             alt="${msg('suQrAlt')}" data-wallet-url="${crossDeviceWalletUrl!''}">
                    </div>
                    <p class="su-qr-caption">${msg("suContinueAutomatically")}</p>
                    <noscript><p class="su-alert">${msg("suJavascriptRequired")}</p></noscript>
                </section>
            </#if>
        </div>
        <#assign hasAlternativeProvider = false>
        <#if social.providers??>
            <#list social.providers as p>
                <#if p.alias != (currentBrokerAlias!'')>
                    <#assign hasAlternativeProvider = true>
                    <#break>
                </#if>
            </#list>
        </#if>
        <#if hasAlternativeProvider>
            <nav class="su-alternatives" aria-label="${msg('suAlternativeMethods')}">
                <p>${msg("suAlternativeMethods")}</p>
                <#list social.providers as p>
                    <#if p.alias != (currentBrokerAlias!'')>
                        <a id="social-${p.alias}" href="${p.loginUrl}">${p.displayName!}</a>
                    </#if>
                </#list>
            </nav>
        </#if>
        <#if (crossDeviceStatusUrl!'')?has_content && (crossDeviceEnabled!false)>
            <div id="oid4vp-cross-device-status-config" hidden
                 data-status-url="${crossDeviceStatusUrl}"
                 data-request-handle="${crossDeviceRequestHandle!''}"
                 data-poll-interval-ms="${(crossDevicePollIntervalMs!2000)?c}"></div>
            <#-- Shared extension resource: keep completion behavior identical across themes. -->
            <script nonce="${cspNonce!}" src="${url.resourcesPath}/js/oid4vp-cross-device-status.js"></script>
        </#if>
    </#if>
</@layout.registrationLayout>
