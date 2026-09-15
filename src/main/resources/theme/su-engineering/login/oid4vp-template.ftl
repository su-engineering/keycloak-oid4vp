<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false>
<!DOCTYPE html>
<html lang="${lang}"<#if realm.internationalizationEnabled> dir="${(locale.rtl)?then('rtl','ltr')}"</#if>>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <title>${msg("suWalletTitle")} · ${realm.displayName!realm.name}</title>
    <link rel="stylesheet" href="${url.resourcesPath}/css/su-engineering.css">
</head>
<body class="su-wallet-page ${bodyClass}">
    <a class="su-skip-link" href="#su-main">${msg("suSkipToContent")}</a>
    <div class="su-shell">
        <header class="su-masthead">
            <span class="su-wordmark">su.engineering</span>
            <span class="su-realm">${realm.displayName!realm.name}</span>
        </header>
        <main id="su-main" class="su-main">
            <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
                <div class="su-alert su-alert--${message.type}" role="alert">${kcSanitize(message.summary)?no_esc}</div>
            </#if>
            <#nested "form">
        </main>
        <footer class="su-footer">
            <span>${msg("suFooter")}</span>
            <#if (url.loginRestartFlowUrl!'')?has_content>
                <a href="${url.loginRestartFlowUrl}">${msg("suRestart")}</a>
            </#if>
        </footer>
    </div>
</body>
</html>
</#macro>
