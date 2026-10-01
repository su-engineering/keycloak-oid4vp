<#macro registrationLayout displayMessage=true displayInfo=false displayRequiredFields=false>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${msg("loginTitle",realm.displayName)}</title>
    <link rel="stylesheet" href="${url.resourcesPath}/css/oid4vp-fonts.css">
    <link rel="stylesheet" href="${url.resourcesPath}/css/styles.css">
</head>
<body>
    <div class="container">
        <#if displayMessage && message?has_content>
            <div class="alert alert-${message.type}">
                <#if message.type = 'success'><span class="icon">✓</span></#if>
                <#if message.type = 'warning'><span class="icon">⚠</span></#if>
                <#if message.type = 'error'><span class="icon">✕</span></#if>
                <#if message.type = 'info'><span class="icon">ℹ</span></#if>
                <span class="message-text">${message.summary}</span>
            </div>
        </#if>

        <div class="card">
            <#nested "header">
            <#nested "form">
        </div>
        
        <#if displayInfo>
            <#nested "info">
        </#if>
        
        <div class="footer">
            <p class="footer-text">
                Powered by <a href="https://openkyc.org" class="footer-link">OpenKYC</a> • Secure Identity Verification
            </p>
        </div>
    </div>
</body>
</html>
</#macro>
