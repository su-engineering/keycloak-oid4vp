<#macro registrationLayout displayMessage=true displayInfo=false displayRequiredFields=false>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${msg("loginTitle",realm.displayName)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
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
