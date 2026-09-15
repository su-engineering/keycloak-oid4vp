<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "header">
        <div class="card-header">
            <h2 class="card-title">Connect Your Wallet</h2>
            <p class="card-description">Use your OpenKYC wallet to verify your identity securely.</p>
        </div>

    <#elseif section = "form">
        <#if identityProviders??>
            <div id="kc-social-providers" class="identity-providers">
                <#list identityProviders as idp>
                    <#if idp.alias == "oid4vp">
                        <a id="social-${idp.alias}" class="wallet-button" href="${idp.loginUrl}">
                            <svg class="wallet-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M20 12V8H6a2 2 0 0 1-2-2c0-1.1.9-2 2-2h12v4"/>
                                <path d="M4 6v12a2 2 0 0 0 2 2h14v-4"/>
                                <path d="M18 12a2 2 0 0 0-2 2 2 2 0 0 0 2 2 2 2 0 0 0 2-2 2 2 0 0 0-2-2"/>
                            </svg>
                            <span>Sign in with Wallet</span>
                        </a>
                    </#if>
                </#list>
            </div>
        </#if>

        <div class="info-section">
            <h3 class="info-title">
                <svg class="info-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <path d="M12 16v-4M12 8h.01"/>
                </svg>
                What happens next
            </h3>
            <ol class="steps">
                <li>Click the button above to open your wallet</li>
                <li>Scan the QR code with your OpenKYC wallet app</li>
                <li>Select your AgeOverEighteenCredential</li>
                <li>Confirm to complete verification</li>
            </ol>
        </div>

        <div class="security-badge">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
            </svg>
            <span>W3C Verifiable Credentials • Zero data exposure</span>
        </div>
    </#if>
</@layout.registrationLayout>
