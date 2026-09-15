<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=message?has_content displayInfo=displayInfo!false; section>
    <#if section = "header">
        <div class="card-header">
            <h1 class="app-title">Sign In</h1>
            <p class="app-subtitle">Verify your identity with OpenKYC</p>
        </div>
    <#elseif section = "form">
        <#if message?has_content>
            <div class="alert alert-${message.type}">${message.summary}</div>
        </#if>
        
        <#-- Direct link to OID4VP broker endpoint -->
        <#assign brokerUrl = url.loginAction?keep_before("/login-actions") + "/broker/oid4vp/login">
        <div class="form-options">
            <a id="social-oid4vp" href="${brokerUrl}" class="primary-button">
                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="3" width="18" height="18" rx="2"/>
                    <path d="M3 9h18"/>
                </svg>
                <span>Sign in with Wallet</span>
            </a>
        </div>
        
    </#if>
</@layout.registrationLayout>
