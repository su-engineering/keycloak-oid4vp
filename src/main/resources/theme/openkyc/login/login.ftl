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

        <#-- Keycloak supplies provider URLs bound to this authentication session. -->
        <div class="form-options">
            <#if social?? && social.providers?has_content>
                <#list social.providers as provider>
                    <a id="social-${provider.alias}" href="${provider.loginUrl}" class="primary-button">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="3" width="18" height="18" rx="2"/>
                            <path d="M3 9h18"/>
                        </svg>
                        <span>${provider.displayName!}</span>
                    </a>
                </#list>
            </#if>
        </div>

    </#if>
</@layout.registrationLayout>
