<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        <div class="card-header">
            <h2 class="card-title">Scan QR Code</h2>
            <p class="card-description">Use your OpenKYC wallet app to scan this QR code and verify your identity.</p>
        </div>

    <#elseif section = "form">
        <div class="qr-container">
            <#if qrCode??>
                <img src="${qrCode}" alt="Scan with your wallet" class="qr-code"/>
            <#else>
                <div class="qr-placeholder">
                    <div class="spinner"></div>
                    <p>Generating QR code...</p>
                </div>
            </#if>
        </div>

        <div class="same-device-option">
            <p class="divider"><span>or</span></p>
            <#if sameDeviceUrl??>
                <a href="${sameDeviceUrl}" class="btn-secondary">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="5" y="2" width="14" height="20" rx="2" ry="2"/>
                        <line x1="12" y1="18" x2="12" y2="18"/>
                    </svg>
                    Open in Wallet App
                </a>
            </#if>
        </div>

        <div class="info-section">
            <h3 class="info-title">
                <svg class="info-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <path d="M12 16v-4M12 8h.01"/>
                </svg>
                How to verify
            </h3>
            <ol class="steps">
                <li>Open your OpenKYC wallet app</li>
                <li>Tap "Scan" and point at the QR code</li>
                <li>Select your AgeOverEighteenCredential</li>
                <li>Tap "Present" to verify</li>
            </ol>
        </div>

        <div class="security-badge">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
            </svg>
            <span>W3C Verifiable Credentials • End-to-end encrypted</span>
        </div>
    </#if>
</@layout.registrationLayout>
