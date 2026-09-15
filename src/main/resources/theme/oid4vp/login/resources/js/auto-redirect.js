// Auto-redirect to OIDC4VP identity provider
// This ensures users see the QR code immediately without clicking any button

document.addEventListener('DOMContentLoaded', function () {
  // Find the OIDC4VP provider link
  const oid4vpLink = document.getElementById('social-oid4vp');

  if (oid4vpLink) {
    // Show a brief "Redirecting..." message then redirect
    const content = document.getElementById('content');
    if (content) {
      content.innerHTML = `
                <div class="loading">
                    <div class="spinner"></div>
                    <p class="loading-text">Connecting to your wallet...</p>
                </div>
            `;
    }

    // Redirect after a short delay (1500ms) so user sees the branding
    setTimeout(function () {
      window.location.href = oid4vpLink.href;
    }, 1500);
  } else {
    // Fallback: If no OIDC4VP link found, show error
    console.error('OpenKYC: OIDC4VP identity provider not found');
    const content = document.getElementById('content');
    if (content) {
      content.innerHTML = `
                <div style="text-align: center; padding: 32px;">
                    <p style="color: #FF4D6A; font-size: 14px;">
                        Unable to connect to wallet service.<br>
                        Please try again or contact support.
                    </p>
                </div>
            `;
    }
  }
});

// Handle browser back button gracefully
window.addEventListener('pageshow', function (event) {
  if (event.persisted) {
    // Page was loaded from cache (user clicked back)
    // Reload to ensure fresh state
    window.location.reload();
  }
});
