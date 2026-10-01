<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - OpenKYC</title>
    <link rel="stylesheet" href="${url.resourcesPath}/css/oid4vp-fonts.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', sans-serif;
            background: #0D0C2B;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #F7F8FF;
            padding: 24px;
        }
        .container { width: 100%; max-width: 480px; }
        .brand-header { text-align: center; margin-bottom: 32px; }
        .logo { width: 64px; height: 64px; margin: 0 auto 16px; }
        .brand-title { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 28px; font-weight: 700; color: #F7F8FF; margin-bottom: 8px; }
        .brand-title span { color: #00D4AA; }
        .brand-subtitle { font-size: 16px; color: #B8BADB; }
        .card { background: #1A1847; border: 1px solid #2D2A6E; border-radius: 16px; padding: 32px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
        .error-header { text-align: center; margin-bottom: 24px; }
        .error-icon { width: 64px; height: 64px; margin: 0 auto 16px; color: #FF4D6A; }
        .card-title { font-family: 'Plus Jakarta Sans', sans-serif; font-size: 22px; font-weight: 700; color: #F7F8FF; margin-bottom: 8px; }
        .card-description { font-size: 14px; color: #B8BADB; }
        .error-message { background: rgba(255, 77, 106, 0.1); border: 1px solid rgba(255, 77, 106, 0.2); border-radius: 8px; padding: 16px; margin-bottom: 24px; }
        .error-label { font-size: 12px; font-weight: 600; color: #FF4D6A; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 8px; }
        .error-text { font-size: 14px; color: #fca5a5; font-family: 'JetBrains Mono', monospace; word-break: break-word; }
        .error-help { margin-bottom: 24px; }
        .error-help p { font-size: 14px; color: #B8BADB; margin-bottom: 12px; }
        .error-help ul { list-style: none; padding: 0; margin: 0; }
        .error-help li { font-size: 13px; color: #B8BADB; padding-left: 20px; position: relative; margin-bottom: 8px; }
        .error-help li::before { content: "•"; color: #00D4AA; position: absolute; left: 0; }
        .error-actions { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }
        .btn-primary { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 14px 24px; background: linear-gradient(135deg, #12107C 0%, #100E5C 100%); border: 2px solid #00D4AA; border-radius: 8px; color: #F7F8FF; font-family: 'Inter', sans-serif; font-size: 14px; font-weight: 600; text-decoration: none; cursor: pointer; transition: all 200ms; }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 0 15px rgba(0, 212, 170, 0.3); }
        .btn-secondary { display: flex; align-items: center; justify-content: center; padding: 14px 24px; background: transparent; border: 1px solid #2D2A6E; border-radius: 8px; color: #B8BADB; font-family: 'Inter', sans-serif; font-size: 14px; font-weight: 500; text-decoration: none; cursor: pointer; transition: all 200ms; }
        .btn-secondary:hover { background: rgba(255, 255, 255, 0.05); border-color: #00D4AA; color: #F7F8FF; }
        .error-support { text-align: center; padding-top: 16px; border-top: 1px solid #2D2A6E; }
        .error-support p { font-size: 13px; color: #B8BADB; margin: 0; }
        .error-support a { color: #00D4AA; text-decoration: none; font-weight: 500; }
        .footer { text-align: center; margin-top: 32px; }
        .footer-text { font-size: 12px; color: #B8BADB; }
        .footer-link { color: #00D4AA; text-decoration: none; font-weight: 500; }
        @media (max-width: 480px) { .card { padding: 24px; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="brand-header">
            <div class="logo">
                <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="32" cy="32" r="30" stroke="#00D4AA" stroke-width="2" fill="none"/>
                    <circle cx="32" cy="32" r="4" fill="#00D4AA"/>
                    <path d="M32 16L32 28M24 32L32 28L40 32" stroke="#00D4AA" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M24 24L32 28L40 24" stroke="#00D4AA" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.5"/>
                </svg>
            </div>
            <h1 class="brand-title">open<span>KYC</span></h1>
            <p class="brand-subtitle">Own Your Identity. Monetize Your Trust.</p>
        </div>
        <div class="card">
            <div class="error-header">
                <div class="error-icon">
                    <svg viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="32" cy="32" r="30"/>
                        <line x1="20" y1="20" x2="44" y2="44"/>
                        <line x1="44" y1="20" x2="20" y2="44"/>
                    </svg>
                </div>
                <h2 class="card-title">Unable to Sign In</h2>
                <p class="card-description">We encountered a problem while trying to verify your identity.</p>
            </div>
            <div class="error-message">
                <span class="error-label">Error</span>
                <span class="error-text">${message.summary}</span>
            </div>
            <div class="error-help">
                <p>This could be due to:</p>
                <ul>
                    <li>An invalid or expired link</li>
                    <li>Missing required information</li>
                    <li>A configuration issue</li>
                </ul>
            </div>
            <div class="error-actions">
                <button class="btn-primary" onclick="history.back()">Go Back</button>
            </div>
            <div class="error-support">
                <p>Need help? <a href="mailto:support@openkyc.org">Contact OpenKYC Support</a></p>
            </div>
        </div>
        <div class="footer">
            <p class="footer-text">Powered by <a href="https://openkyc.org" class="footer-link">OpenKYC</a></p>
        </div>
    </div>
</body>
</html>
