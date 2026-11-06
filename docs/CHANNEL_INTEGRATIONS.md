# Channel integrations

| Channel | Current implementation | External requirements |
| --- | --- | --- |
| WhatsApp | Meta OAuth consent, Cloud API send/webhook, template sync and approved-template send path | Meta app with WhatsApp Embedded Signup configured, business/phone assets, app review and template approval |
| Instagram | Meta OAuth and messaging/webhook foundation | Professional account, linked Page, Meta app review and scopes |
| Messenger | Meta OAuth and messaging/webhook foundation | Page, Meta app review and messaging permission |
| Email | Gmail/Outlook OAuth, sync and queued send | Google/Microsoft app registration, consent and verified callbacks |
| Website | Widget bootstrap, visitor message endpoint | Website installation and production origin configuration |

The campaign system is not a standalone provider sender. It requires eligible contacts, channel consent and an existing conversation/outbox path. Confirm current platform policy and applicable law before enabling bulk messaging. Credentials, approvals and callback/domain configuration are owned by the deployer.

## Meta direct connection

Set `META_APP_ID`, `META_APP_SECRET`, `META_WHATSAPP_CONFIG_ID`, `META_GRAPH_VERSION`, `NEXT_PUBLIC_APP_URL`, `AUTH_SECRET`, and `CREDENTIAL_ENCRYPTION_KEY` in the server environment. `META_WHATSAPP_CONFIG_ID` is the WhatsApp Embedded Signup configuration created for your Meta app. Do not expose the app secret or encryption key to browser code. In the Meta app dashboard, enable Facebook Login and WhatsApp Embedded Signup, configure the OAuth redirect URI as `/api/channels/{channelId}/meta/oauth/callback`, and configure the WhatsApp webhook at `/api/webhooks/whatsapp`. The app requests channel-specific permissions; a workspace administrator signs in at Meta, grants permissions, and selects from authorized accounts. Tokens are encrypted before database storage.

Meta must approve the app and requested permissions for production access. Instagram messaging requires an eligible professional account linked to a Facebook Page; Messenger requires a Page. WhatsApp Embedded Signup requires a supported business onboarding configuration and phone-number access. Meta's consent and business verification requirements still apply. Webhook verification uses the per-channel verifier generated during the WhatsApp connection; `META_VERIFY_TOKEN` is also accepted for deployments that have configured a shared webhook verifier.
