/* Split-deployment override. Same-origin default: local dev and Render-only
 * both work with this file untouched.
 *
 * On Vercel, the build command overwrites this file from the
 * SHADOWTRACE_API_BASE environment variable:
 *   printf 'window.SHADOWTRACE_API_BASE="%s";' "$SHADOWTRACE_API_BASE" \
 *     > server/static/api-config.js
 */
window.SHADOWTRACE_API_BASE = "";
