/**
 * Cookie consent - GDPR/EDPB-compliant.
 *
 * Stores a JSON cookie "mks_consent" with the user's choices.
 * Necessary cookies are always on; analytics and marketing default to off
 * and require explicit opt-in. The banner re-appears after 12 months or
 * if the cookie schema version changes.
 */
(function () {
  const COOKIE_NAME = "mks_consent";
  const SCHEMA_VERSION = 1;
  const ONE_YEAR_DAYS = 365;
  const REPROMPT_AFTER_DAYS = 365;

  function readConsent() {
    const match = document.cookie.match(new RegExp("(?:^|;\\s*)" + COOKIE_NAME + "=([^;]+)"));
    if (!match) return null;
    try {
      const data = JSON.parse(decodeURIComponent(match[1]));
      if (data.v !== SCHEMA_VERSION) return null;
      if (data.t && (Date.now() - data.t) / 86_400_000 > REPROMPT_AFTER_DAYS) return null;
      return data;
    } catch {
      return null;
    }
  }

  function writeConsent(choice) {
    const data = {
      v: SCHEMA_VERSION,
      n: 1, // necessary - always
      a: choice.analytics ? 1 : 0,
      m: choice.marketing ? 1 : 0,
      t: Date.now(),
    };
    const value = encodeURIComponent(JSON.stringify(data));
    const expires = new Date();
    expires.setDate(expires.getDate() + ONE_YEAR_DAYS);
    document.cookie =
      COOKIE_NAME + "=" + value +
      "; expires=" + expires.toUTCString() +
      "; path=/; SameSite=Lax" +
      (location.protocol === "https:" ? "; Secure" : "");
    applyConsent(data);
    window.dispatchEvent(new CustomEvent("cookie:saved", { detail: data }));
  }

  function clearConsent() {
    document.cookie = COOKIE_NAME + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  }

  function applyConsent(data) {
    if (data.a === 1) loadAnalytics();
    // Marketing scripts would go here when needed
  }

  function loadAnalytics() {
    if (window.__ahrefs_loaded) return;
    window.__ahrefs_loaded = true;
    const s = document.createElement("script");
    s.src = "https://analytics.ahrefs.com/analytics.js";
    s.async = true;
    s.dataset.key = "55HGUtDfeHS17Scw3DZauQ";
    document.head.appendChild(s);
  }

  // Public API exposed for templates / other components
  window.MksConsent = {
    accept: function () {
      writeConsent({ analytics: true, marketing: true });
    },
    reject: function () {
      writeConsent({ analytics: false, marketing: false });
    },
    save: function (choice) {
      writeConsent(choice);
    },
    show: function () {
      window.dispatchEvent(new CustomEvent("cookie:show"));
    },
    showPrefs: function () {
      window.dispatchEvent(new CustomEvent("cookie:show-prefs"));
    },
    read: readConsent,
    clear: clearConsent,
  };

  // Apply existing consent on load
  document.addEventListener("DOMContentLoaded", function () {
    const existing = readConsent();
    if (existing) {
      applyConsent(existing);
    } else {
      window.dispatchEvent(new CustomEvent("cookie:show"));
    }
  });
})();
