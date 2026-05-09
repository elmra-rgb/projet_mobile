import traceback
import re
from androguard.misc import AnalyzeAPK

# ──────────────────────────────────────────────────────────────
# Expanded tracker database — 40+ SDKs, categorized
# ──────────────────────────────────────────────────────────────
TRACKERS = {
    # ── Advertising / Ads ──
    "com.google.android.gms.ads":   {"name": "Google Ads (AdMob)",       "category": "ads"},
    "com.facebook.ads":             {"name": "Facebook Ads",             "category": "ads"},
    "com.unity3d.ads":              {"name": "Unity Ads",                "category": "ads"},
    "com.applovin":                 {"name": "AppLovin Ads",             "category": "ads"},
    "com.ironsource":               {"name": "ironSource Ads",           "category": "ads"},
    "com.vungle":                   {"name": "Vungle Ads",               "category": "ads"},
    "com.inmobi":                   {"name": "InMobi Ads",               "category": "ads"},
    "com.chartboost":               {"name": "Chartboost Ads",           "category": "ads"},
    "com.tapjoy":                   {"name": "Tapjoy Ads",               "category": "ads"},
    "com.adcolony":                 {"name": "AdColony Ads",             "category": "ads"},
    "com.startapp":                 {"name": "StartApp Ads",             "category": "ads"},
    "com.mopub":                    {"name": "MoPub Ads",                "category": "ads"},
    "com.criteo":                   {"name": "Criteo Ads",               "category": "ads"},
    "com.amazon.device.ads":        {"name": "Amazon Ads",               "category": "ads"},
    "com.bytedance.sdk.openadsdk":  {"name": "TikTok/Pangle Ads",       "category": "ads"},
    "com.moat":                     {"name": "Moat Ad Verification",     "category": "ads"},

    # ── Analytics / Tracking ──
    "com.google.firebase.analytics":{"name": "Firebase Analytics",       "category": "analytics"},
    "com.google.firebase":          {"name": "Firebase SDK",             "category": "analytics"},
    "com.facebook.appevents":       {"name": "Facebook Analytics",       "category": "analytics"},
    "com.mixpanel":                 {"name": "Mixpanel Analytics",       "category": "analytics"},
    "com.amplitude":                {"name": "Amplitude Analytics",      "category": "analytics"},
    "com.flurry":                   {"name": "Flurry Analytics",         "category": "analytics"},
    "com.segment":                  {"name": "Segment Analytics",        "category": "analytics"},
    "com.clevertap":                {"name": "CleverTap Analytics",      "category": "analytics"},
    "com.leanplum":                 {"name": "Leanplum Analytics",       "category": "analytics"},
    "com.comscore":                 {"name": "comScore Analytics",       "category": "analytics"},
    "com.apptentive":               {"name": "Apptentive Engagement",    "category": "analytics"},
    "com.heap":                     {"name": "Heap Analytics",           "category": "analytics"},
    "ly.count.android.sdk":         {"name": "Countly Analytics",        "category": "analytics"},

    # ── Attribution / Marketing ──
    "com.adjust":                   {"name": "Adjust Attribution",       "category": "attribution"},
    "com.appsflyer":                {"name": "AppsFlyer Attribution",    "category": "attribution"},
    "com.kochava":                  {"name": "Kochava Attribution",      "category": "attribution"},
    "io.branch":                    {"name": "Branch.io Attribution",    "category": "attribution"},
    "com.singular.sdk":             {"name": "Singular Attribution",     "category": "attribution"},
    "com.tune":                     {"name": "TUNE Attribution",         "category": "attribution"},
    "com.tenjin":                   {"name": "Tenjin Attribution",       "category": "attribution"},

    # ── Crash Reporting / Monitoring ──
    "com.crashlytics":              {"name": "Crashlytics",              "category": "crash"},
    "io.sentry":                    {"name": "Sentry Crash Reporting",   "category": "crash"},
    "com.bugsnag":                  {"name": "Bugsnag Crash Reporting",  "category": "crash"},
    "com.newrelic":                 {"name": "New Relic Monitoring",     "category": "crash"},
    "com.datadog":                  {"name": "Datadog Monitoring",       "category": "crash"},
    "com.instabug":                 {"name": "Instabug Bug Reporting",   "category": "crash"},

    # ── Push / Messaging ──
    "com.onesignal":                {"name": "OneSignal Push",           "category": "analytics"},
    "com.pusher":                   {"name": "Pusher Messaging",         "category": "analytics"},
}

# ──────────────────────────────────────────────────────────────
# Patterns for secret/URL detection
# ──────────────────────────────────────────────────────────────
IP_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
URL_PATTERN = re.compile(r"^https?://(?:[a-zA-Z]|[0-9]|[$\-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
API_KEY_PATTERN = re.compile(r"(?:AIza[0-9A-Za-z\-_]{35}|(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,})")

IGNORED_DOMAINS = [
    "android.com", "google.com", "googleapis.com",
    "w3.org", "schema.org", "xmlpull.org",
    "apache.org", "xml.org", "example.com",
]


def analyze_apk(apk_path):
    """Analyse complète d'un APK : permissions, trackers catégorisés, secrets."""
    print(f"[*] Analyzing APK via Androguard: {apk_path}")

    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        print(f"[!] Error analyzing APK: {e}")
        traceback.print_exc()
        return {
            "permissions": [],
            "trackers": [],
            "secrets": [],
            "app_info": {},
            "error": str(e),
        }

    # ── App metadata ──
    def safe_get(func, default="N/A"):
        try:
            return func() or default
        except Exception as e:
            return default

    app_info = {}
    if a:
        app_info = {
            "package": safe_get(a.get_package),
            "app_name": safe_get(a.get_app_name),
            "version_name": safe_get(a.get_androidversion_name),
            "version_code": safe_get(a.get_androidversion_code),
            "min_sdk": safe_get(a.get_min_sdk_version),
            "target_sdk": safe_get(a.get_target_sdk_version),
        }

    # ── Permissions ──
    permissions = list(a.get_permissions()) if a else []

    # ── Trackers & Secrets ──
    found_trackers = {}   # key = tracker name, value = category
    secrets = set()

    try:
        if d:
            for dex in d:
                # 1. Look for trackers in class names
                for cls in dex.get_classes():
                    name = cls.get_name()
                    for pkg, info in TRACKERS.items():
                        tracker_path = pkg.replace(".", "/")
                        if tracker_path in name:
                            found_trackers[info["name"]] = info["category"]

                # 2. Look for secrets & hardcoded URLs in strings
                dex_strings = dex.get_strings()
                if dex_strings:
                    for s in dex_strings:
                        s_str = str(s).strip()
                        if len(s_str) > 300 or len(s_str) < 5:
                            continue

                        # API Keys
                        if API_KEY_PATTERN.search(s_str):
                            secrets.add(f"🔑 Clé API suspecte : {s_str[:80]}…")

                        # IPs
                        if IP_PATTERN.match(s_str):
                            if s_str not in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
                                secrets.add(f"🌐 IP suspecte : {s_str}")

                        # URLs
                        if URL_PATTERN.match(s_str):
                            if not any(dom in s_str for dom in IGNORED_DOMAINS):
                                secrets.add(f"🔗 URL externe : {s_str}")

    except Exception as e:
        print(f"[!] Warning reading classes/strings from DEX: {e}")

    # Format trackers as list of dicts for the template
    trackers_list = [
        {"name": name, "category": cat}
        for name, cat in found_trackers.items()
    ]

    return {
        "permissions": permissions,
        "trackers": trackers_list,
        "secrets": list(secrets)[:100],
        "app_info": app_info,
    }
