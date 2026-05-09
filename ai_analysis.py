"""
AI Analysis Module — Privacy Posture Analyzer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Heuristic-based classification engine:
  • Permission classification (necessary / sensitive / dangerous / excessive)
  • Data collection inference
  • Privacy checklist generation per app profile
  • Minimization recommendations
  • Weighted privacy scoring
"""

# ──────────────────────────────────────────────────────────────
# Permission risk levels
# ──────────────────────────────────────────────────────────────
PERMISSION_RISK = {
    # Normal / Low risk
    "android.permission.INTERNET":              "normal",
    "android.permission.ACCESS_NETWORK_STATE":  "normal",
    "android.permission.ACCESS_WIFI_STATE":     "normal",
    "android.permission.WAKE_LOCK":             "normal",
    "android.permission.CHANGE_WIFI_STATE":     "normal",
    "android.permission.VIBRATE":               "normal",
    "android.permission.RECEIVE_BOOT_COMPLETED":"normal",
    "android.permission.FOREGROUND_SERVICE":    "normal",
    "android.permission.POST_NOTIFICATIONS":    "normal",
    "android.permission.USE_BIOMETRIC":         "normal",
    "android.permission.NFC":                   "normal",
    "android.permission.BLUETOOTH":             "normal",
    "android.permission.BLUETOOTH_CONNECT":     "normal",

    # Sensitive
    "android.permission.READ_EXTERNAL_STORAGE":     "sensitive",
    "android.permission.WRITE_EXTERNAL_STORAGE":    "sensitive",
    "android.permission.READ_MEDIA_IMAGES":         "sensitive",
    "android.permission.READ_MEDIA_VIDEO":          "sensitive",
    "android.permission.READ_MEDIA_AUDIO":          "sensitive",
    "android.permission.ACCESS_COARSE_LOCATION":    "sensitive",
    "android.permission.ACCESS_FINE_LOCATION":      "sensitive",
    "android.permission.READ_PHONE_STATE":          "sensitive",
    "android.permission.GET_ACCOUNTS":              "sensitive",
    "android.permission.BODY_SENSORS":              "sensitive",

    # Dangerous
    "android.permission.MANAGE_EXTERNAL_STORAGE":   "dangerous",
    "android.permission.ACCESS_BACKGROUND_LOCATION":"dangerous",
    "android.permission.READ_CONTACTS":             "dangerous",
    "android.permission.WRITE_CONTACTS":            "dangerous",
    "android.permission.CALL_PHONE":                "dangerous",
    "android.permission.READ_SMS":                  "dangerous",
    "android.permission.SEND_SMS":                  "dangerous",
    "android.permission.RECEIVE_SMS":               "dangerous",
    "android.permission.READ_CALL_LOG":             "dangerous",
    "android.permission.RECORD_AUDIO":              "dangerous",
    "android.permission.CAMERA":                    "dangerous",
    "android.permission.SYSTEM_ALERT_WINDOW":       "dangerous",
    "android.permission.REQUEST_INSTALL_PACKAGES":  "dangerous",
    "android.permission.READ_CALENDAR":             "dangerous",
    "android.permission.WRITE_CALENDAR":            "dangerous",
}

# ──────────────────────────────────────────────────────────────
# Data collection inference mapping
# ──────────────────────────────────────────────────────────────
DATA_MAPPING = {
    "LOCATION":    {"label": "Localisation (GPS, WiFi)",           "icon": "📍"},
    "CONTACTS":    {"label": "Contacts & Carnet d'adresses",      "icon": "👥"},
    "STORAGE":     {"label": "Fichiers, Photos, Médias",          "icon": "📁"},
    "MEDIA":       {"label": "Photos, Vidéos, Audio de l'appareil","icon": "🖼️"},
    "AUDIO":       {"label": "Données audio (Microphone)",        "icon": "🎙️"},
    "CAMERA":      {"label": "Caméra / Photos / Vidéos",          "icon": "📷"},
    "SMS":         {"label": "Messages texte (SMS)",              "icon": "💬"},
    "CALL":        {"label": "Journal d'appels",                  "icon": "📞"},
    "PHONE":       {"label": "Identité téléphonique (IMEI)",      "icon": "📱"},
    "SENSORS":     {"label": "Capteurs corporels (santé, mouvements)", "icon": "🏃"},
    "ACCOUNTS":    {"label": "Comptes utilisateur sur l'appareil","icon": "🔑"},
    "CALENDAR":    {"label": "Calendrier et événements",          "icon": "📅"},
    "BIOMETRIC":   {"label": "Empreinte / Données biométriques",  "icon": "🔐"},
}

# ──────────────────────────────────────────────────────────────
# App profile heuristics
# ──────────────────────────────────────────────────────────────
APP_PROFILES = {
    "education": {
        "label": "Éducation / Apprentissage",
        "expected": ["INTERNET", "ACCESS_NETWORK_STATE", "STORAGE", "WAKE_LOCK"],
        "unexpected": ["LOCATION", "CONTACTS", "SMS", "PHONE_STATE", "CALL", "CAMERA", "RECORD_AUDIO", "CALENDAR"],
        "message": "Les apps éducatives ne nécessitent généralement que l'accès réseau et au stockage.",
        "checklist_rules": {
            "no_location":      "Ne collecte pas la localisation des élèves",
            "no_contacts":      "Ne lit pas le carnet d'adresses",
            "no_ads_trackers":  "Pas de trackers publicitaires (conformité COPPA/RGPD enfants)",
            "no_sms":           "Pas d'accès aux SMS",
            "https_only":       "Communications chiffrées (HTTPS)",
            "minimal_perms":    "Permissions minimales (réseau + stockage uniquement)",
            "no_background_loc":"Pas de localisation en arrière-plan",
        }
    },
    "health": {
        "label": "Santé / Médical",
        "expected": ["INTERNET", "ACCESS_NETWORK_STATE", "SENSORS", "CAMERA", "STORAGE", "BIOMETRIC"],
        "unexpected": ["CONTACTS", "SMS", "PHONE", "CALL", "CALENDAR"],
        "message": "Les apps de santé justifient l'accès aux capteurs et au stockage (dossiers médicaux), mais pas aux contacts ou SMS.",
        "checklist_rules": {
            "no_contacts":         "Ne lit pas le carnet d'adresses",
            "no_sms":              "Pas d'accès aux SMS/appels",
            "no_ads_trackers":     "Pas de trackers publicitaires (données médicales sensibles)",
            "minimal_analytics":   "Analytics limitées et anonymisées",
            "https_only":          "Communications chiffrées (HTTPS)",
            "encrypted_storage":   "Stockage local chiffré recommandé",
            "biometric_justified": "Biométrie utilisée pour sécuriser l'accès",
        }
    },
    "commerce": {
        "label": "E-commerce / Achats",
        "expected": ["INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "LOCATION", "STORAGE", "NFC", "VIBRATE"],
        "unexpected": ["SMS", "SENSORS", "CONTACTS", "CALL", "CALENDAR", "RECORD_AUDIO"],
        "message": "Le e-commerce peut utiliser la géolocalisation et la caméra (QR codes/scan), mais les contacts et SMS sont suspects.",
        "checklist_rules": {
            "no_contacts":      "Ne lit pas le carnet d'adresses",
            "no_sms":           "Pas de lecture des SMS",
            "camera_justified": "Caméra utilisée pour scanner (QR/code-barres) uniquement",
            "location_opt":     "Localisation optionnelle (livraison/magasin)",
            "https_only":       "Paiements et données chiffrés (HTTPS)",
            "analytics_limited":"Analytics de navigation, pas de profiling excessif",
        }
    },
    "gaming": {
        "label": "Jeux Vidéo",
        "expected": ["INTERNET", "ACCESS_NETWORK_STATE", "WAKE_LOCK", "VIBRATE"],
        "unexpected": ["CONTACTS", "SMS", "LOCATION", "CAMERA", "RECORD_AUDIO", "PHONE_STATE", "CALL", "CALENDAR", "SENSORS"],
        "message": "Les jeux mobiles ne nécessitent en général aucun accès aux contacts, caméra, micro ou localisation.",
        "checklist_rules": {
            "no_contacts":      "Pas d'accès au carnet d'adresses",
            "no_location":      "Pas de géolocalisation",
            "no_camera":        "Pas d'accès à la caméra",
            "no_audio":         "Pas d'accès au microphone",
            "no_sms":           "Pas d'accès aux SMS",
            "ads_disclosed":    "Publicités clairement identifiées (si présentes)",
            "minimal_perms":    "Permissions limitées au strict nécessaire",
        }
    },
    "social": {
        "label": "Réseaux Sociaux / Rencontres",
        "expected": ["INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "RECORD_AUDIO", "CONTACTS", "STORAGE", "LOCATION", "VIBRATE", "POST_NOTIFICATIONS"],
        "unexpected": ["SMS", "CALL_PHONE", "SEND_SMS", "CALENDAR"],
        "message": "Les réseaux sociaux sont par nature gourmands en permissions mais ne devraient pas envoyer de SMS ou passer des appels.",
        "checklist_rules": {
            "no_sms_send":      "Pas d'envoi automatique de SMS",
            "no_call":          "Pas d'appels automatiques",
            "camera_justified": "Caméra pour photos/vidéos utilisateur",
            "location_opt":     "Localisation optionnelle et transparente",
            "https_only":       "Communications chiffrées (HTTPS)",
            "data_export":      "Droit d'export de données (RGPD)",
        }
    },
    "other": {
        "label": "Autre / Neutre",
        "expected": ["INTERNET", "ACCESS_NETWORK_STATE"],
        "unexpected": [],
        "message": "Analyse neutre — aucun profil spécifique appliqué.",
        "checklist_rules": {
            "minimal_perms":    "Permissions limitées au strict nécessaire",
            "https_only":       "Communications chiffrées (HTTPS)",
            "no_ads_trackers":  "Pas de trackers publicitaires inutiles",
        }
    },
}


# ══════════════════════════════════════════════════════════════
# 1. CLASSIFY PERMISSIONS
# ══════════════════════════════════════════════════════════════
def classify_permissions(permissions, profile="other"):
    """Classify each permission as normal/sensitive/dangerous/excessive based on profile context."""
    results = []
    prof = APP_PROFILES.get(profile, APP_PROFILES["other"])
    expected_categories = prof["expected"]
    unexpected_categories = prof["unexpected"]

    for perm in permissions:
        short = perm.split(".")[-1]
        risk = PERMISSION_RISK.get(perm, "unknown")
        justification = ""

        # Profile-based override
        is_unexpected = any(cat in short for cat in unexpected_categories)
        is_expected = any(cat in short for cat in expected_categories)

        if is_unexpected:
            risk = "excessive"
            justification = f"⚠️ Inattendu pour le profil « {prof['label']} »"
        elif is_expected and risk in ["sensitive", "dangerous"]:
            justification = f"✅ Justifié pour le profil « {prof['label']} »"
        elif risk == "dangerous":
            justification = "🔴 Permission dangereuse — nécessite une justification"
        elif risk == "sensitive":
            justification = "🟡 Permission sensible — vérifier la nécessité"
        elif risk == "unknown":
            justification = "❓ Permission non standard — investigation requise"

        results.append({
            "permission": perm,
            "risk": risk,
            "short": short,
            "justification": justification,
        })

    return results


# ══════════════════════════════════════════════════════════════
# 2. INFER DATA COLLECTION
# ══════════════════════════════════════════════════════════════
def infer_data_collection(permissions):
    """Infer probable collected data types from the permissions list."""
    data = []
    seen = set()
    for perm in permissions:
        short = perm.split(".")[-1].upper()
        for key, info in DATA_MAPPING.items():
            if key in short and key not in seen:
                seen.add(key)
                data.append({
                    "type": key,
                    "label": info["label"],
                    "icon": info["icon"],
                })
    return data


# ══════════════════════════════════════════════════════════════
# 3. GENERATE PRIVACY CHECKLIST (per profile)
# ══════════════════════════════════════════════════════════════
def generate_privacy_checklist(profile, classified_perms, trackers, data_collected):
    """
    Generate a context-aware privacy checklist based on the app profile.
    Each item is marked as passed (✅) or failed (❌) with an explanation.
    """
    prof = APP_PROFILES.get(profile, APP_PROFILES["other"])
    checklist = []

    # Helper sets
    perm_shorts = {p["short"].upper() for p in classified_perms}
    risks = {p["risk"] for p in classified_perms}
    tracker_categories = {t["category"] for t in trackers} if trackers else set()
    data_types = {d["type"] for d in data_collected} if data_collected else set()
    has_ads = "ads" in tracker_categories
    has_analytics = "analytics" in tracker_categories
    excessive_count = sum(1 for p in classified_perms if p["risk"] == "excessive")

    rules = prof.get("checklist_rules", {})

    for rule_id, rule_label in rules.items():
        passed = True
        detail = ""

        if rule_id == "no_location":
            has_loc = any("LOCATION" in s for s in perm_shorts)
            passed = not has_loc
            detail = "Localisation détectée dans les permissions" if not passed else "Aucune permission de localisation"

        elif rule_id == "no_contacts":
            has_contacts = any("CONTACTS" in s or "GET_ACCOUNTS" in s for s in perm_shorts)
            passed = not has_contacts
            detail = "Accès aux contacts/comptes détecté" if not passed else "Pas d'accès aux contacts"

        elif rule_id == "no_ads_trackers":
            passed = not has_ads
            detail = f"Trackers publicitaires détectés" if not passed else "Aucun tracker publicitaire"

        elif rule_id == "no_sms" or rule_id == "no_sms_send":
            has_sms = any("SMS" in s for s in perm_shorts)
            passed = not has_sms
            detail = "Accès aux SMS détecté" if not passed else "Aucun accès aux SMS"

        elif rule_id == "no_camera":
            has_cam = "CAMERA" in perm_shorts
            passed = not has_cam
            detail = "Permission caméra détectée" if not passed else "Pas d'accès caméra"

        elif rule_id == "no_audio":
            has_audio = "RECORD_AUDIO" in perm_shorts
            passed = not has_audio
            detail = "Permission microphone détectée" if not passed else "Pas d'accès microphone"

        elif rule_id == "no_call":
            has_call = any("CALL" in s for s in perm_shorts)
            passed = not has_call
            detail = "Permission appel détectée" if not passed else "Pas d'accès appels"

        elif rule_id == "no_background_loc":
            has_bg = "ACCESS_BACKGROUND_LOCATION" in perm_shorts
            passed = not has_bg
            detail = "Localisation en arrière-plan active" if not passed else "Pas de localisation en arrière-plan"

        elif rule_id == "https_only":
            # Heuristic: check if INTERNET permission is present (we assume HTTPS)
            passed = True
            detail = "Vérifier manuellement que les communications sont en HTTPS"

        elif rule_id == "minimal_perms":
            passed = excessive_count == 0
            detail = f"{excessive_count} permission(s) excessive(s) détectée(s)" if not passed else "Toutes les permissions sont justifiées"

        elif rule_id == "minimal_analytics":
            passed = not has_ads and len(trackers) <= 2
            detail = f"{len(trackers)} tracker(s) détecté(s)" if not passed else "Analytics minimales"

        elif rule_id == "analytics_limited":
            passed = len(trackers) <= 3
            detail = f"{len(trackers)} tracker(s) détecté(s)" if not passed else "Nombre de trackers raisonnable"

        elif rule_id == "camera_justified":
            passed = True  # If profile expects camera, it's justified
            detail = "Caméra justifiée par le profil applicatif"

        elif rule_id == "location_opt":
            has_loc = any("LOCATION" in s for s in perm_shorts)
            has_bg = "ACCESS_BACKGROUND_LOCATION" in perm_shorts
            passed = not has_bg  # Background location is not OK
            if has_bg:
                detail = "Localisation en arrière-plan non justifiée"
            elif has_loc:
                detail = "Localisation active — vérifier qu'elle est optionnelle"
                passed = True
            else:
                detail = "Pas de localisation"

        elif rule_id == "ads_disclosed":
            if has_ads:
                passed = True  # We can't check disclosure, just note it
                detail = "Publicités détectées — vérifier la transparence"
            else:
                passed = True
                detail = "Aucun tracker publicitaire"

        elif rule_id == "biometric_justified":
            passed = True
            detail = "Biométrie justifiée pour la sécurité des données médicales"

        elif rule_id == "encrypted_storage":
            passed = True  # Cannot verify programmatically
            detail = "Vérifier manuellement le chiffrement local"

        elif rule_id == "data_export":
            passed = True
            detail = "Vérifier manuellement le droit d'export de données (Art. 20 RGPD)"

        else:
            detail = "Vérification manuelle requise"

        checklist.append({
            "rule": rule_label,
            "passed": passed,
            "detail": detail,
        })

    return checklist


# ══════════════════════════════════════════════════════════════
# 4. MINIMIZATION RECOMMENDATIONS
# ══════════════════════════════════════════════════════════════
MINIMIZATION_ADVICE = {
    "excessive": {
        "LOCATION":     "Supprimer l'accès à la localisation ou le rendre optionnel (opt-in).",
        "CONTACTS":     "Supprimer l'accès au carnet d'adresses. Si nécessaire, utiliser le Contacts Picker (sélection unique sans lecture complète).",
        "SMS":          "Supprimer la lecture/envoi de SMS. Utiliser un serveur backend pour les OTP.",
        "CALL":         "Supprimer la permission d'appel. Proposer un clic vers le dialer sans permission CALL_PHONE.",
        "CAMERA":       "Supprimer la caméra ou utiliser un Intent photo (sans permission directe).",
        "RECORD_AUDIO": "Supprimer le microphone. Si vocal nécessaire, rendre l'accès opt-in et temporaire.",
        "PHONE_STATE":  "Supprimer READ_PHONE_STATE. Utiliser un identifiant applicatif (UUID) au lieu de l'IMEI.",
        "CALENDAR":     "Supprimer l'accès au calendrier sauf si fonctionnalité centrale.",
    },
    "dangerous": {
        "CAMERA":              "Documenter l'usage de la caméra. Préférer un Intent photo si possible.",
        "RECORD_AUDIO":        "Documenter l'usage du micro. Ne l'activer que pendant l'interaction utilisateur.",
        "READ_CONTACTS":       "Justifier l'accès ou migrer vers le Contacts Picker API.",
        "ACCESS_BACKGROUND_LOCATION": "Supprimer la localisation en arrière-plan. Utiliser la localisation uniquement au premier plan.",
        "MANAGE_EXTERNAL_STORAGE": "Utiliser le Scoped Storage (Android 10+) au lieu du stockage global.",
        "SYSTEM_ALERT_WINDOW":  "Vérifier la nécessité. Remplacer par des notifications si possible.",
        "REQUEST_INSTALL_PACKAGES": "Supprimer sauf si l'app est un store. Risque de sideloading.",
    },
}

TRACKER_ALTERNATIVES = {
    "ads": {
        "problem": "Trackers publicitaires collectant des données comportementales",
        "alternatives": [
            "Utiliser des publicités contextuelles (non basées sur le profil utilisateur)",
            "Implémenter un modèle freemium sans publicité",
            "Si publicité nécessaire, limiter aux réseaux respectueux (ex: AdMob en mode limité)",
        ]
    },
    "analytics": {
        "problem": "Trackers d'analytics pouvant collecter des données personnelles",
        "alternatives": [
            "Migrer vers Matomo (self-hosted, respectueux de la vie privée)",
            "Utiliser Firebase Analytics en mode anonyme (sans user-ID)",
            "Implémenter un analytics côté serveur (aucune donnée client)",
        ]
    },
    "attribution": {
        "problem": "SDKs d'attribution traçant le parcours cross-app de l'utilisateur",
        "alternatives": [
            "Utiliser l'API d'attribution Android (Privacy Sandbox) au lieu de SDKs tiers",
            "Limiter l'attribution au premier lancement uniquement",
            "Supprimer l'attribution si non critique pour le business model",
        ]
    },
    "crash": {
        "problem": "SDKs de crash reporting (risque faible mais données collectées)",
        "alternatives": [
            "Les crash reporters sont généralement acceptables",
            "Vérifier qu'aucune donnée personnelle n'est incluse dans les crash reports",
            "Préférer les solutions self-hosted (ex: Sentry self-hosted)",
        ]
    },
}


def generate_minimization_recommendations(classified_perms, trackers, data_collected, profile):
    """Generate actionable minimization recommendations."""
    recommendations = []

    # ── Permission recommendations ──
    for p in classified_perms:
        risk = p["risk"]
        short = p["short"]

        if risk == "excessive":
            # Find matching advice
            advice = None
            for key, text in MINIMIZATION_ADVICE["excessive"].items():
                if key in short.upper():
                    advice = text
                    break
            if not advice:
                advice = f"Permission « {short} » inattendue pour le profil « {profile} ». Envisager la suppression."

            recommendations.append({
                "type": "permission",
                "severity": "high",
                "title": f"Supprimer « {short} »",
                "detail": advice,
                "icon": "🔴",
            })

        elif risk == "dangerous":
            advice = None
            for key, text in MINIMIZATION_ADVICE["dangerous"].items():
                if key in short.upper():
                    advice = text
                    break
            if advice:
                recommendations.append({
                    "type": "permission",
                    "severity": "medium",
                    "title": f"Revoir « {short} »",
                    "detail": advice,
                    "icon": "🟡",
                })

    # ── Tracker recommendations ──
    seen_categories = set()
    if trackers:
        for t in trackers:
            cat = t["category"]
            if cat not in seen_categories:
                seen_categories.add(cat)
                alt = TRACKER_ALTERNATIVES.get(cat)
                if alt:
                    recommendations.append({
                        "type": "tracker",
                        "severity": "high" if cat == "ads" else "medium",
                        "title": alt["problem"],
                        "detail": " | ".join(alt["alternatives"]),
                        "icon": "🔴" if cat == "ads" else "🟡",
                    })

    # ── General recommendations if data is collected ──
    if len(data_collected) > 5:
        recommendations.append({
            "type": "general",
            "severity": "medium",
            "title": "Volume de données élevé",
            "detail": f"L'app accède à {len(data_collected)} catégories de données. Appliquer le principe de minimisation (Art. 5 RGPD) : ne collecter que le strict nécessaire.",
            "icon": "🟡",
        })

    return recommendations


# ══════════════════════════════════════════════════════════════
# 5. WEIGHTED PRIVACY SCORE
# ══════════════════════════════════════════════════════════════
SCORE_WEIGHTS = {
    "excessive":  15,
    "dangerous":  10,
    "sensitive":  3,
    "unknown":    5,
    "normal":     0,
}

TRACKER_WEIGHTS = {
    "ads":         8,
    "analytics":   4,
    "attribution": 5,
    "crash":       2,
}

SCORE_LABELS = [
    (80, "Excellent",  "L'application respecte les bonnes pratiques de confidentialité."),
    (60, "Bon",        "Quelques points d'attention mais globalement acceptable."),
    (40, "Moyen",      "Plusieurs problèmes de confidentialité à corriger."),
    (20, "Mauvais",    "Nombreux problèmes — l'app collecte probablement trop de données."),
    (0,  "Critique",   "Posture privacy très préoccupante — action immédiate requise."),
]


def calculate_score(classified_perms, trackers):
    """Calculate a weighted privacy score (0-100) with breakdown."""
    score = 100
    breakdown = {
        "permissions": 0,
        "trackers": 0,
    }

    # ── Permission penalties ──
    for p in classified_perms:
        penalty = SCORE_WEIGHTS.get(p["risk"], 0)
        score -= penalty
        breakdown["permissions"] += penalty

    # ── Tracker penalties (weighted by category) ──
    if trackers:
        for t in trackers:
            cat = t.get("category", "analytics")
            penalty = TRACKER_WEIGHTS.get(cat, 3)
            score -= penalty
            breakdown["trackers"] += penalty

    final_score = max(score, 0)

    # ── Label ──
    label = "Critique"
    description = ""
    for threshold, lbl, desc in SCORE_LABELS:
        if final_score >= threshold:
            label = lbl
            description = desc
            break

    return {
        "value": final_score,
        "label": label,
        "description": description,
        "breakdown": breakdown,
    }


# ══════════════════════════════════════════════════════════════
# 6. RADAR CHART DATA — App vs Ideal Profile
# ══════════════════════════════════════════════════════════════

# Each axis is scored 0-100 (100 = best privacy)
RADAR_AXES = [
    "Permissions",
    "Trackers",
    "Localisation",
    "Contacts & SMS",
    "Volume Données",
    "Transparence",
]

# Ideal scores per profile (what a privacy-respectful app in this category should look like)
IDEAL_PROFILES = {
    "education": {
        "Permissions":      95,   # Minimal permissions
        "Trackers":         100,  # Zero trackers (kids)
        "Localisation":     100,  # No location at all
        "Contacts & SMS":   100,  # No contacts/SMS
        "Volume Données":   90,   # Very little data
        "Transparence":     95,   # High transparency
    },
    "health": {
        "Permissions":      70,   # Needs sensors, camera, storage
        "Trackers":         95,   # Minimal trackers (medical data)
        "Localisation":     90,   # Location rarely needed
        "Contacts & SMS":   100,  # No contacts/SMS
        "Volume Données":   60,   # Medical data needed
        "Transparence":     95,   # Must be transparent
    },
    "commerce": {
        "Permissions":      65,   # Needs camera, location, storage
        "Trackers":         60,   # Some analytics acceptable
        "Localisation":     60,   # Location for delivery
        "Contacts & SMS":   100,  # No contacts/SMS
        "Volume Données":   55,   # Moderate data
        "Transparence":     80,   # Good transparency
    },
    "gaming": {
        "Permissions":      90,   # Very few permissions needed
        "Trackers":         50,   # Ads common in games
        "Localisation":     100,  # No location
        "Contacts & SMS":   100,  # No contacts/SMS
        "Volume Données":   85,   # Little data needed
        "Transparence":     70,   # Moderate
    },
    "social": {
        "Permissions":      40,   # Many permissions expected
        "Trackers":         50,   # Analytics common
        "Localisation":     50,   # Location sharing is a feature
        "Contacts & SMS":   60,   # Contact sync expected
        "Volume Données":   35,   # Lots of data expected
        "Transparence":     75,   # Should be transparent
    },
    "other": {
        "Permissions":      80,
        "Trackers":         80,
        "Localisation":     90,
        "Contacts & SMS":   95,
        "Volume Données":   80,
        "Transparence":     80,
    },
}


def generate_radar_data(classified_perms, trackers, data_collected, profile):
    """
    Compute the radar chart data comparing the analyzed app
    against the ideal privacy profile for its category.

    Returns:
        {
            "labels": [...],
            "app_scores": [...],
            "ideal_scores": [...],
        }
    """
    perm_shorts = {p["short"].upper() for p in classified_perms}
    total_perms = len(classified_perms)
    excessive_count = sum(1 for p in classified_perms if p["risk"] == "excessive")
    dangerous_count = sum(1 for p in classified_perms if p["risk"] == "dangerous")
    tracker_cats = {t.get("category") for t in trackers} if trackers else set()

    # ── Axis 1: Permissions ──
    # Fewer excessive/dangerous = higher score
    if total_perms == 0:
        perm_score = 100
    else:
        penalty = (excessive_count * 20 + dangerous_count * 10)
        perm_score = max(0, 100 - penalty)

    # ── Axis 2: Trackers ──
    ads_count = sum(1 for t in trackers if t.get("category") == "ads")
    analytics_count = sum(1 for t in trackers if t.get("category") == "analytics")
    other_tracker_count = len(trackers) - ads_count - analytics_count
    tracker_score = max(0, 100 - ads_count * 15 - analytics_count * 8 - other_tracker_count * 5)

    # ── Axis 3: Localisation ──
    has_fine = any("FINE_LOCATION" in s for s in perm_shorts)
    has_coarse = any("COARSE_LOCATION" in s for s in perm_shorts)
    has_bg = any("BACKGROUND_LOCATION" in s for s in perm_shorts)
    loc_score = 100
    if has_bg:
        loc_score -= 50
    if has_fine:
        loc_score -= 30
    elif has_coarse:
        loc_score -= 15
    loc_score = max(0, loc_score)

    # ── Axis 4: Contacts & SMS ──
    has_contacts = any("CONTACTS" in s or "GET_ACCOUNTS" in s for s in perm_shorts)
    has_sms = any("SMS" in s for s in perm_shorts)
    has_call = any("CALL_PHONE" in s or "CALL_LOG" in s for s in perm_shorts)
    contact_score = 100
    if has_contacts:
        contact_score -= 35
    if has_sms:
        contact_score -= 40
    if has_call:
        contact_score -= 25
    contact_score = max(0, contact_score)

    # ── Axis 5: Volume de Données ──
    data_count = len(data_collected) if data_collected else 0
    data_score = max(0, 100 - data_count * 12)

    # ── Axis 6: Transparence ──
    # Based on secrets/hardcoded URLs and crash reporters
    has_crash = "crash" in tracker_cats
    transparency_score = 80  # baseline
    if has_crash:
        transparency_score += 10  # crash reporting = more transparent
    if excessive_count > 0:
        transparency_score -= excessive_count * 10
    transparency_score = max(0, min(100, transparency_score))

    # ── Get ideal profile ──
    ideal = IDEAL_PROFILES.get(profile, IDEAL_PROFILES["other"])

    app_scores = [
        perm_score,
        tracker_score,
        loc_score,
        contact_score,
        data_score,
        transparency_score,
    ]

    ideal_scores = [ideal[axis] for axis in RADAR_AXES]

    return {
        "labels": RADAR_AXES,
        "app_scores": app_scores,
        "ideal_scores": ideal_scores,
    }
