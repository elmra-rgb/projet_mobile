import os
from flask import Flask, render_template, request, redirect, flash
from werkzeug.utils import secure_filename

from analyzer import analyze_apk
from ai_analysis import (
    classify_permissions,
    infer_data_collection,
    calculate_score,
    generate_privacy_checklist,
    generate_minimization_recommendations,
    generate_radar_data,
    APP_PROFILES,
)
from gemini_ai import analyze_with_gemini, is_gemini_configured

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB
app.secret_key = "privacy-posture-analyzer-secret"

ALLOWED_EXTENSIONS = {".apk"}
APK_MAGIC_BYTES = b"PK"  # APK files are ZIP archives


def _is_valid_apk(filepath):
    """Validate that the uploaded file is a genuine APK (ZIP/PK header)."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(2)
        return header == APK_MAGIC_BYTES
    except Exception:
        return False


@app.route("/")
def index():
    profiles = {k: v["label"] for k, v in APP_PROFILES.items()}
    return render_template("index.html", profiles=profiles, gemini_active=is_gemini_configured())


@app.route("/analyze", methods=["POST"])
def analyze():
    # ── File validation ──
    if "file" not in request.files:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect("/")

    file = request.files["file"]
    profile = request.form.get("profile", "other")

    if file.filename == "":
        flash("Aucun fichier sélectionné.", "danger")
        return redirect("/")

    # Validate extension
    _, ext = os.path.splitext(file.filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        flash("Format non supporté. Seuls les fichiers .apk sont acceptés.", "danger")
        return redirect("/")

    # Secure filename & save
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    safe_name = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    file.save(filepath)

    # Validate magic bytes
    if not _is_valid_apk(filepath):
        os.remove(filepath)
        flash("Le fichier uploadé n'est pas un APK valide.", "danger")
        return redirect("/")

    try:
        # ══════════════════════════════════════════════
        # STEP 1 — Static analysis via Androguard
        # ══════════════════════════════════════════════
        result = analyze_apk(filepath)

        perms = result.get("permissions", [])
        trackers = result.get("trackers", [])
        secrets = result.get("secrets", [])
        app_info = result.get("app_info", {})

        # ══════════════════════════════════════════════
        # STEP 2 — Heuristic classification (always runs as baseline)
        # ══════════════════════════════════════════════
        classified = classify_permissions(perms, profile=profile)
        data = infer_data_collection(perms)
        score = calculate_score(classified, trackers)
        checklist = generate_privacy_checklist(profile, classified, trackers, data)
        recommendations = generate_minimization_recommendations(classified, trackers, data, profile)

        # ══════════════════════════════════════════════
        # STEP 3 — Gemini AI (if configured)
        # ══════════════════════════════════════════════
        gemini_result = None
        executive_summary = ""
        ai_powered = False

        if is_gemini_configured():
            print("[*] Calling Gemini AI for intelligent analysis...")
            gemini_result = analyze_with_gemini(perms, trackers, data, profile, app_info)

            if gemini_result.get("ai_powered"):
                ai_powered = True
                executive_summary = gemini_result.get("executive_summary", "")

                # Override classification with Gemini's verdicts
                gemini_classification = gemini_result.get("classification", [])
                if gemini_classification:
                    # Build a lookup by permission name
                    gemini_lookup = {}
                    for gc in gemini_classification:
                        gemini_lookup[gc["permission"]] = gc

                    # Merge Gemini verdicts into our classification
                    for item in classified:
                        gc = gemini_lookup.get(item["permission"])
                        if gc:
                            verdict = gc.get("verdict", "")
                            # Map Gemini verdict to our risk levels
                            verdict_map = {
                                "necessaire": "normal",
                                "acceptable": "sensitive",
                                "excessive": "excessive",
                                "dangereuse": "dangerous",
                            }
                            item["risk"] = verdict_map.get(verdict, item["risk"])
                            item["justification"] = f"🤖 {gc.get('justification', item['justification'])}"

                # Override checklist with Gemini's
                gemini_checklist = gemini_result.get("checklist", [])
                if gemini_checklist:
                    checklist = gemini_checklist

                # Override recommendations with Gemini's
                gemini_recs = gemini_result.get("recommendations", [])
                if gemini_recs:
                    recommendations = []
                    severity_icons = {"high": "🔴", "medium": "🟡", "low": "🟢"}
                    for r in gemini_recs:
                        sev = r.get("severity", "medium")
                        recommendations.append({
                            "type": "ai",
                            "severity": sev,
                            "title": r.get("title", ""),
                            "detail": r.get("detail", ""),
                            "icon": severity_icons.get(sev, "🟡"),
                        })

                # Recalculate score with updated classifications
                score = calculate_score(classified, trackers)

        # ══════════════════════════════════════════════
        # STEP 4 — Stats for charts
        # ══════════════════════════════════════════════
        risk_distribution = {"normal": 0, "sensitive": 0, "dangerous": 0, "excessive": 0, "unknown": 0}
        for p in classified:
            r = p["risk"]
            if r in risk_distribution:
                risk_distribution[r] += 1

        tracker_distribution = {}
        for t in trackers:
            cat = t.get("category", "other")
            tracker_distribution[cat] = tracker_distribution.get(cat, 0) + 1

        # ══════════════════════════════════════════════
        # STEP 5 — Radar chart data (App vs Ideal Profile)
        # ══════════════════════════════════════════════
        radar_data = generate_radar_data(classified, trackers, data, profile)

        analysis = {
            "app_info": app_info,
            "permissions": classified,
            "trackers": trackers,
            "secrets": secrets,
            "data": data,
            "score": score,
            "checklist": checklist,
            "recommendations": recommendations,
            "risk_distribution": risk_distribution,
            "tracker_distribution": tracker_distribution,
            "radar_data": radar_data,
            "profile": profile,
            "profile_label": APP_PROFILES.get(profile, {}).get("label", profile),
            "profile_message": APP_PROFILES.get(profile, {}).get("message", ""),
            "filename": file.filename,
            "ai_powered": ai_powered,
            "executive_summary": executive_summary,
            "stats": {
                "total_permissions": len(perms),
                "total_trackers": len(trackers),
                "total_secrets": len(secrets),
                "excessive_count": sum(1 for p in classified if p["risk"] == "excessive"),
                "dangerous_count": sum(1 for p in classified if p["risk"] == "dangerous"),
                "checklist_passed": sum(1 for c in checklist if c.get("passed", False)),
                "checklist_total": len(checklist),
            },
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        analysis = {"error": str(e)}
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

    return render_template("result.html", analysis=analysis)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
