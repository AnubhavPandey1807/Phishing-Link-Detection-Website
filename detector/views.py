from django.shortcuts import render
from .forms import URLForm
import joblib
from ml_model.feature_extractor import extract_features

# Load model at startup
model = joblib.load("ml_model/phishing_model.pkl")

def home(request):
    return render(request, "detector/home.html")

def result(request):
    if request.method == "POST":
        url = request.POST.get("url")
        features = [extract_features(url)]
        prediction = model.predict(features)[0]

        # Get probability if available
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features)[0][1]  # probability of phishing
            confidence = round(proba * 100, 2)
        else:
            confidence = None  # fallback

        # Decide verdict and color
        if confidence is not None:
            if confidence >= 70:
                verdict = "Phishing ❌"
                color = "red"
            elif 50 <= confidence < 70:
                verdict = "Possibly Phishing ⚠️"
                color = "yellow"
            else:
                verdict = "Safe ✅"
                color = "green"
        else:
            # fallback if probability not available
            verdict = "Phishing ❌" if prediction == 1 else "Safe ✅"
            color = "red" if prediction == 1 else "green"

        context = {
            "url": url,
            "verdict": verdict,
            "color": color,
            "confidence": confidence,
        }

        return render(request, "detector/result.html", context)
