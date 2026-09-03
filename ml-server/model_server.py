#!/usr/bin/env python3
"""GoUpload ML Prediction Server"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np
import json
import os

app = FastAPI(title="GoUpload ML API")

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Model path - relative to script location
DEFAULT_MODEL_PATH = os.path.join(SCRIPT_DIR, "models", "goupload_production.joblib")

# Allow override via environment variable
MODEL_PATH = os.getenv("MODEL_PATH", DEFAULT_MODEL_PATH)

print(f"📁 Script directory: {SCRIPT_DIR}")
print(f"🔍 Looking for model at: {MODEL_PATH}")

# Load model at startup
model = None
try:
    if os.path.exists(MODEL_PATH):
        model_data = joblib.load(MODEL_PATH)
        model = model_data['model'] if isinstance(model_data, dict) else model_data
        print(f"✅ Model loaded: {type(model).__name__}")
    else:
        print(f"⚠️  Model not found at {MODEL_PATH}")
        print(f"   Please copy your model to: {SCRIPT_DIR}/models/")
        print("   Using dummy model for development")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    print("   Using dummy model for development")


class PredictionRequest(BaseModel):
    features: list  # 36 float values


class PredictionResponse(BaseModel):
    prediction: int
    probability: list
    verdict: str
    confidence: float


@app.post("/predict")
async def predict(request: PredictionRequest):
    try:
        # Validate features
        if len(request.features) != 36:
            raise HTTPException(
                status_code=400, 
                detail=f"Expected 36 features, got {len(request.features)}"
            )
        
        # Convert features to numpy array
        X = np.array([request.features])
        
        if model is None:
            # Dummy prediction for development
            features = request.features
            
            # Extract key indicators
            has_php = features[1] > 0.5
            has_success = features[10] > 0.5 or features[11] > 0.5
            has_filepath = features[14] > 0.5 or features[15] > 0.5
            has_suspicious = features[17] > 0.5
            flag_count = features[16]
            
            # Simple scoring
            score = 0.0
            if has_php: score += 0.3
            if has_success: score += 0.2
            if has_filepath: score += 0.2
            if has_suspicious: score += 0.2
            if flag_count > 2: score += 0.1
            
            score = min(score, 0.95)
            
            if score >= 0.5:
                prediction = 1
                probability = [1-score, score]
                confidence = score
                verdict = "VULNERABLE" if score >= 0.65 else "REVIEW_NEEDED"
            else:
                prediction = 0
                probability = [1-score, score]
                confidence = 1-score
                verdict = "SAFE"
        else:
            # Real model prediction
            prediction = int(model.predict(X)[0])
            probability = model.predict_proba(X)[0].tolist()
            confidence = max(probability)
            
            # Determine verdict
            if confidence < 0.65:
                verdict = "REVIEW_NEEDED"
            else:
                verdict = "VULNERABLE" if prediction == 1 else "SAFE"
        
        return PredictionResponse(
            prediction=prediction,
            probability=probability,
            verdict=verdict,
            confidence=confidence
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "model": "goupload_v4",
        "model_loaded": model is not None,
        "model_path": MODEL_PATH
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
