python3 - <<'PY'
import os, joblib
class AdaptiveEnsemblePredictor: pass
m = joblib.load(os.getenv("MODEL_PATH","intrusion_detection_model.joblib"))
print("ROOT TYPE:", type(m))
for name in ("meta_learner","model","estimator","pipeline","best_estimator_","clf","base_estimator"):
    v = getattr(m,name,None)
    if v is None: continue
    print(f"{name}: type={type(v)} has_predict={hasattr(v,'predict')} has_proba={hasattr(v,'predict_proba')}")
    steps = getattr(v,'steps',None)
    if steps: print(f"{name}.steps len:", len(steps))
    ns = getattr(v,'named_steps',None)
    if ns: print(f"{name}.named_steps:", list(ns.keys()))
PY