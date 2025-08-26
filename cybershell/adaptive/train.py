from typing import List, Dict, Any
from dataclasses import dataclass
import json, os, glob
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, multilabel_confusion_matrix
from .mapper import MLMapper, FAMILIES
@dataclass
class Sample:
    text: str
    labels: Dict[str, int]
def load_nvd_json_folder(folder: str) -> List[Sample]:
    samples: List[Sample] = []
    for path in sorted(glob.glob(os.path.join(folder, "nvdcve-1.1-*.json"))):
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for it in data.get('CVE_Items', []):
            descs = it.get('cve',{}).get('description',{}).get('description_data',[])
            text = " ".join(d.get('value','') for d in descs)
            if not text or text.startswith("** REJECT **"):
                continue
            labs = {k:0 for k in FAMILIES}
            low = text.lower()
            if "sql" in low: labs['sqli']=1
            if "cross-site scripting" in low or "xss" in low: labs['xss']=1
            if "template" in low or "jinja" in low or "freemarker" in low: labs['ssti']=1
            if "insecure direct object" in low or "idor" in low: labs['idor']=1
            if "server-side request forgery" in low or "ssrf" in low: labs['ssrf']=1
            if "remote code execution" in low or "rce" in low: labs['rce']=1
            if "deserialization" in low or "xstream" in low: labs['deserialization']=1
            if "authentication" in low or "auth" in low: labs['auth']=1
            if "csrf" in low: labs['csrf']=1
            if "directory traversal" in low or "../" in low: labs['lfi']=1
            if "file inclusion" in low: labs['rfi']=1
            if "open redirect" in low: labs['open_redirect']=1
            if "jwt" in low or "jws" in low: labs['jwt']=1
            if any(labs.values()):
                samples.append(Sample(text=text, labels=labs))
    return samples
def train_mapper(samples: List[Sample], test_size=0.2, random_state=42):
    X = [s.text for s in samples]
    Y = np.array([[s.labels.get(f,0) for f in FAMILIES] for s in samples], dtype=int)
    Xtr, Xte, Ytr, Yte = train_test_split(X, Y, test_size=test_size, random_state=random_state, stratify=(Y.sum(axis=1)>0))
    model = MLMapper()
    model.fit(Xtr, Ytr)
    Yp = (model.predict_proba(Xte) >= 0.5).astype(int)
    report = classification_report(Yte, Yp, target_names=FAMILIES, zero_division=0, output_dict=True)
    cm = multilabel_confusion_matrix(Yte, Yp)
    return model, report, cm
