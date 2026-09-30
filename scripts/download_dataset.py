"""Download only the pinned public dataset; never fetch submitted scan URLs."""

import hashlib, io, zipfile, urllib.request
from pathlib import Path

url = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
with urllib.request.urlopen(url, timeout=90) as response:
    raw = response.read(30_000_000)
z = zipfile.ZipFile(io.BytesIO(raw))
name = "PhiUSIIL_Phishing_URL_Dataset.csv"
data = z.read(name)
expected = "a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6"
actual = hashlib.sha256(data).hexdigest()
if actual != expected:
    raise SystemExit("Dataset changed. Inspect its provenance before retraining.")
p = Path("ml/data")
p.mkdir(exist_ok=True, parents=True)
(p / name).write_bytes(data)
print("Verified dataset saved to", p / name)
