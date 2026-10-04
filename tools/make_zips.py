"""Packs each project folder, its report, its study Q&A and the deployment guide into zips/<project>.zip.
Run from the repository root: python tools/make_zips.py"""
import glob
import os
import zipfile

SKIP_DIRS = {"data", "sample_data", "venv", "__pycache__"}
os.makedirs("zips", exist_ok=True)
for fam in ("backup-recovery", "conflict-early-warning"):
    for proj in sorted(glob.glob(f"{fam}/*/")):
        name = os.path.basename(proj.rstrip("/"))
        pid = name.split("-")[0]
        extras = glob.glob(f"reports/{pid}_*_Report.docx") + glob.glob(f"reports/study-qa/{pid}_*_Study_QA.docx") + ["DEPLOYMENT_GUIDE.md"]
        out = f"zips/{name}.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(proj):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in files:
                    if not f.endswith(".pyc"):
                        full = os.path.join(root, f)
                        z.write(full, os.path.join(name, os.path.relpath(full, proj)))
            for e in extras:
                z.write(e, os.path.join(name, os.path.basename(e)))
        print(out, os.path.getsize(out) // 1024, "KB")
