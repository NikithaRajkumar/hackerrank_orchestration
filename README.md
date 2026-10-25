# Ghost Data Still Exists — Deletion Audit Agent

## What it does
- Reads `dataset/deletion_requests.csv` by default, identity history, policy, system activity, and `evidence_files.csv`.
- Extracts records from JSON, SQL, logs, text, and (optionally) PDF/image evidence.
- Resolves current and historical identifiers.
- Uses `audit_at` as the evidence cutoff.
- Produces root-level `output.csv` with the required schema and preserves the input request order.
- Runs structural validation and writes `code/evaluation/evaluation_report.md` and `code/evaluation/usage_report.md`.

## Run
Place the `code/` directory in the cloned challenge repository, preserving the repository's `dataset/` folder.

```bash
python code/main.py
```

Run against the 32 public requests and compare predictions with `sample_output.csv`:

```bash
python code/main.py --dataset dataset --requests sample_deletion_requests.csv --output output.csv
```

For the full dataset, the first command uses all 518 requests. The sample command uses the public request CSV; it does not use `sample_output.csv` as input. Both runs evaluate overlapping IDs against the gold output and write evaluation results to `code/evaluation/evaluation_report.md`.

Python 3.10+ is supported. Core execution uses the standard library.

### Evidence readers
PDF evidence requires:

```bash
pip install pypdf
```

Image OCR requires the Tesseract system binary and:

```bash
pip install pillow pytesseract
```

If a reader is unavailable, the script prints a warning and reports incomplete modality coverage; predictions may miss evidence present only in those files. The current image evidence is supplied as screenshots, so configure Tesseract to enable programmatic OCR.

## Important
The agent applies the supplied deletion policy to evidence available at or before each request's `audit_at`. The sample evaluation reports only IDs actually shared by the generated output and gold sample; a full-dataset run will explicitly indicate when it has no public-sample ID overlap. Run the sample command to measure public-sample accuracy.

## Submission packaging
Create a submission ZIP from the project root with Python's standard library:

```bash
python -c "from zipfile import ZipFile, ZIP_DEFLATED; z=ZipFile('submission.zip','w',ZIP_DEFLATED); z.write('README.md'); z.write('code/main.py','code/main.py'); z.close()"
```

The archive contains only `README.md` and `code/main.py`. Do not include `dataset/`, virtual environments, caches, build artifacts, or nested archives. Upload root `output.csv` separately. Upload the repository's `log.txt` as the chat transcript; do not fabricate a transcript or include secrets.
