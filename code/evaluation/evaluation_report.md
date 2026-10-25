# Evaluation Report

- Request input: `C:\Users\nikit\Downloads\ghost_data_agent_code\dataset\deletion_requests.csv`

## Automated public-sample evaluation

Public sample rows compared: 0 of 32
Sample evaluation: NOT RUN (no matching case_id values in this output; use --requests sample_deletion_requests.csv to evaluate the public sample)

## Structural validation

- Requests: 518
- Output rows: 518
- Evidence records indexed: 3421
- Structural errors: 0
- No structural errors found.

## Limitations and improvements

- This version uses a deterministic, evidence-grounded rules engine rather than a hosted LLM, so token usage is zero and results are reproducible.
- PDF text extraction requires `pypdf`; image OCR requires Pillow, pytesseract, and the Tesseract binary. Missing image OCR is reported as a warning and may reduce evidence coverage.
- Public sample comparisons use exact matching case_id values; runs with no overlap are reported as not run rather than as a 0/0 success.
