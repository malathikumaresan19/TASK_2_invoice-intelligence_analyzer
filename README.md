# Signal Desk

Invoice Intelligence Analyzer is a dependency-free browser prototype for evidence-aware customer support intake. It analyzes customer messages alongside uploaded invoices, screenshots, PDFs, and product images.

## Run

Open `index.html` in a browser. No build step or server is required.

## Included safeguards

- Extracts order IDs, dates, amounts, error codes, and product signals from the customer message and uploaded text evidence.
- Uses a deterministic OCR-style evidence adapter for screenshots, PDFs, invoices, and product images in the prototype; filenames containing `blur`, `low-quality`, or `unclear` exercise the low-confidence path.
- Compares message claims with evidence and asks for clarification on conflicts or missing values.
- Rejects unsafe file extensions and filenames that represent embedded prompt-injection instructions.
- Masks order-like numbers, email addresses, and amounts in the visible activity log.
- Simulates the 30-second background queue path with a file named `slow-invoice.pdf`.
- Shows a 30-day evidence retention policy in the interface.

For production, replace `inferEvidence` with a server-side OCR provider, virus scanner, content-disarm pipeline, queue, encrypted object storage, and scheduled retention deletion. Never trust client-side validation as a security boundary.
