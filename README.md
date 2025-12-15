# Instructions

## 1. Fork and Run Workflow
1. Fork this repository.
2. Go to the **Actions** tab.
3. Click the green button labeled **"I understand my workflows, go ahead and enable them"**.
4. Select **"Python Atheris Fuzzing"** from the left sidebar.
5. Click the **Run workflow** button.
6. Inspect the logs and output.

<img width="1175" height="606" alt="image" src="https://github.com/user-attachments/assets/782dad16-1d92-426c-9b46-8213dd63bac1" />
<img width="836" height="454" alt="image" src="https://github.com/user-attachments/assets/3b06e9eb-65bf-4b3b-936a-7e2f16fbf852" />

## 2. Trigger a Crash
*Recommendation: Clone your forked repository to your local machine for the following steps.*

1. Uncomment the `modulo` function code in the following files:
   - `src/calculator/calculator.py`
   - `fuzz/fuzz_calculator.py`
2. Push your changes. This will automatically trigger the GitHub Action, which is expected to fail.
3. Click on the failed workflow, select **fuzzing** under the "Jobs" section, and check the failed step labeled **"Fuzzing (Generate Corpus)"**.
4. The error details and the specific input that caused the crash will be displayed. Use this information to fix the code.

<img width="399" height="501" alt="image" src="https://github.com/user-attachments/assets/90409fda-725b-4d2e-a24c-261b26d2c920" />

## 3. Enable Fuzzing for Other Files
Try editing the configuration to enable fuzzing for other files.

1. First, ensure that the Fuzzing process runs successfully.
2. Next, implement the necessary error handling (likely in two places).3. Finally, ensure that the code explicitly raises `InvalidExpressionException` for invalid inputs.

### Hints
**Files requiring modification:**
- `.github/workflows/python_fuzz.yml`
- `fuzz/fuzz_string_calculator.py`
- `fuzz/repro_coverage.py`
- `src/calculator/string_calculator.py`