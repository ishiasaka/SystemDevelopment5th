import sys
import os

# Add the src directory to the system path to allow importing the target module
sys.path.append(os.path.join(os.path.dirname(__file__), "../src"))
from fuzz_calculator import TestOneInput

def run_corpus(corpus_dir):
    """
    Reads files from the specified corpus directory and replays them
    against the fuzzing target function (TestOneInput).
    """
    if not os.path.exists(corpus_dir):
        print(f"Skipping {corpus_dir}")
        return

    files = os.listdir(corpus_dir)
    # Iterate through all files in the directory sequentially
    for fname in files:
        path = os.path.join(corpus_dir, fname)
        # Skip directories or hidden files (e.g., .gitignore)
        if not os.path.isfile(path) or fname.startswith("."):
            continue
            
        with open(path, "rb") as f:
            data = f.read()
        
        try:
            # Replay the input data against the target function
            TestOneInput(data)
        except SystemExit:
            continue
        except:
            # Critical for coverage: Ignore errors and continue to the next input.
            # We want to measure the code path executed even if the input causes a crash.
            pass

if __name__ == "__main__":
    # Process all directories provided as command-line arguments (e.g., corpus_calc, crashes)
    if len(sys.argv) > 1:
        for d in sys.argv[1:]:
            run_corpus(d)