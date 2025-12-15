# fuzz/fuzz_string_calculator.py

import sys
import os

# Add the src directory to the system path
sys.path.append(os.path.join(os.path.dirname(__file__), "../src"))

import atheris

# Import based on the project directory structure
from calculator.string_calculator import StringCalculator, InvalidExpressionException

# Global variable to count execution iterations
TEST_COUNT = 0


def TestOneInput(data):
    global TEST_COUNT
    TEST_COUNT += 1

    # Create a provider to generate random data
    fdp = atheris.FuzzedDataProvider(data)

    # Fix: ConsumeUnicodeString(1024) -> ConsumeString(1024)
    # Consume a random string (expression) up to 1024 bytes
    expression = fdp.ConsumeString(1024)

    calc = StringCalculator()

    try:
        # Execute the calculate method of StringCalculator
        calc.calculate(expression)

    except InvalidExpressionException:
        pass

    # ValueError (e.g., division by zero) is considered expected behavior
    # in this context/lecture intent, so it is ignored.
    except ValueError:
        pass
    except Exception as e:
        # Print the input value (expression) upon crash and re-raise the exception
        print("\n=== CRASH DETECTED IN STRING_CALCULATOR ===")
        print(f"Test Count: {TEST_COUNT}")
        print(f"Expression: '{expression}'")
        print("=========================================")

        # Report any other unexpected errors as a "crash"
        raise e


if __name__ == "__main__":
    # Setup instrumentation and start the Fuzzer
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
