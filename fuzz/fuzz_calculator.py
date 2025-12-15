import sys
import os

# Add the src directory to the system path
sys.path.append(os.path.join(os.path.dirname(__file__), "../src"))

import atheris
# Import based on the project directory structure
from calculator.calculator import Calculator, InvalidInputException

# Added: Global variable to count execution iterations
TEST_COUNT = 0

def TestOneInput(data):
   # Added: Access the global variable and increment the count
   global TEST_COUNT
   TEST_COUNT += 1
    
   # Create a provider to generate random data
   fdp = atheris.FuzzedDataProvider(data)
    
   # Consume two random integers
   val_a = fdp.ConsumeInt(4)
   val_b = fdp.ConsumeInt(4)
   # Determine the operation (add, subtract, etc.) using a random number between 0 and 4
   op = fdp.ConsumeIntInRange(0, 4)
    
   calc = Calculator()

   try:
      if op == 0:
         calc.add(val_a, val_b)
      elif op == 1:
         calc.subtract(val_a, val_b)
      elif op == 2:
         calc.multiply(val_a, val_b)
      elif op == 3:
         calc.divide(val_a, val_b)
      # TODO: Implement modulo operation
      # elif op == 4:
      #    calc.modulo(val_a, val_b)

            
   except (ValueError, InvalidInputException):
      # Ignore expected errors such as division by zero or out-of-range input
      pass
   except Exception as e:
      # Print input values upon crash and re-raise the exception
      print(f"\n=== CRASH DETECTED ===")
      # Added: Print the execution count
      print(f"Test Count: {TEST_COUNT}")
      print(f"val_a: {val_a}")
      print(f"val_b: {val_b}")
      print(f"op   : {op}")
      print(f"======================")
      print(f"Unexpected exception💥: {e} 😱")
        
      # Report any other unexpected errors as a "crash"
      raise e

if __name__ == "__main__":
   # Setup instrumentation and start the Fuzzer
   atheris.instrument_all()
   atheris.Setup(sys.argv, TestOneInput)
   atheris.Fuzz()