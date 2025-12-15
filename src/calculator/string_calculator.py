# src/calculator/string_calculator.py

from calculator.calculator import Calculator


class InvalidExpressionException(Exception):
    """Raised when the expression format is invalid."""

    pass


class StringCalculator:
    def __init__(self):
        self.calc = Calculator()

    def calculate(self, expression: str) -> float:
        """
        Format: "Number Operator Number" (例: "10 + 2.5")
        """

        parts = expression.split(" ")

        val_a = float(parts[0])
        val_b = float(parts[2])

        op = parts[1]

        if op == "+":
            return self.calc.add(val_a, val_b)
        elif op == "-":
            return self.calc.subtract(val_a, val_b)
        elif op == "*":
            return self.calc.multiply(val_a, val_b)
        elif op == "/":
            return self.calc.divide(val_a, val_b)
        elif op == "%":
            return self.calc.modulo(val_a, val_b)
        else:
            raise InvalidExpressionException(
                f"System Error: Unsupported operator '{op}'"
            )
