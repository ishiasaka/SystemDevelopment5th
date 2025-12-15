"""
A simple calculator module with basic arithmetic operations.
"""


class InvalidInputException(Exception):
    """Exception raised when input values are outside the valid range."""

    pass


UPPER_LIMIT = 1e6
LOWER_LIMIT = -1e6


def validate_input(values: list[int | float]) -> None:
    for value in values:
        if value < LOWER_LIMIT or value > UPPER_LIMIT:
            raise InvalidInputException(
                f"Input value {value} is outside the valid range [{LOWER_LIMIT}, {UPPER_LIMIT}]."
            )


class Calculator:
    """Calculator class providing basic arithmetic operations."""

    def add(self, a: int | float, b: int | float) -> int | float:
        """Add two numbers.

        Args:
            a: First number
            b: Second number

        Returns:
            Sum of a and b

        Raises:
            InvalidInputException: If any input is outside valid range
        """
        validate_input([a, b])
        return a + b

    def subtract(self, a: int | float, b: int | float) -> int | float:
        """Subtract b from a.

        Args:
            a: First number
            b: Second number

        Returns:
            Difference of a and b

        Raises:
            InvalidInputException: If any input is outside valid range
        """
        validate_input([a, b])
        return a - b

    def multiply(self, a: int | float, b: int | float) -> int | float:
        """Multiply two numbers.

        Args:
            a: First number
            b: Second number

        Returns:
            Product of a and b

        Raises:
            InvalidInputException: If any input is outside valid range
        """
        validate_input([a, b])
        return a * b

    def divide(self, a: int | float, b: int | float) -> float:
        """Divide a by b.

        Args:
            a: Numerator
            b: Denominator

        Returns:
            Quotient of a and b

        Raises:
            InvalidInputException: If any input is outside valid range
            ValueError: If b is zero
        """
        validate_input([a, b])
        if b == 0:
            raise ValueError("Cannot divide by zero")
        return a / b

    # TODO: Implement modulo operation
    # def modulo(self, a, b):
    #     """Calculate a modulo b.

    #     Args:
    #         a: First number
    #         b: Second number

    #     Returns:
    #         Remainder of a divided by b

    #     Raises:
    #         InvalidInputException: If any input is outside valid range
    #         ValueError: If b is zero
    #     """
    #     return a % b

