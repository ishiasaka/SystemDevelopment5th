"""
Test suite for the Calculator class.
"""

import pytest
from calculator.calculator import Calculator, InvalidInputException, validate_input


class TestAddition:
    """Tests for the add method."""

    def test_add_positive_numbers(self):
        """Test adding two positive numbers."""
        # Arrange
        calc = Calculator()
        a = 5
        b = 3
        expected = 8

        # Act
        result = calc.add(a, b)

        # Assert
        assert result == expected

    def test_add_negative_numbers(self):
        """Test adding two negative numbers."""
        # Arrange
        calc = Calculator()
        a = -5
        b = -3
        expected = -8

        # Act
        result = calc.add(a, b)

        # Assert
        assert result == expected

    def test_add_positive_and_negative(self):
        """Test adding positive and negative numbers."""
        # Arrange
        calc = Calculator()
        a = 5
        b = -3
        expected = 2

        # Act
        result = calc.add(a, b)

        # Assert
        assert result == expected

    def test_add_negative_and_positive(self):
        """Test adding negative and positive numbers."""
        # Arrange
        calc = Calculator()
        a = -5
        b = 3
        expected = -2

        # Act
        result = calc.add(a, b)

        # Assert
        assert result == expected

    def test_add_positive_with_zero(self):
        """Test adding positive number with zero."""
        # Arrange
        calc = Calculator()
        a = 5
        b = 0
        expected = 5

        # Act
        result = calc.add(a, b)

        # Assert
        assert result == expected

    def test_add_zero_with_positive(self):
        """Test adding zero with positive number."""
        # Arrange
        calc = Calculator()
        a = 0
        b = 5
        expected = 5

        # Act
        result = calc.add(a, b)

        # Assert
        assert result == expected

    def test_add_floats(self):
        """Test adding floating point numbers."""
        # Arrange
        calc = Calculator()
        a = 2.5
        b = 3.7
        expected = 6.2

        # Act
        result = calc.add(a, b)

        # Assert
        assert result == pytest.approx(expected)


class TestSubtraction:
    """Tests for the subtract method."""

    def test_subtract_positive_numbers(self):
        """Test subtracting positive numbers."""
        # TODO: Implement
        calc = Calculator()
        assert calc.subtract(5, 3) == 2


class TestMultiplication:
    """Tests for the multiply method."""

    def test_multiply_positive_numbers(self):
        """Test multiplying positive numbers."""
        # TODO: Implement
        calc = Calculator()
        assert calc.multiply(5, 3) == 15


class TestDivision:
    """Tests for the divide method."""

    def test_divide_positive_numbers(self):
        """Test dividing positive numbers."""
        # TODO: Implement
        calc = Calculator()
        assert calc.divide(6, 3) == pytest.approx(2.0)

    def test_divide_negative_numbers(self):
        """Test dividing negative numbers."""
        calc = Calculator()
        assert calc.divide(-6, -3) == pytest.approx(2.0)

    def test_divide_negative_and_positive(self):
        """Test dividing negative by positive number."""
        calc = Calculator()
        assert calc.divide(-6, 3) == pytest.approx(-2.0)

    def test_divide_zero_number(self):
        """Test dividing zero by a positive number."""
        calc = Calculator()
        assert calc.divide(0, 5) == pytest.approx(0.0)

    def test_divide_by_zero(self):
        calc = Calculator()
        with pytest.raises(ValueError, match=r"\bCannot divide by zero\b"):
            calc.divide(5, 0)


class TestExceedingValue:
    calc = Calculator()

    def test_add_both_exceeding_value(self):
        A = 1e6 + 1, -1e6 - 1
        for a in A:
            for b in A:
                with pytest.raises(InvalidInputException):
                    self.calc.add(a, b)

    def test_add_one_exceeding_value(self):
        A = 1e6 + 1, -1e6 - 1
        B = 5, -3
        for a in A:
            for b in B:
                with pytest.raises(InvalidInputException):
                    self.calc.add(a, b)

    def test_subtract_both_exceeding_value(self):
        A = 1e6 + 1, -1e6 - 1
        for a in A:
            for b in A:
                with pytest.raises(InvalidInputException):
                    self.calc.subtract(a, b)

    def test_subtract_one_exceeding_value(self):
        A = 1e6 + 1, -1e6 - 1
        B = 5, -3
        for a in A:
            for b in B:
                with pytest.raises(InvalidInputException):
                    self.calc.subtract(a, b)
                    self.calc.subtract(b, a)

    def test_multiply_both_exceeding_value(self):
        A = 1e6 + 1, -1e6 - 1
        for a in A:
            for b in A:
                with pytest.raises(InvalidInputException):
                    self.calc.multiply(a, b)

    def test_multiply_one_exceeding_value(self):
        A = 1e6 + 1, -1e6 - 1
        B = 5, -3
        for a in A:
            for b in B:
                with pytest.raises(InvalidInputException):
                    self.calc.multiply(a, b)
                    self.calc.multiply(b, a)

    def test_divide_both_exceeding_value(self):
        A = 1e6 + 1, -1e6 - 1
        for a in A:
            for b in A:
                with pytest.raises(InvalidInputException):
                    self.calc.divide(a, b)

    def test_divide_one_exceeding_value(self):
        A = 1e6 + 1, -1e6 - 1
        B = 5, -3
        for a in A:
            for b in B:
                with pytest.raises(InvalidInputException):
                    self.calc.divide(a, b)
                    self.calc.divide(b, a)


class TestValidateValue:
    def test_validate_value_within_range(self):
        validate_input([500, -300, 0, 1e6, -1e6])  # Should not raise an exception

    def test_validate_value_exceeding_upper_limit(self):
        with pytest.raises(
            InvalidInputException,
            match="Input value 1000001.0 is outside the valid range",
        ):
            validate_input([1e6 + 1])

    def test_validate_value_exceeding_lower_limit(self):
        with pytest.raises(
            InvalidInputException,
            match="Input value -1000001.0 is outside the valid range",
        ):
            validate_input([-1e6 - 1])
