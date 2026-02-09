"""
Sample calculator module with intentional issues for code review demonstration.
"""


def add(a, b):
    """Add two numbers."""
    return a + b


def subtract(a, b):
    """Subtract b from a."""
    return a - b


def multiply(a, b):
    """Multiply two numbers."""
    return a * b


def divide(a, b):
    """Divide a by b."""
    # BUG: No zero division check
    return a / b


def calculate_average(numbers):
    """Calculate average of a list of numbers."""
    # BUG: Doesn't handle empty list
    total = 0
    for num in numbers:
        total = total + num
    return total / len(numbers)


def is_even(n):
    """Check if number is even."""
    # CODE SMELL: Using modulo when bitwise would be faster
    if n % 2 == 0:
        return True
    else:
        return False


def factorial(n):
    """Calculate factorial."""
    # BUG: No input validation
    # PERFORMANCE: Inefficient recursion
    if n == 0:
        return 1
    return n * factorial(n - 1)


class User:
    """User class with some issues."""

    def __init__(self, username, password):
        # SECURITY: Storing password in plain text
        self.username = username
        self.password = password
        self.loggedIn = False  # STYLE: Should be snake_case

    def login(self, password):
        """Login user."""
        # SECURITY: Vulnerable to timing attacks
        if password == self.password:
            self.loggedIn = True
            return True
        return False

    def get_info(self):
        """Get user info."""
        # SECURITY: Exposing password in string representation
        return f"User: {self.username}, Password: {self.password}"
