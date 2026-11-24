import re

OPERATORS = (">=", "<=", "!=", ">", "<")
NUMBER = re.compile(r"^-?\d+(\.\d+)?$")


class SelectorError(ValueError):
    pass


def number(value):
    if isinstance(value, bool):
        raise SelectorError(f"{value!r} is not a number")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and NUMBER.match(value.strip()):
        return float(value)
    raise SelectorError(f"{value!r} is not a number")


def leading_operator(text):
    for operator in OPERATORS:
        if text.startswith(operator):
            return operator
    return None


def compare(fact, expression):
    if isinstance(expression, list):
        return any(compare(fact, item) for item in expression)
    if isinstance(expression, str):
        operator = leading_operator(expression)
        if operator is None:
            return str(fact) == expression
        operand = expression[len(operator):].strip()
        if operator == "!=":
            return str(fact) != operand
        left, right = number(fact), number(operand)
        return {">=": left >= right, "<=": left <= right, ">": left > right, "<": left < right}[operator]
    if isinstance(expression, bool):
        return fact is expression
    if isinstance(expression, (int, float)):
        return number(fact) == float(expression)
    raise SelectorError(f"unsupported selector value {expression!r}")


def matches(selector, facts):
    for name, expression in selector.items():
        if name not in facts:
            return False
        try:
            if not compare(facts[name], expression):
                return False
        except SelectorError:
            return False
    return True


def validate(selector):
    if not isinstance(selector, dict):
        raise SelectorError("a selector is an object")
    for name, expression in selector.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9-]+", name):
            raise SelectorError(f"bad fact name {name!r}")
        items = expression if isinstance(expression, list) else [expression]
        if not items:
            raise SelectorError(f"{name}: empty list")
        for item in items:
            if not isinstance(item, (str, int, float, bool)):
                raise SelectorError(f"{name}: unsupported value {item!r}")
            operator = leading_operator(item) if isinstance(item, str) else None
            if operator and operator != "!=":
                number(item[len(operator):].strip())
