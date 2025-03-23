"""
Author: Edunbar2
Version: 1.0
Description: SecureTCP v1.0 flag logic
"""

#Flags
SYN = 0b00000001
ACK = 0b00000010
FIN = 0b00000100
RST = 0b00001000
SEC = 0b00010000
PSH = 0b00100000
URG = 0b01000000
RES = 0b10000000

def has_flag(value, flag)-> bool:
    """
       Check if a specific flag is set in a flag byte.

       Parameters:
           value (int): The full flag's byte.
           flag (int): The flag to check.

       Returns:
           bool: True if the flag is set, False otherwise.
       """
    return (value & flag) != 0

def set_flag(value, flag) -> int:
    """
        Set a specific flag in a flag byte.

        Parameters:
            value (int): The original flag's byte.
            flag (int): The flag to set.

        Returns:
            int: Updated flags byte with the flag set.
        """
    return value | flag

def clear_flag(value, flag)-> int:
    """
        Clear a specific flag in a flag byte.

        Parameters:
            value (int): The original flag's byte.
            flag (int): The flag to clear.

        Returns:
            int: Updated flags byte with the flag cleared.
        """
    return value & ~flag


def describe_flags(value: int):
    return [name for name, bit in {
        "SYN": SYN, "ACK": ACK, "FIN": FIN, "RST": RST,
        "SEC": SEC, "PSH": PSH, "URG": URG, "RES": RES
    }.items() if has_flag(value, bit)]