"""
Author: Edunbar2
Version: 1.0
Description: SecureTCP session tracking active sessions
"""

from secureTCP.transport.connection import SecureTCPConnection

_connection_table = {}

def get_connection(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> SecureTCPConnection:
    """
    Retrieve a connection from the table using a 4-tuple key.

    Parameters:
        src_ip (str): Source IP address.
        src_port (int): Source port number.
        dst_ip (str): Destination IP address (local host).
        dst_port (int): Destination port number.

    Returns:
        The connection object if found, else None.
    """
    key = (src_ip, src_port, dst_ip, dst_port)
    return _connection_table.get(key)

def create_connection(conn_obj: SecureTCPConnection) -> SecureTCPConnection:
    """
    Add a new connection to the table.

    Parameters:
        :param conn_obj: An instance of SecureTCPConnection or equivalent.

    Returns:
        The stored connection object.


    """
    key = (conn_obj.src_ip, conn_obj.src_port, conn_obj.dst_ip, conn_obj.dst_port)
    _connection_table[key] = conn_obj
    return conn_obj

def remove_connection(src_ip: str, src_port: int, dst_ip: str, dst_port: int):
    """
    Remove a connection from the table, if it exists.

    Parameters:
        src_ip (str): Source IP address.
        src_port (int): Source port number.
        dst_ip (str): Destination IP address.
        dst_port (int): Destination port number.
    """
    key = (src_ip, src_port, dst_ip, dst_port)
    _connection_table.pop(key, None)

def list_connections():
    """
    Return a shallow copy of the current connection table.

    Returns:
        dict: A copy of the internal connection dictionary.
    """
    return _connection_table.copy()
