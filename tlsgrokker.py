#!/usr/bin/env python3
import os
import ssl
import socket
import pandas as pd
from sqlalchemy import create_engine
import asyncio
import argparse
from datetime import datetime, timezone
import logging
import ipaddress
import psycopg2

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Timeout for network operations in seconds
DEFAULT_TIMEOUT = 10

# Mapping from original field names to snake_case for database compatibility
FIELD_NAME_MAPPING = {
    'commonName': 'common_name',
    'notBefore': 'not_before',
    'notAfter': 'not_after',
    'subjectAltName': 'subject_alt_name',
    'serialNumber': 'serial_number',
    'OCSP': 'ocsp',
    'caIssuers': 'ca_issuers',
    'crlDistributionPoints': 'crl_distribution_points'
}

def get_server_certificate(host: str, port: int) -> tuple:
    """
    Retrieves the server certificate from the given host and port.

    Args:
        host (str): The hostname or IP address of the server.
        port (int): The port number to connect to.

    Returns:
        tuple: A tuple containing the following elements:
            - host (str): The hostname or IP address of the server.
            - port (int): The port number.
            - parsed_cert (dict): The parsed certificate information.
            - last_checked (datetime): The timestamp when the certificate was retrieved.
            - ptr_record (str or None): The PTR record of the IP address, if available.
    """
    try:
        ip = ipaddress.ip_address(host)
        af = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    except ValueError:
        af = socket.AF_INET

    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(socket.socket(af), server_hostname=host)
    conn.settimeout(DEFAULT_TIMEOUT)
    last_checked = datetime.now(timezone.utc)
    try:
        conn.connect((host, port))
        cert = conn.getpeercert(binary_form=False)
        parsed_cert = parse_certificate(cert)

        # Perform PTR lookup
        try:
            ptr_record = socket.gethostbyaddr(host)[0]
        except socket.herror:
            ptr_record = None

        return (host, port, parsed_cert, last_checked, ptr_record)
    except Exception as e:
        return (host, port, str(e), last_checked, None)
    finally:
        conn.close()

def parse_certificate(cert: dict) -> dict:
    """
    Parses the certificate dictionary into a more structured format using predefined field mappings.

    Args:
        cert (dict): The certificate dictionary returned by `ssl.getpeercert()`.

    Returns:
        dict: A dictionary containing the parsed certificate information.
    """
    def tuple_to_dict(tuples):
        result = {}
        for t in tuples:
            for k, v in t:
                key = FIELD_NAME_MAPPING.get(k, k)  # Apply field mapping
                if key in result:
                    result[key] = [result[key], v] if isinstance(result[key], list) else [result[key]]
                else:
                    result[key] = v
        return result

    subject_dict = tuple_to_dict(cert.get("subject", []))
    issuer_dict = tuple_to_dict(cert.get("issuer", []))

    not_before = datetime.strptime(cert.get("notBefore"), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

    return {
        "subject": format_dict(subject_dict),
        "common_name": subject_dict.get("common_name", ""),
        "issuer": format_dict(issuer_dict),
        "version": cert.get("version"),
        "serial_number": cert.get("serialNumber"),
        "not_before": not_before,
        "not_after": not_after,
        "subject_alt_name": format_tuple_list(cert.get("subjectAltName")),
        "ocsp": format_list(cert.get("OCSP")),
        "ca_issuers": format_list(cert.get("caIssuers")),
        "crl_distribution_points": format_list(cert.get("crlDistributionPoints")),
    }

def format_dict(d: dict) -> str:
    """
    Formats a dictionary into a string representation with each key-value pair.

    Args:
        d (dict): The dictionary to format.

    Returns:
        str: The formatted string representation of the dictionary.
    """
    return ", ".join(f"{k}: {v}" for k, v in d.items())

def format_tuple_list(t: list) -> str:
    """
    Formats a list of tuples into a string.

    Args:
        t (list): The list of tuples to format.

    Returns:
        str: The formatted string representation of the list of tuples.
    """
    if t:
        return ", ".join(f"{k}: {v}" for k, v in t)
    return ""

def format_list(l: list) -> str:
    """
    Converts a list into a comma-separated string.

    Args:
        l (list): The list to format.

    Returns:
        str: The formatted comma-separated string.
    """
    if l:
        return ", ".join(l)
    return ""

async def audit_tls_certificates(file_path: str) -> list:
    """
    Asynchronously audits TLS certificates from a file containing IP addresses and ports.

    Args:
        file_path (str): The path to the file containing IP addresses and ports.

    Returns:
        list: A list of tuples containing the certificate information for each host and port.
    """
    data = []
    loop = asyncio.get_event_loop()
    with open(file_path, "r") as file:
        tasks = []
        for line in file:
            line = line.strip()
            host, port = parse_host_port(line)
            tasks.append(loop.run_in_executor(None, get_server_certificate, host, port))

        responses = await asyncio.gather(*tasks)
        for response in responses:
            data.append(response)
    return data


def parse_host_port(line: str) -> tuple:
    """
    Parses a line to extract host and port.

    Args:
        line (str): The line to parse.

    Returns:
        tuple: A tuple containing the host and port. If the port is not specified or in an improper format, the port will be None.
    """
    parts = line.rsplit('.', 1)
    if len(parts) == 2 and parts[1].isdigit():
        host, port = parts[0], int(parts[1])
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 6:
                return host, port
        except ValueError:
            pass

    parts = line.split(':')
    if len(parts) == 2 and parts[1].isdigit():
        host, port = parts[0], int(parts[1])
        return host, port

    return line, None


def to_dataframe(data: list) -> pd.DataFrame:
    """
    Converts a list of certificate information into a pandas DataFrame.

    Args:
        data (list): A list of tuples containing certificate information.

    Returns:
        pd.DataFrame: A DataFrame containing the certificate information.
    """
    records = []
    for host, port, tls_info, last_checked, ptr_record in data:
        if isinstance(tls_info, dict):
            record = {key: value for key, value in tls_info.items()}
            record["host"] = host
            record["port"] = port
            record["last_checked"] = last_checked
            record["ptr_record"] = ptr_record
            records.append(record)
        else:
            records.append({
                "host": host, "port": port, "error": tls_info, "last_checked": last_checked, "ptr_record": ptr_record
            })
    df = pd.DataFrame(records)
    return df

def save_to_database(df: pd.DataFrame, table_name: str):
    """
    Saves the DataFrame to a PostgreSQL database.

    Args:
        df (pd.DataFrame): The DataFrame to save.
        table_name (str): The name of the table to save the data to.
    """
    db_name = os.getenv("DB_NAME")
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    host = os.getenv("DB_HOST")
    port = os.getenv("DB_PORT")
    connection_string = f"postgresql://{user}:{password}@{host}:{port}/{db_name}"
    engine = create_engine(connection_string)

    try:
        with engine.begin() as connection:
            df.to_sql(table_name, connection, if_exists='replace', index=False)
            logger.info(f"Data successfully saved to the table {table_name}.")
    except Exception as e:
        logger.error(f"An error occurred while saving data to the database: {e}")

def save_to_file(df: pd.DataFrame, file_path: str, file_type: str):
    """
    Saves the DataFrame to a file in the specified format.

    Args:
        df (pd.DataFrame): The DataFrame to save.
        file_path (str): The path to save the file.
        file_type (str): The file type to save the data as. Supported types are 'csv' and 'xls'.

    Raises:
        ValueError: If an unsupported file type is provided.
    """
    if file_type == "csv":
        df.to_csv(file_path, index=False)
        logger.info(f"Data successfully saved to {file_path}.")
    elif file_type == "xls":
        df.to_excel(file_path, index=False)
        logger.info(f"Data successfully saved to {file_path}.")
    else:
        raise ValueError("Unsupported file type. Use 'csv' or 'xls'.")


def main():
    """
    Main function to execute the TLS certificate audit based on command-line arguments.
    """
    parser = argparse.ArgumentParser(description="TLS Certificate Auditor")
    parser.add_argument("--file", required=True, help="File containing IP addresses and ports")
    parser.add_argument("--table", required=True, help="Table name to save data")
    parser.add_argument("--postgres", action="store_true", help="Save data to PostgreSQL database")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--type", choices=["csv", "xls"], help="Output file type")
    parser.add_argument("--stdout", action="store_true", help="Print data to stdout")

    args = parser.parse_args()

    data = asyncio.run(audit_tls_certificates(args.file))
    df = to_dataframe(data)

    if args.postgres:
        save_to_database(df, args.table)
    elif args.output and args.type:
        save_to_file(df, args.output, args.type)
    elif args.stdout:
        print(df.to_string())
    else:
        print("Either --postgres, --output and --type, or --stdout must be specified")

if __name__ == "__main__":
    main()

