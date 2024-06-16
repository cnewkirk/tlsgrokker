#!/usr/bin/env python3
import os
import ssl
import socket
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
import asyncio
import argparse
from datetime import datetime, timezone
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Timeout for network operations in seconds
DEFAULT_TIMEOUT = 10


import ipaddress

def get_server_certificate(host: str, port: int) -> tuple:
    """
    Retrieves the server certificate from the given host and port.
    Args:
        host (str): Hostname or IP address of the server.
        port (int): Port number.
    Returns:
        tuple: A tuple containing the host, port, parsed certificate details, and timestamp.
    """
    # Determine IP address version
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            af = socket.AF_INET
        elif ip.version == 6:
            af = socket.AF_INET6
    except ValueError:
        af = socket.AF_INET  # Default to AF_INET if host is not a valid IP address

    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(socket.socket(af), server_hostname=host)
    conn.settimeout(DEFAULT_TIMEOUT)
    last_checked = datetime.now(timezone.utc)  # Timestamp for when the check was done

    try:
        conn.connect((host, port))
        cert = conn.getpeercert(binary_form=False)
        parsed_cert = parse_certificate(cert)
        return (host, port, parsed_cert, last_checked)
    except Exception as e:
        return (host, port, str(e), last_checked)
    finally:
        conn.close()


def parse_certificate(cert: dict) -> dict:
    """
    Parses the certificate dictionary into a more structured format.
    Args:
        cert (dict): The certificate dictionary.
    Returns:
        dict: A dictionary with parsed certificate details.
    """

    def tuple_to_dict(tuples):
        result = {}
        for t in tuples:
            for k, v in t:
                if k in result:
                    if isinstance(result[k], list):
                        result[k].append(v)
                    else:
                        result[k] = [result[k], v]
                else:
                    result[k] = v
        return result

    subject_dict = tuple_to_dict(cert.get("subject", []))
    common_name = subject_dict.get("commonName", "")
    not_before = datetime.strptime(
        cert.get("notBefore"), "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )

    return {
        "subject": format_dict(subject_dict),
        "commonName": common_name,
        "issuer": format_dict(tuple_to_dict(cert.get("issuer", []))),
        "version": cert.get("version"),
        "serialNumber": cert.get("serialNumber"),
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": format_tuple_list(cert.get("subjectAltName")),
        "OCSP": format_list(cert.get("OCSP")),
        "caIssuers": format_list(cert.get("caIssuers")),
        "crlDistributionPoints": format_list(cert.get("crlDistributionPoints")),
    }


def format_dict(d: dict) -> str:
    """
    Formats a dictionary into a string representation with each key-value pair.
    Args:
        d (dict): The dictionary to format.
    Returns:
        str: A string representation of the dictionary.
    """
    return ", ".join(f"{k}: {v}" for k, v in d.items())


def format_tuple_list(t: list) -> str:
    """
    Formats a list of tuples into a string.
    Args:
        t (list): The list of tuples.
    Returns:
        str: A comma-separated string of the tuples.
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
        str: A comma-separated string of the list items.
    """
    if l:
        return ", ".join(l)
    return ""

async def audit_tls_certificates(file_path: str) -> list:
    data = []
    loop = asyncio.get_event_loop()
    with open(file_path, "r") as file:
        tasks = []
        for line in file:
            line = line.strip()
            if ':' in line and line.count(':') > 1:  # Likely an IPv6 address
                parts = line.rsplit('.', 1)  # Split from the right on the dot for port
                if len(parts) == 2 and parts[1].isdigit():
                    host, port = parts[0], int(parts[1])  # Separate the port
                else:
                    host, port = line, None  # No port specified, treat whole line as address
            else:  # Likely an IPv4 address or hostname
                parts = line.split(':')
                if len(parts) == 2 and parts[1].isdigit():
                    host, port = parts[0], int(parts[1])
                else:
                    host, port = line, None  # No port specified or improper format

            tasks.append(loop.run_in_executor(None, get_server_certificate, host, port))

        responses = await asyncio.gather(*tasks)
        for response in responses:
            data.append(response)
    return data


def to_dataframe(data: list, days_threshold: int) -> pd.DataFrame:
    """
    Converts a list of certificate information into a pandas DataFrame.
    Args:
        data (list): List of tuples containing certificate details.
        days_threshold (int): Number of days to consider for expiring soon status.
    Returns:
        pd.DataFrame: A DataFrame containing the certificate details with expiration flags.
    """
    records = []
    for host, port, tls_info, last_checked in data:
        if isinstance(tls_info, dict):
            record = {"host": host, "port": port}
            record.update(tls_info)
            expiring_soon, expired = check_certificate_expiry(
                tls_info["notAfter"].strftime("%b %d %H:%M:%S %Y %Z"), days_threshold
            )
            record["expiring_soon"] = expiring_soon
            record["expired"] = expired
            record["last_checked"] = last_checked
            records.append(record)
        else:
            records.append(
                {
                    "host": host,
                    "port": port,
                    "error": tls_info,
                    "expiring_soon": None,
                    "expired": None,
                    "last_checked": last_checked,
                }
            )
    df = pd.DataFrame(records)
    return df


def check_certificate_expiry(not_after_str: str, days_threshold: int) -> tuple:
    """
    Determines whether a certificate is expiring soon or has expired.
    Args:
        not_after_str (str): The 'notAfter' date string from the certificate.
        days_threshold (int): The threshold in days to determine if the certificate is expiring soon.
    Returns:
        tuple: Boolean values indicating if the certificate is expiring soon and if it has expired.
    """
    try:
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        current_date = datetime.now(timezone.utc)
        days_until_expiry = (not_after - current_date).days
        expired = days_until_expiry < 0
        expiring_soon = days_until_expiry <= days_threshold
        return expiring_soon, expired
    except Exception as e:
        logger.error(f"Error parsing 'notAfter' date: {not_after_str} - {e}")
        return False, False


def create_table_if_not_exists(connection, table_name: str):
    """
    Creates a database table if it does not already exist.
    Args:
        connection: A SQLAlchemy connection object.
        table_name (str): Name of the table to create.
    """
    create_table_sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        host TEXT NOT NULL,
        ptr TEXT,
        description TEXT,
        port INTEGER NOT NULL,
        subject TEXT,
        commonName TEXT,
        issuer TEXT,
        version INTEGER,
        serialNumber TEXT,
        notBefore TIMESTAMP WITH TIME ZONE,
        notAfter TIMESTAMP WITH TIME ZONE,
        subjectAltName TEXT,
        OCSP TEXT,
        caIssuers TEXT,
        crlDistributionPoints TEXT,
        expiring_soon BOOLEAN,
        expired BOOLEAN,
        error TEXT,
        last_checked TIMESTAMP WITH TIME ZONE,
        PRIMARY KEY (host, port)
    );
    """
    logger.info(f"Creating table {table_name} if it does not exist.")
    connection.execute(text(create_table_sql))
    logger.info(f"Table {table_name} creation checked.")


def save_to_database(df: pd.DataFrame, table_name: str):
    """
    Saves the DataFrame to a PostgreSQL database.
    Args:
        df (pd.DataFrame): The DataFrame containing the data to be saved.
        table_name (str): The name of the database table to save the data.
    """
    db_name = os.getenv("DB_NAME")
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    host = os.getenv("DB_HOST")
    port = os.getenv("DB_PORT")

    # Logging the environment variables (excluding sensitive data)
    logger.info(
        f"DB_NAME: {db_name}, DB_USER: {user}, DB_HOST: {host}, DB_PORT: {port}"
    )
    logger.debug(f"DB_PASSWORD: {'set' if password else 'not set'}")

    # Verify that the environment variables are correctly set
    if not db_name or not user or not password or not host or not port:
        raise ValueError(
            "One or more environment variables for database connection are not set."
        )

    # Debug: Print the connection string (without the password)
    logger.debug(
        f"Connecting to postgresql+pg8000://{user}:<password>@{host}:{port}/{db_name}"
    )

    # Create the SQLAlchemy engine
    engine = create_engine(
        f"postgresql+pg8000://{user}:{password}@{host}:{port}/{db_name}"
    )

    try:
        with engine.begin() as connection:
            result = connection.execute(text("SELECT current_user;"))
            current_user = result.fetchone()[0]
            logger.info(f"Connected to the database as user: {current_user}")

            result = connection.execute(
                text("SELECT has_schema_privilege(current_user, 'public', 'CREATE');")
            )
            can_create = result.fetchone()[0]
            if not can_create:
                raise PermissionError(
                    "User does not have CREATE permission on the public schema."
                )
            logger.info("User has CREATE permission on the public schema.")

            create_table_if_not_exists(connection, f"public.{table_name}")

            result = connection.execute(
                text(f"SELECT to_regclass('public.{table_name}');")
            )
            table_exists = result.fetchone()[0]
            if table_exists:
                logger.info(f"Table public.{table_name} exists.")
            else:
                logger.error(
                    f"Table public.{table_name} does not exist after creation attempt."
                )
                raise Exception(
                    f"Table public.{table_name} does not exist after creation attempt."
                )

            df.to_sql(
                table_name,
                connection,
                if_exists="replace",
                index=False,
                schema="public",
            )
            logger.info(f"Data inserted into table public.{table_name}.")

            result = connection.execute(
                text(f"SELECT COUNT(*) FROM public.{table_name};")
            )
            row_count = result.fetchone()[0]
            logger.info(f"Number of rows in public.{table_name}: {row_count}")

    except SQLAlchemyError as e:
        logger.error(f"Error saving to database: {e}")
        raise


def save_to_file(df: pd.DataFrame, file_path: str, file_type: str):
    """
    Saves the DataFrame to a file in the specified format.
    Args:
        df (pd.DataFrame): The DataFrame to save.
        file_path (str): The path where the file will be saved.
        file_type (str): The type of file to save ('csv' or 'xls').
    """
    if file_type == "csv":
        df.to_csv(file_path, index=False)
    elif file_type == "xls":
        df.to_excel(file_path, index=False)
    else:
        raise ValueError("Unsupported file type. Use 'csv' or 'xls'.")


def filter_dataframe(
    df: pd.DataFrame,
    expiring_soon: bool = None,
    expired: bool = None,
    valid: bool = None,
) -> pd.DataFrame:
    """
    Filters the DataFrame based on certificate validity.
    Args:
        df (pd.DataFrame): The DataFrame to filter.
        expiring_soon (bool): If True, filters for certificates that are expiring soon.
        expired (bool): If True, filters for certificates that have expired.
        valid (bool): If True, filters for certificates that are valid.
    Returns:
        pd.DataFrame: The filtered DataFrame.
    """
    df["expiring_soon"] = df["expiring_soon"].infer_objects()
    df["expired"] = df["expired"].infer_objects()

    df["expiring_soon"] = df["expiring_soon"].astype(bool, copy=False)
    df["expired"] = df["expired"].astype(bool, copy=False)

    if expiring_soon:
        df = df[df["expiring_soon"]]
    if expired:
        df = df[df["expired"]]
    if valid:
        df = df[~df["expiring_soon"] & ~df["expired"]]
    return df


def main():
    """
    Main function to execute the TLS certificate audit based on command-line arguments.
    """
    parser = argparse.ArgumentParser(description="TLS Certificate Auditor")
    parser.add_argument(
        "--file", required=True, help="File containing IP addresses and ports"
    )
    parser.add_argument("--table", required=True, help="Table name to save data")
    parser.add_argument(
        "--postgres", action="store_true", help="Save data to PostgreSQL database"
    )
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--type", choices=["csv", "xls"], help="Output file type")
    parser.add_argument("--stdout", action="store_true", help="Print data to stdout")
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days to flag certificates nearing expiration",
    )
    parser.add_argument(
        "--expiring_soon",
        action="store_true",
        help="Filter to show only expiring soon certificates",
    )
    parser.add_argument(
        "--expired",
        action="store_true",
        help="Filter to show only expired certificates",
    )
    parser.add_argument(
        "--valid", action="store_true", help="Filter to show only valid certificates"
    )
    args = parser.parse_args()

    data = asyncio.run(audit_tls_certificates(args.file))
    df = to_dataframe(data, args.days)
    df = filter_dataframe(df, args.expiring_soon, args.expired, args.valid)

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
