#!/usr/bin/env python3
import os
import ssl
import socket
import pandas as pd
import psycopg2
import asyncio
import argparse
from datetime import datetime, timezone

# Timeout for network operations in seconds
DEFAULT_TIMEOUT = 10

def get_server_certificate(host, port):
    """
    Retrieve and parse the TLS certificate for a given host and port.

    Args:
        host (str): The hostname or IP address.
        port (int): The port number.

    Returns:
        tuple: A tuple containing host, port, and the parsed certificate as a dictionary, or an error message if an exception occurs.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    conn.settimeout(DEFAULT_TIMEOUT)
    try:
        conn.connect((host, port))
        cert = conn.getpeercert(binary_form=False)
        parsed_cert = parse_certificate(cert)
        return (host, port, parsed_cert)
    except Exception as e:
        return (host, port, str(e))
    finally:
        conn.close()

def parse_certificate(cert):
    """
    Parse a TLS certificate into a dictionary with useful fields.

    Args:
        cert (dict): The TLS certificate as a dictionary.

    Returns:
        dict: A dictionary with parsed certificate details or the original certificate if it's not a dictionary.
    """
    def tuple_to_dict(tuples):
        """Convert a list of tuples into a dictionary."""
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

    subject_dict = tuple_to_dict(cert.get('subject', []))
    common_name = subject_dict.get('commonName', '')
    
    if isinstance(cert, dict):
        return {
            'subject': format_dict(subject_dict),
            'commonName': common_name,
            'issuer': format_dict(tuple_to_dict(cert.get('issuer', []))),
            'version': cert.get('version'),
            'serialNumber': cert.get('serialNumber'),
            'notBefore': cert.get('notBefore'),
            'notAfter': cert.get('notAfter'),
            'subjectAltName': format_tuple_list(cert.get('subjectAltName')),
            'OCSP': format_list(cert.get('OCSP')),
            'caIssuers': format_list(cert.get('caIssuers')),
            'crlDistributionPoints': format_list(cert.get('crlDistributionPoints'))
        }
    return cert

def format_dict(d):
    """
    Format a dictionary into a human-readable string.

    Args:
        d (dict): The dictionary to format.

    Returns:
        str: The formatted string.
    """
    return ', '.join(f'{k}: {v}' for k, v in d.items())

def format_tuple_list(t):
    """
    Format a list of tuples into a human-readable string.

    Args:
        t (list): The list of tuples.

    Returns:
        str: The formatted string.
    """
    if t:
        return ', '.join(f'{k}: {v}' for k, v in t)
    return ''

def format_list(l):
    """
    Format a list into a human-readable string.

    Args:
        l (list): The list to format.

    Returns:
        str: The formatted string.
    """
    if l:
        return ', '.join(l)
    return ''

async def audit_tls_certificates(file_path):
    """
    Audit TLS certificates for the hosts and ports listed in the given file.

    Args:
        file_path (str): Path to the file containing host:port pairs.

    Returns:
        list: A list of tuples containing host, port, and the parsed certificate details or an error message.
    """
    data = []
    loop = asyncio.get_event_loop()
    with open(file_path, 'r') as file:
        tasks = []
        for line in file:
            host, port = line.strip().split(':')
            tasks.append(loop.run_in_executor(None, get_server_certificate, host, int(port)))
        responses = await asyncio.gather(*tasks)
        for response in responses:
            data.append(response)
    return data

def check_certificate_expiry(not_after_str, days_threshold):
    """
    Check if the TLS certificate is expiring soon or already expired.

    Args:
        not_after_str (str): The 'notAfter' date from the TLS certificate.
        days_threshold (int): The number of days before expiration to flag the certificate.

    Returns:
        tuple: A tuple containing two boolean values: expiring_soon, expired.
    """
    try:
        not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        current_date = datetime.now(timezone.utc)
        days_until_expiry = (not_after - current_date).days
        expired = days_until_expiry < 0
        expiring_soon = expired or days_until_expiry <= days_threshold
        return expiring_soon, expired
    except Exception as e:
        print(f"Error parsing 'notAfter' date: {not_after_str} - {e}")
        return False, False

def to_dataframe(data, days_threshold):
    """
    Convert TLS certificate data to a pandas DataFrame and add expiry columns.

    Args:
        data (list): The list of TLS certificate data tuples.
        days_threshold (int): The number of days before expiration to flag certificates.

    Returns:
        pandas.DataFrame: A DataFrame containing the TLS certificate data.
    """
    records = []
    for host, port, tls_info in data:
        if isinstance(tls_info, dict):
            record = {'host': host, 'port': port}
            record.update(tls_info)
            expiring_soon, expired = check_certificate_expiry(tls_info.get('notAfter', ''), days_threshold)
            record['expiring_soon'] = expiring_soon
            record['expired'] = expired
            records.append(record)
        else:
            records.append({'host': host, 'port': port, 'error': tls_info, 'expiring_soon': None, 'expired': None})
    df = pd.DataFrame(records)
    return df

def save_to_database(df, table_name):
    """
    Save the DataFrame to a PostgreSQL database table.

    Args:
        df (pandas.DataFrame): The DataFrame to save.
        table_name (str): The name of the database table.
    """
    db_name = os.getenv('DB_NAME')
    user = os.getenv('DB_USER')
    password = os.getenv('DB_PASSWORD')
    host = os.getenv('DB_HOST')
    port = os.getenv('DB_PORT')
    conn = psycopg2.connect(database=db_name, user=user, password=password, host=host, port=port)
    create_table_if_not_exists(conn, table_name)  # Ensure the table exists
    df.to_sql(table_name, conn, if_exists='replace', index=False)

def create_table_if_not_exists(conn, table_name):
    """
    Create the table in PostgreSQL if it does not already exist.

    Args:
        conn: A psycopg2 connection object.
        table_name (str): The name of the table to create.
    """
    create_table_sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        subject TEXT,
        commonName TEXT,
        issuer TEXT,
        version INTEGER,
        serialNumber TEXT,
        notBefore TEXT,
        notAfter TEXT,
        subjectAltName TEXT,
        OCSP TEXT,
        caIssuers TEXT,
        crlDistributionPoints TEXT,
        expiring_soon BOOLEAN,
        expired BOOLEAN,
        error TEXT,
        PRIMARY KEY (host, port)
    );
    """
    with conn.cursor() as cursor:
        cursor.execute(create_table_sql)
        conn.commit()

def save_to_file(df, file_path, file_type):
    """
    Save the DataFrame to a file.

    Args:
        df (pandas.DataFrame): The DataFrame to save.
        file_path (str): The path to save the file.
        file_type (str): The type of file to save ('csv' or 'xls').

    Raises:
        ValueError: If the file type is not supported.
    """
    if file_type == 'csv':
        df.to_csv(file_path, index=False)
    elif file_type == 'xls':
        df.to_excel(file_path, index=False)
    else:
        raise ValueError("Unsupported file type. Use 'csv' or 'xls'.")

def filter_dataframe(df, expiring_soon=None, expired=None, valid=None):
    """
    Filter the DataFrame based on the certificate status.

    Args:
        df (pandas.DataFrame): The DataFrame to filter.
        expiring_soon (bool): If True, filter to show only certificates that are expiring soon.
        expired (bool): If True, filter to show only certificates that have expired.
        valid (bool): If True, filter to show only certificates that are neither expiring soon nor expired.

    Returns:
        pandas.DataFrame: The filtered DataFrame.
    """
    df['expiring_soon'] = df['expiring_soon'].infer_objects()
    df['expired'] = df['expired'].infer_objects()
    
    # Convert to boolean after ensuring types
    df['expiring_soon'] = df['expiring_soon'].astype(bool, copy=False)
    df['expired'] = df['expired'].astype(bool, copy=False)
    
    
    if expiring_soon:
        df = df[df['expiring_soon']]
    if expired:
        df = df[df['expired']]
    if valid:
        df = df[~df['expiring_soon'] & ~df['expired']]
    return df

def main():
    """
    Main function to parse arguments and run the TLS certificate auditor.
    """
    parser = argparse.ArgumentParser(description='TLS Certificate Auditor')
    parser.add_argument('--file', required=True, help='File containing IP addresses and ports')
    parser.add_argument('--table', required=True, help='Table name to save data')
    parser.add_argument('--postgres', action='store_true', help='Save data to PostgreSQL database')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--type', choices=['csv', 'xls'], help='Output file type')
    parser.add_argument('--stdout', action='store_true', help='Print data to stdout')
    parser.add_argument('--days', type=int, default=30, help='Number of days to flag certificates nearing expiration')
    parser.add_argument('--expiring_soon', action='store_true', help='Filter to show only expiring soon certificates')
    parser.add_argument('--expired', action='store_true', help='Filter to show only expired certificates')
    parser.add_argument('--valid', action='store_true', help='Filter to show only valid certificates')
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
        print('Either --postgres, --output and --type, or --stdout must be specified')

if __name__ == '__main__':
    main()

