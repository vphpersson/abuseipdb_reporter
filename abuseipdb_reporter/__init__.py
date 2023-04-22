from logging import getLogger, Logger
from typing import Final
from datetime import datetime
from time import mktime
from collections import defaultdict
from csv import DictWriter
from io import StringIO

from httpx import AsyncClient

LOG: Final[Logger] = getLogger(__name__)

ABUSEIPDB_BASE_URL: Final[str] = 'https://api.abuseipdb.com'

_NUM_MAX_CSV_LINES: Final[int] = 10_000
_MAX_CSV_DATA_BYTE_SIZE: Final[int] = 2_000_000

_PORT_SCAN_CATEGORY_ID: Final[str] = '14'

_MAX_BUCKETS: Final[int] = 65_536
_COMMENT_SIZE_LIMIT: Final[int] = 1024


async def bulk_report_csv(csv_data_list: list[bytes], http_client: AsyncClient) -> list[dict]:
    """
    Bulk upload AbuseIPDB CSV data blobs.
    :param csv_data_list: A list of CSV data blobs to be uploaded.
    :param http_client: An HTTP client with which to perform the uploading.
    :return: A list of returns data per uploaded CSV data blob.
    """

    response_list: list[dict] = []

    for csv_data in csv_data_list:
        response = await http_client.post(
            url='/api/v2/bulk-report',
            headers={'Accept': 'application/json'},
            files={'csv': ('report.csv', csv_data)},
        )
        response.raise_for_status()

        response_list.append(response.json())

    return response_list


def _make_comment(
    network_transport_to_port_ranges: dict[str, list[str]],
    network_transport_to_count: dict[str, int],
    num_blocks: int
) -> str:
    """
    Create a comment about an IP address based on network transport, port range, and occurrence information.

    :param network_transport_to_port_ranges: A mapping between the network transport and the port ranges.
    :param network_transport_to_count: A mapping between the network transport and the associated number of blocks.
    :param num_blocks: The total number of blocks observed from the IP address.
    :return: A comment based on the provided information.
    """

    comment_header = (
            'Unsolicited network traffic.\n'
            + f'{num_blocks} ' + ('blocks' if num_blocks > 1 else 'block') + ' in the last 24 hours.\n\n'
    )

    if len(comment_header) > _COMMENT_SIZE_LIMIT:
        return 'Unsolicited network traffic.'

    comment_body = '\n\n'.join(
        f'{network_transport} ({network_transport_to_count[network_transport]})\n{",".join(port_ranges)}'
        for network_transport, port_ranges in network_transport_to_port_ranges.items()
    )

    if len(comment := (comment_header + comment_body)) > _COMMENT_SIZE_LIMIT:
        comment_body = '\n'.join(
            f'{network_transport} ({network_transport_to_count[network_transport]})'
            for network_transport, port_ranges in network_transport_to_port_ranges.items()
        )
    else:
        return comment

    if len(comment := (comment_header + comment_body)) > _COMMENT_SIZE_LIMIT:
        return comment_header
    else:
        return comment


def _datetime_to_epoch(d: datetime) -> int:
    return int(mktime(d.timetuple()))


def collect_port_scan_data(
    query: str,
    index: str,
    datetime_from: datetime,
    datetime_to: datetime,
    elasticsearch_client
) -> dict[str, str]:
    """

    :param query: The query to be made to Elasticsearch.
    :param index: The index in which the query should be performed.
    :param datetime_from:
    :param datetime_to:
    :param elasticsearch_client: An Elasticsearch client with which to make the query.
    :return:
    """

    data_response = elasticsearch_client.search(
        index=index,
        size=0,
        aggs={
            'source_ip_aggs': {
                'terms': {
                    'field': 'source.ip',
                    'size': _MAX_BUCKETS
                },
                'aggs': {
                    'network_transport_aggs': {
                        'terms': {
                            'field': 'network.transport',
                            'size': _MAX_BUCKETS
                        },
                        'aggs': {
                            'destination_port_aggs': {
                                'terms': {
                                    'field': 'destination.port',
                                    'size': _MAX_BUCKETS
                                }
                            }
                        }
                    }
                }
            }
        },
        query={
            'bool': {
                'filter': [{
                    'range': {
                        '@timestamp': {
                            'format': 'epoch_second',
                            'gte': _datetime_to_epoch(d=datetime_from),
                            'lte': _datetime_to_epoch(d=datetime_to)
                        }
                    }
                }],
                'must': [{
                    'query_string': {'query': query}
                }]
            }
        }
    )

    source_ip_to_comment: dict[str, str] = {}

    source_ip_buckets = data_response['aggregations']['source_ip_aggs']['buckets']
    for source_ip_bucket in source_ip_buckets:
        network_transport_to_port_ranges: defaultdict[str, list[str]] = defaultdict(list)
        network_transport_to_count: dict[str, int] = {}
        num_blocks: int = source_ip_bucket['doc_count']

        network_transport_buckets = source_ip_bucket['network_transport_aggs']['buckets']
        for network_transport_bucket in network_transport_buckets:
            network_transport: str = network_transport_bucket['key']
            network_transport_to_count[network_transport] = network_transport_bucket['doc_count']

            destination_ports: list[int] = sorted(
                destination_port_bucket['key']
                for destination_port_bucket in network_transport_bucket['destination_port_aggs']['buckets']
            )

            start_port: int = destination_ports[0]
            previous_port: int = start_port

            for port in destination_ports[1:]:
                if port != (previous_port + 1):
                    network_transport_to_port_ranges[network_transport].append(
                        f'{start_port}-{previous_port}'
                        if start_port != previous_port
                        else str(start_port)
                    )
                    start_port = port
                previous_port = port

            network_transport_to_port_ranges[network_transport].append(
                f'{start_port}-{previous_port}'
                if start_port != previous_port
                else str(start_port)
            )

        source_ip_to_comment[source_ip_bucket['key']] = _make_comment(
            network_transport_to_port_ranges=network_transport_to_port_ranges,
            network_transport_to_count=network_transport_to_count,
            num_blocks=num_blocks
        )

    return source_ip_to_comment


class _IODictWriter(DictWriter):
    def __init__(self, *args, io: StringIO, **kwargs):
        super().__init__(*args, **kwargs)
        self.io = io


def _make_dict_writer() -> _IODictWriter:
    csv_io = StringIO(newline='')

    dict_writer = _IODictWriter(
        f=csv_io,
        fieldnames=['IP', 'Categories', 'ReportDate', 'Comment'],
        dialect='unix',
        io=csv_io
    )
    dict_writer.io = csv_io

    return dict_writer


def make_bulk_report_csv_blobs(source_ip_to_comment: dict[str, str], datetime_now: datetime) -> list[bytes]:
    """
    Create CSV-formatted, AbuseIPDB-compatible data from aggregated source IP address and comment data.

    :param source_ip_to_comment: A mapping of the source IP addresses and their associated comment.
    :param datetime_now: The timestamp, as a datetime, to use in the report.
    :return: A list of CSV blobs in a format accepted by AbuseIPDB.
    """

    timestamp: str = datetime_now.astimezone().isoformat()

    dict_writer: _IODictWriter = _make_dict_writer()
    n: int = dict_writer.writeheader()
    num_bytes_written: int = n
    num_lines = 1

    csv_data_list: list[bytes] = []

    for source_ip, comment in source_ip_to_comment.items():
        n = dict_writer.writerow({
            'IP': source_ip,
            'Categories': _PORT_SCAN_CATEGORY_ID,
            'ReportDate': timestamp,
            'Comment': comment
        })
        num_lines += (comment.count('\n') + 1)
        num_bytes_written += n

        # If the entry written exceeds one of the limits, remove its raw byte data from the and store the resulting
        # blob in the list to be returned. Then rewrite the entry in a new CSV blob.
        if num_lines > _NUM_MAX_CSV_LINES or num_bytes_written > _MAX_CSV_DATA_BYTE_SIZE:
            csv_data_list.append(dict_writer.io.getvalue().encode()[:-n])

            dict_writer = _make_dict_writer()
            n = dict_writer.writeheader()
            num_bytes_written = n
            num_lines = 1

            n = dict_writer.writerow({
                'IP': source_ip,
                'Categories': _PORT_SCAN_CATEGORY_ID,
                'ReportDate': timestamp,
                'Comment': comment
            })
            num_lines += (comment.count('\n') + 1)
            num_bytes_written += n

    csv_data_list.append(dict_writer.io.getvalue().encode())

    return csv_data_list

