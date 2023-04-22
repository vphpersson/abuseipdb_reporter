#!/usr/bin/env python

from logging import INFO
from logging.handlers import TimedRotatingFileHandler
from asyncio import run as asyncio_run
from dataclasses import dataclass
from argparse import ArgumentParser, FileType
from datetime import datetime, timedelta

from ecs_tools_py import make_log_handler
from elasticsearch import Elasticsearch
from httpx import AsyncClient
from toml import load as toml_load

from abuseipdb_reporter import LOG, ABUSEIPDB_BASE_URL, bulk_report_csv, collect_port_scan_data,\
    make_bulk_report_csv_blobs

log_handler = make_log_handler(
    base_class=TimedRotatingFileHandler,
    provider_name='abuseipdb_reporter',
    generate_field_names=('event.timezone', 'host.name', 'host.hostname')
)(filename='abuseipdb_reporter.log', when='W0')

LOG.addHandler(hdlr=log_handler)
LOG.setLevel(level=INFO)


@dataclass
class Config:
    abuseipdb_api_key: str
    elasticsearch_host: str
    elasticsearch_index: str
    elasticsearch_api_key: str
    query: str
    timeout: float = 90.0


class AbuseIPDBReporterArgumentParser(ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **(
                dict(
                    description='Report IP addresses to AbuseIPDB.'
                ) | kwargs
            )
        )

        self.add_argument(
            '-c', '--config',
            required=True,
            help='The path of a configuration file.',
            type=FileType(mode='r')
        )


async def main():
    try:
        config = Config(**toml_load(AbuseIPDBReporterArgumentParser().parse_args().config))
        datetime_now = datetime.now()

        source_ip_to_comment: dict[str, str] = collect_port_scan_data(
            query=config.query,
            index=config.elasticsearch_index,
            datetime_from=datetime_now - timedelta(hours=24),
            datetime_to=datetime_now,
            elasticsearch_client=Elasticsearch(
                hosts=[config.elasticsearch_host],
                api_key=config.elasticsearch_api_key,
                verify_certs=False
            )
        )

        http_client_options = dict(
            base_url=ABUSEIPDB_BASE_URL,
            timeout=config.timeout,
            headers={
                'Key': config.abuseipdb_api_key
            }
        )
        async with AsyncClient(**http_client_options) as http_client:
            await bulk_report_csv(
                csv_data_list=make_bulk_report_csv_blobs(
                    source_ip_to_comment=source_ip_to_comment,
                    datetime_now=datetime_now
                ),
                http_client=http_client
            )

        LOG.info(
            msg=f'Successfully reported IP addresses to AbuseIPDB.',
            extra=dict(
                num_ip_addresses=len(source_ip_to_comment)
            )
        )
    except KeyboardInterrupt:
        pass
    except Exception:
        LOG.exception(msg='An unexpected error occurred.')

if __name__ == '__main__':
    asyncio_run(main())
