from datetime import datetime
from pprintjson import pprintjson as ppjson


def before_scenario(context, scenario):
    context.scenario_name = scenario.name


def after_tag(context, tag):
    if not (request_str := getattr(context, 'request_str', None)):
        # failure at 'given' stage
        return

    if tag == 'report':
        report_header = [
            '='*50,
            context.scenario_name,
            '='*50,
            '',
            f"Timestamp:  {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')}",
            f"Request:    {request_str}",
            '',
            'Response:',
        ]
        with open('logs/crypto_test_report.txt', 'a') as f:
            f.writelines([line + '\n' for line in report_header])
            ppjson(context.response, file=f)
            f.write('\n\n')
