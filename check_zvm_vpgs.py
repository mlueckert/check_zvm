#!/usr/bin/env python3
"""Plugin to check Zerto Alerts and VPGs"""

from sys import exit
import logging
import requests
from enum import IntEnum
import argparse


class service_states(IntEnum):
    ok = 0
    warning = 1
    critical = 2
    unknown = 3


class vpg_statuses(IntEnum):
    initializing = 0
    meeting_sla = 1
    not_meeting_sla = 2
    history_not_meeting_sla = 3
    rpm_not_meeting_sla = 4
    failing_over = 5
    moving = 6
    deleting = 7
    recovered = 8


def login(url, auth, **kwargs):
    """
    Requires a url and (username, password) tuple, and returns a session token
    to be passed with future requests.
    """

    url = '{0}/v1/session/add'.format(url)

    response = requests.post(url, auth=auth, verify=kwargs.get('verify', True))
    response.raise_for_status()

    return response.headers.get('X-Zerto-Session')

def get_api(url, session, api_endpoint, verify):
    """
    Requires a url and session token, and returns a list of VPGs
    """
    url = '{0}/v1/{1}'.format(url, api_endpoint)
    headers = {'X-Zerto-Session': session}

    response = requests.get(url, headers=headers, verify=verify)
    return response.json()

def check_vpg_statuses(url, session, verify):
    """
    Return a list of VPGs which meet the SLA and a list of those which don't
    """

    good, bad = [], []

    for vpg in get_api(url, session, "vpgs", verify):
        name = vpg['VpgName']
        status = vpg_statuses(vpg['Status'])

        if status == vpg_statuses.meeting_sla:
            good.append(name)
        else:
            bad.append(name)

    return good, bad

def check_alerts(url, session, verify, exclude):
    """
    Return a list of all active critical and warning alerts
    """
    warning, critical = [], []

    for alert in get_api(url, session, "alerts", verify):
        if alert['IsDismissed'] == False and alert['HelpIdentifier'] not in exclude:
            id = alert['HelpIdentifier']
            description = alert['Description']
            status = alert['Level']
            if status == 'Warning':
                warning.append("{0} - {1}".format(id, description))
            else:
                critical.append("{0} - {1}".format(id, description))
    return warning, critical

def main():
    try:
        logging.captureWarnings(True)
    except AttributeError:
        pass

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-u', '--url', type=str, required=True,
                        help='The URL of the ZVM')
    parser.add_argument('-n', '--username', type=str, required=True,
                        help='The Windows username used to authenticate')
    parser.add_argument('-p', '--password', type=str, required=True,
                        help='The password for the specified username')
    parser.add_argument('-m', '--mode', type=str, required=True,
                        help='Valid modes are vpgs, alerts')
    parser.add_argument('--no-verify', action='store_false', dest='verify', help='Disables certificate verification')
    parser.add_argument('-e', '--exclude', default=['VRA0056','DRV0001','ZVM0011','VRA0059'], nargs = '*', type=str,
                        help='Alerts to exclude. Use the HelpIdentifier e.g. VRA0056')

    args = parser.parse_args()

    try:
        auth = (args.username, args.password)
        session = login(args.url, auth, verify=args.verify)
        if args.mode == 'vpgs':
            result = check_vpg_statuses(args.url, session=session, verify=args.verify)
            good, bad = result
            if len(bad) == 0:
                print("OK: All {0} VPGs meet their SLAs"
                    .format(len(good)))
                exit(service_states.ok)
            else:
                print("CRITICAL: {0} of {1} VPGs are not meeting SLAs: {2}"
                    .format(len(bad), len(bad)+len(good),', '.join(bad)))
                exit(service_states.critical)
        elif args.mode == 'alerts':
            result = check_alerts(args.url, session=session, verify=args.verify, exclude=args.exclude)
            warning, critical = result
            output = ""
            exitcode = service_states.unknown
            if len(critical) == 0 and len(warning) == 0:
                output = "No alerts reported.</br>"
                exitcode = service_states.ok
            elif len(warning) != 0:
                output = "{0} warning alerts: </br>{1}</br>".format(len(warning), '</br>'.join(warning))
                exitcode = service_states.warning
            if len(critical) != 0:
                output = output + "{0} critical alerts:</br>{1}</br>".format(len(critical), '</br>'.join(critical))
                exitcode = service_states.critical
            if args.exclude:
                output = output + "Alert IDs {0} and acknowledged alerts are excluded.</br>".format(' '.join(args.exclude))
            print("{0}: {1}".format(service_states(exitcode).name.upper(), output))
            exit(exitcode)

    except Exception as e:
        exitcode = service_states.critical
        print("{0}: {1}".format(service_states(exitcode).name.upper(), repr(e)))
        exit(exitcode)

if __name__ == '__main__':
    main()
