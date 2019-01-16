#!/usr/bin/env python3

import csv
import datetime
import os

class ReportBuilder:

    def __init__(self):
        self.numberofdayspast = 15

        self.days_old = [30, 60, 90]

        self.outputdirectory = 'results'
        if not os.path.exists(self.outputdirectory):
            os.makedirs(self.outputdirectory)

        self.chart = {
            'External': {
                'Low': 60,
                'Medium': 30,
                'High': 7,
                'Critical': 2
            },
            'Internal': {
                'Low': 90,
                'Medium': 60,
                'High': 30,
                'Critical': 7
            }
        }

        self.sev_to_level = {
            '1': 'Low',
            '2': 'Medium',
            '3': 'High',
            '4': 'High',
            '5': 'Critical'
        }

        self.strtodate = '%m/%d/%Y'

        self.reportlist = [
            'inputs/Output-20181022-body-added.csv',
            None,
            None,
            'inputs/Output-20181114-body-added.csv',
            'inputs/Output-20181120-body-added.csv',
            'inputs/Output-20181127-body-added.csv',
            'inputs/Output-20181205-body-added.csv',
            'inputs/Output-20181214-body-added.csv',
            'inputs/Output-20181221-body-added.csv',
            None,
            'inputs/Output-20190102-body-added.csv',
            'inputs/Output-20190110-body-added.csv'
        ]

        self.internal_ips = [
            '192.168.',
            '10.',
            '127.',
            '172.16'
        ]

        self.processweeks()

    def is_recent(self, reportName, lastSeenDate):
        pass

    def is_compliant(self, ternal, severity, diff):
        max = self.chart['Internal' if ternal else 'External'][self.sev_to_level[severity]]
        # print(diff, max, diff < max)
        return diff < max

    def get_ternal(self, ip):
        return any(ip.startswith(s) for s in self.internal_ips)

    def processweeks(self):
        for weeknum, rep in enumerate(self.reportlist):
            if rep:
                # try:
                print(f'Processing week-{weeknum:02}')
                res = self.loadcsv(rep)
                # print(res)
                self.writeweek(weeknum, res)
                # except Exception as ex:
                #     print(f'Unable to process week-{weeknum:02}')
                #     print(ex)
            else:
                print(f'No report available for week-{weeknum:02}')

    def writeweek(self, weeknum, results):
        for bum in results:
            # complianceweek = f'results/{bum}_week-{weeknum:02}_Compliance.csv'
            # print(f'Writing {complianceweek}')
            # with open(complianceweek, 'wt', newline='\n') as csvfile:
            #     cw = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            #     cw.writerow(['Level', 'Compliant', 'Not Compliant'])
            #     for level in ['Low', 'Medium', 'High', 'Critical']:
            #         cw.writerow([level, results[bum][level]['Compliant'], results[bum][level]['Not Compliant']])
            # for ternal in ['Internal', 'External']:
            #     complianceweek = f'results/{bum}_week-{weeknum:02}_Compliance_{ternal}.csv'
            #     print(f'Writing {complianceweek}')
            #     with open(complianceweek, 'wt', newline='\n') as csvfile:
            #         cw = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            #         cw.writerow(['Level', 'Compliant', 'Not Compliant'])
            #         for level in ['Low', 'Medium', 'High', 'Critical']:
            #             cw.writerow([level, results[bum][ternal][level]['Compliant'], results[bum][ternal][level]['Not Compliant']])

            ipsallweek = f'{self.outputdirectory}/{bum}_week-{weeknum:02}_IPs_All.csv'
            print(f'Writing {ipsallweek}')
            with open(ipsallweek, 'wt', newline='\n') as csvfile:
                cw = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                cw.writerow(['IP', 'Vulnerabilities'])
                for ip in results[bum]['IPs']:
                    cw.writerow([ip, results[bum]['IPs'][ip]])

            ips50week = f'results/{bum}_week-{weeknum:02}_IPs_50-or-more.csv'
            print(f'Writing {ips50week}')
            with open(ips50week, 'wt', newline='\n') as csvfile:
                cw = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                cw.writerow(['IP', 'Vulnerabilities'])
                for ip in results[bum]['IPs']:
                    if results[bum]['IPs'][ip] >= 50:
                        cw.writerow([ip, results[bum]['IPs'][ip]])

        bu_facing_vulncount = f'results/MASTER_week-{weeknum:02}_BU-Facing-Vulns.csv'
        print(f'Writing {bu_facing_vulncount}')
        with open(bu_facing_vulncount, 'wt', newline='\n') as csvfile:
            cw = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            cw.writerow(['Business Unit', 'Facing', 'Compliance', 'Low', 'Medium', 'High', 'Critical'])
            for bum in results:
                for facing in ['Internal', 'External']:
                    for compliance in ['Compliant', 'Not Compliant']:
                        cw.writerow([
                            bum,
                            facing,
                            compliance,
                            results[bum][facing]['Low'][compliance],
                            results[bum][facing]['Medium'][compliance],
                            results[bum][facing]['High'][compliance],
                            results[bum][facing]['Critical'][compliance]
                        ])

        bu_days_old = f'results/MASTER_week-{weeknum:02}_BU-Days_Old.csv'
        print(f'Writing {bu_days_old}')
        with open(bu_days_old, 'wt', newline='\n') as csvfile:
            cw = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            cw.writerow(['Business Unit', '>=Days Old', 'Low', 'Medium', 'High', 'Critical'])
            for bum in results:
                for dold in self.days_old:
                    cw.writerow([
                        bum,
                        dold,
                        results[bum][f'>{dold}']['Low'],
                        results[bum][f'>{dold}']['Medium'],
                        results[bum][f'>{dold}']['High'],
                        results[bum][f'>{dold}']['Critical']
                    ])

    def loadcsv(self, filename):
        repdate = datetime.datetime.strptime(filename[-23:-15], '%Y%m%d').date()
        result = {}
        with open(filename, 'rt', newline='\n') as csvfile:
            cr = csv.reader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            head = next(cr)
            headers = dict(zip(head, range(0, len(head))))
            # print(f'\tHeaders: {headers}')
            # Headers: {'IP': 0, 'Network': 1, 'DNS': 2, 'NetBIOS': 3, 'Tracking Method': 4, 'OS': 5, 'IP Status': 6, 'QID': 7, 'Title': 8, 'Vuln Status': 9, 'Type': 10, 'Severity': 11, 'Port': 12, 'Protocol': 13, 'FQDN': 14, 'SSL': 15, 'First Detected': 16, 'Last Detected': 17, 'Times Detected': 18, 'Date Last Fixed': 19, 'CVE ID': 20, 'Vendor Reference': 21, 'Bugtraq ID': 22, 'CVSS': 23, 'CVSS Base': 24, 'CVSS Temporal': 25, 'CVSS Environment': 26, 'CVSS3': 27, 'CVSS3 Base': 28, 'CVSS3 Temporal': 29, 'Results': 30, 'PCI Vuln': 31, 'Ticket State': 32, 'Instance': 33, 'OS CPE': 34, 'Category': 35, 'Business Unit': 36, 'Business Unit Master': 37, 'PCI': 38, 'SOX': 39, 'Tier0': 40}
            for row in cr:
                ip = row[headers['IP']]
                qid = row[headers['QID']]
                severity = row[headers['Severity']]
                bum = row[headers['Business Unit Master']]
                if bum == '':
                    bum = 'Unknown'
                fd = row[headers['First Detected']]
                fdd = datetime.datetime.strptime(fd[:10], self.strtodate).date()
                ld = row[headers['Last Detected']]
                ldd = datetime.datetime.strptime(ld[:10], self.strtodate).date()
                if abs((ldd-repdate).days) > self.numberofdayspast:
                    continue
                fldiff = abs((ldd - fdd).days)
                # print(ld, fd)
                # print(ldd, fdd, fldiff)
                ternal = self.get_ternal(ip)
                ternalstr = 'Internal' if ternal else 'External'
                level = self.sev_to_level[severity]
                compliant = self.is_compliant(ternal, severity, fldiff)
                compliantstr = 'Compliant' if compliant else 'Not Compliant'
                # print(', '.join([row[headers['IP']], row[headers['Network']], row[headers['Business Unit Master']], ]))

                if bum not in result:
                    result[bum] = self.get_struct()

                result[bum][level][compliantstr] += 1

                result[bum][ternalstr][level][compliantstr] += 1

                if ip not in result[bum]['IPs']:
                    result[bum]['IPs'][ip] = 0

                result[bum]['IPs'][ip] += 1

                for dold in reversed(self.days_old):
                    if fldiff >= dold:
                        result[bum][f'>{dold}'][level] += 1
                        break

        return result

    def get_basic(self):
        return {
            'Low': {
                'Compliant': 0,
                'Not Compliant': 0
            },
            'Medium': {
                'Compliant': 0,
                'Not Compliant': 0
            },
            'High': {
                'Compliant': 0,
                'Not Compliant': 0
            },
            'Critical': {
                'Compliant': 0,
                'Not Compliant': 0
            }
        }

    def get_basic2(self):
        return {
            'Low': 0,
            'Medium': 0,
            'High': 0,
            'Critical': 0
        }

    def get_struct(self):
        res = self.get_basic()
        res['External'] = self.get_basic()
        res['Internal'] = self.get_basic()
        res['IPs'] = {}
        for dold in self.days_old:
            res[f'>{dold}'] = self.get_basic2()
        return res

if __name__ == '__main__':
    rb = ReportBuilder()
