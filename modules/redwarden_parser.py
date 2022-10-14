#!/usr/bin/python3
#
# This script acts as a HTTP/HTTPS reverse-proxy with several restrictions imposed upon which
# requests and from whom it should process, similarly to the .htaccess file in Apache2's mod_rewrite.
#
# malleable_redirector was created to resolve the problem of effective IR/AV/EDRs/Sandboxes evasion on the
# C2 redirector's backyard. 
#
# The proxy along with this plugin can both act as a CobaltStrike Teamserver C2 redirector, given Malleable C2
# profile used during the campaign and teamserver's hostname:port. The plugin will parse supplied malleable profile
# in order to understand which inbound requests may possibly come from the compatible Beacon or are not compliant with
# the profile and therefore should be misdirected. Sections such as http-stager, http-get, http-post and their corresponding 
# uris, headers, prepend/append patterns, User-Agent are all used to distinguish between legitimate beacon's request
# and some Internet noise or IR/AV/EDRs out of bound inquiries. 
#
# The plugin was also equipped with marvelous known bad IP ranges coming from:
#   curi0usJack and the others:
#   https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
#
# Using a IP addresses blacklist along with known to be bad keywords lookup on Reverse-IP DNS queries and HTTP headers,
# is considerably increasing plugin's resiliency to the unauthorized peers wanting to examine protected infrastructure.
#
# Use wisely, stay safe.
#
# Requirements:
#   - brotli
#   - yaml
#
# Author:
#   Mariusz Banach / mgeeky, '19-'20
#   <mb@binary-offensive.com>
#
#
# Sources: https://github.com/mgeeky/RedWarden/blob/master/plugins/malleable_redirector.py

import re

class MalleableParser:
    ProtocolTransactions = ('http-stager', 'http-get', 'http-post')
    TransactionBlocks = ('metadata', 'id', 'output')
    UriParameters = ('uri', 'uri_x86', 'uri_x64')
    CommunicationParties = ('client', 'server')

    GlobalOptionsDefaults = {
        'data_jitter': "0",
        'dns_idle': "0.0.0.0",
        'dns_max_txt': "252",
        'dns_sleep': "0",
        'dns_stager_prepend': "",
        'dns_stager_subhost': ".stage.123456.",
        'dns_ttl': "1",
        'headers_remove': "",
        'host_stage': "true",
        'jitter': "0",
        'maxdns': "255",
        'pipename': "msagent_##",
        'pipename_stager': "status_##",
        'sample_name': "My Profile",
        'sleeptime': "60000",
        'smb_frame_header': "",
        'ssh_banner': "Cobalt Strike 4.2",
        'ssh_pipename': "postex_ssh_####",
        'tcp_frame_header': "",
        'tcp_port': "4444",
        'useragent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.158 Safari/537.36",
    }

    def __init__(self, logger):
        self.path = ''
        self.data = ''
        self.datalines = []
        self.logger = logger
        self.parsed = {}
        self.config = self.parsed
        self.variants = []

    def get_config(self):
        return self.config

    def parse(self, path):
        try:
            with open(path, 'r') as f:
                self.data = f.read().replace('\r\n', '\n')
                self.datalines = self.data.split('\n')
                self.datalines.append('\n')

        except FileNotFoundError as e:
            self.logger.fatal("Malleable profile specified in redirector's config file (profile) doesn't exist: ({})".format(path))

        pos = 0
        linenum = 0
        depth = 0
        dynkey = []
        parsed = self.parsed

        regexes = {
            # Finds: set name "value";
            'set-name-value' : r"\s*set\s+(\w+)\s+(?=(?:(?<!\w)'(\S.*?)'(?!\w)|\"(\S.*?)\"(?!\w))).*",
            
            # Finds: section { as well as variant-driven: section "variant" {
            'begin-section-and-variant' : r'^\s*([\w-]+)(\s+"[^"]+")?\s*\{\s*',

            # Finds: [set] parameter ["value", ...];
            'set-parameter-value' : r'(?:([\w-]+)\s+(?=")".*")|(?:([\w-]+)(?=;))',

            # Finds: prepend "something"; and append "something";
            'prepend-append-value' : r'\s*(prepend|append)\s*"([^"\\]*(?:\\.[^"\\]*)*)"',
            
            'parameter-value' : r"(?=(?:(?<!\w)'(\S.*?)'(?!\w)|\"(\S.*?)\"(?!\w)))",
        }

        compregexes = {}

        for k, v in regexes.items():
            compregexes[k] = re.compile(v, re.I)

        while linenum < len(self.datalines):
            line = self.datalines[linenum]

            assert len(dynkey) == depth, "Depth ({}) and dynkey differ ({})".format(depth, dynkey)

            if line.strip() == '': 
                pos += len(line)
                linenum += 1
                continue

            if line.lstrip().startswith('#'): 
                pos += len(line) + 1
                linenum += 1
                continue

            if len(line) > 100:
                self.logger.dbg('[key: {}, line: {}, pos: {}] {}...{}'.format(str(dynkey), linenum, pos, line[:50], line[-50:]))
            else:
                self.logger.dbg('[key: {}, line: {}, pos: {}] {}'.format(str(dynkey), linenum, pos, line[:100]))

            parsed = self.parsed
            for key in dynkey:
                sect, variant = key
                if len(variant) > 0:
                    parsed = parsed[sect][variant]
                else:
                    parsed = parsed[sect]

            matched = False

            m = compregexes['begin-section-and-variant'].match(line)
            twolines = self.datalines[linenum]

            if len(self.datalines) >= linenum+1:
                twolines += self.datalines[linenum+1]

            n = compregexes['begin-section-and-variant'].match(twolines)
            if m or n:
                if m == None and n != None: 
                    self.logger.dbg('Section opened in a new line: [{}] = ["{}"]'.format(
                        n.group(1), 
                        twolines.replace('\r', "\\r").replace('\n', "\\n")
                    ))
                    linenum += 1
                    pos += len(self.datalines[linenum])
                    m = n

                depth += 1
                section = m.group(1)
                variant = ''

                if section not in parsed.keys():
                    parsed[section] = {}

                if m.group(2) is not None:
                    variant = m.group(2).strip().replace('"', '')
                    parsed[section][variant] = {}
                    parsed[section]['variant'] = variant

                elif section in MalleableParser.ProtocolTransactions:
                    variant = 'default'
                    parsed[section][variant] = {}
                    parsed[section]['variant'] = variant

                else:
                    parsed[section] = {}

                if len(variant) > 0 and variant not in self.variants:
                    self.variants.append(variant)
                
                self.logger.dbg('Extracted section: [{}] (variant: {})'.format(section, variant))

                dynkey.append((section, variant))

                matched = 'section'
                pos += len(line)
                linenum += 1
                continue

            if line.strip() == '}':
                depth -= 1
                matched = 'endsection'
                sect, variant = dynkey.pop()
                variant = ''

                if sect in parsed.keys() and 'variant' in parsed[sect][variant].keys():
                    variant = '(variant: {})'.format(variant)

                self.logger.dbg('Reached end of section {}.{}'.format(sect, variant))
                pos += len(line)
                linenum += 1
                continue

            m = compregexes['set-name-value'].match(line)
            if m:
                n = list(filter(lambda x: x != None, m.groups()[2:]))[0]
                
                val = n.replace('\\\\', '\\')
                param = m.group(1)

                if param.lower() == 'uri' or param.lower() == 'uri_x86' or param.lower() == 'uri_x64':
                    parsed[param] = val.split(' ')
                    self.logger.dbg('Multiple URIs defined: [{}] = [{}]'.format(param, ', '.join(val.split(' '))))

                else:
                    parsed[param] = val
                    self.logger.dbg('Extracted variable: [{}] = [{}]'.format(param, val))

                matched = 'set'
                pos += len(line)
                linenum += 1
                continue

            # Finds: [set] parameter ["value", ...];
            m = compregexes['set-parameter-value'].search(line)
            if m:
                paramname = list(filter(lambda x: x != None, m.groups()))[0]
                restofline = line[line.find(paramname) + len(paramname):]
                values = []

                n = compregexes['prepend-append-value'].search(line)
                if n != None and len(n.groups()) > 1:
                    paramname = n.groups()[0]
                    paramval = n.groups()[1].replace('\\\\', '\\')
                    values.append(paramval)
                    self.logger.dbg('Extracted {} value: "{}..."'.format(paramname, paramval[:20]))

                else: 
                    for n in compregexes['parameter-value'].finditer(restofline):
                        try:
                            paramval = list(filter(lambda x: x != None, n.groups()[1:]))[0]
                            values.append(paramval.replace('\\\\', '\\'))
                        except Exception as e:
                            self.logger.fatal(f'Could not process line as ([set] parameter ["value", ...] :\n\n\t{line}\n\nMake sure your line doesnt include apostrophes, or other characters breaking compregexes["parameter-value"] regex.')


                if values == []:
                    values = ''
                elif len(values) == 1:
                    values = values[0]

                if paramname in parsed.keys():
                    if type(parsed[paramname]) == list:
                        parsed[paramname].append(values)
                    else:
                        parsed[paramname] = [parsed[paramname], values]
                else:
                    if type(values) == list:
                        parsed[paramname] = [values, ]
                    else:
                        parsed[paramname] = values

                self.logger.dbg('Extracted complex variable: [{}] = [{}]'.format(paramname, str(values)[:100]))

                matched = 'complexset'
                pos += len(line)
                linenum += 1
                continue

            # Finds: prepend "value" / append "value"
            if re.match(r'^\s*(?:append|prepend)\s+"', line, re.I):
                self.logger.dbg(f'Found beginning of prepend/append instruction (line: {linenum}): ' + line[:30])

                lineidx = 0
                cancont = False
                values = []
                
                while lineidx < 100 and lineidx + linenum < len(self.datalines):
                    if re.match('.*";\s*$', self.datalines[lineidx + linenum]):
                        self.logger.dbg(f'Found end of prepend/append instruction at line: {linenum+lineidx}')

                        longline = ''.join(self.datalines[linenum : linenum + lineidx + 1])

                        m = compregexes['prepend-append-value'].match(longline, re.I|re.M)
                        if m:
                            self.logger.dbg(f'Extracted multi-line prepend/append instruction.')

                            paramname = m.groups()[0]
                            paramval = m.groups()[1].replace('\\\\', '\\')
                            values.append(paramval)

                            if values == []:
                                values = ''
                            elif len(values) == 1:
                                values = values[0]

                            if paramname in parsed.keys():
                                if type(parsed[paramname]) == list:
                                    parsed[paramname].append(values)
                                else:
                                    parsed[paramname] = [parsed[paramname], values]
                            else:
                                if type(values) == list:
                                    parsed[paramname] = [values, ]
                                else:
                                    parsed[paramname] = values

                            linenum += lineidx + 1
                            pos += len(longline)
                            matched = 'prepend-append'
                            cancont = True

                        else:
                            self.logger.dbg(f'Extracted prepend/append instruction IS NOT valid!')
                            self.logger.dbg(f'\n---------------------\n{longline}\n---------------------')

                        break

                    lineidx += 1

                if cancont:
                    continue

            a = linenum
            b = linenum+1

            if a > 5: a -= 5

            if b > len(self.datalines): b = len(self.datalines)
            elif b < len(self.datalines) + 5: b += 5

            self.logger.err("Unexpected statement:\n\t{}\n\n----- Context -----\n\n{}\n".format(
                line,
                '\n'.join(self.datalines[a:b])
                ))

            self.logger.err("\nParsing failed.")
            return False

        self.normalize()
        return True

    def normalize(self):
        for k, v in self.config.items():
            if k in MalleableParser.ProtocolTransactions:
                if k == 'http-get' and 'verb' not in self.config[k].keys():
                    self.config[k]['verb'] = 'GET'
                elif k == 'http-post' and 'verb' not in self.config[k].keys():
                    self.config[k]['verb'] = 'POST'

                for a in MalleableParser.CommunicationParties:
                    if a not in self.config[k]:
                        self.config[k][a] = {
                            'header' : [],
                            'parameter' : [],
                            'variant' : 'default',
                        }
                    else:
                        if 'header' not in self.config[k][a].keys(): self.config[k][a]['header'] = []
                        if 'parameter' not in self.config[k][a].keys(): self.config[k][a]['parameter'] = []
                        if 'variant' not in self.config[k][a].keys(): self.config[k][a]['variant'] = 'default'

        for k, v in MalleableParser.GlobalOptionsDefaults.items():
            if k.lower() not in self.config.keys():
                self.config[k] = v
                self.logger.dbg('MalleableParser: Global variable ({}) not defined. Setting default value of: "{}"'.format(k, v))
