#!/bin/python
"""
Author: Haridas N <haridas.nss@gmai.com>
Date: 10/Nov/2012

This is the main file for this project.

Copyright (C) 2012,  Haridas N <haridas.nss@gmail.com>

IPmonitoring is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

"""
import os
import subprocess
import urllib

TMP_DIR = './'


class ARecord(object):
    """
        Generate the A record for standard DNS zone file.
    """
    def __init__(self):
        pass


class SPFRecord(object):
    """
        Generate the SPF record for standard DNS zone file.
    """
    def __init__(self):
        pass


class DomainKey(object):
    """
    Manages all operations related to Domain Key generation.
    """
    def __init__(self):
        pass


class DKIM(object):
    """
    Manages all operations related to the DKIM operation.


    DKIM/DomainKey are both are simiar one. But DomainKey was the
    implementation of Yahoo and it is pattented, but the DKIM is developed by
    open standard commity, but due it resembles with DomainKye, it was sued
    by Yahoo, and it still uncertain that some portions of DKIM still comes
    under Yahoo patent specification.

    """
    def __init__(self, domain, selector="mailserver", key=None, key_pub=None,
                 policy_strict=False,
                ):

        # Option for getting the pub and private key from outside.
        self._dkim_key_pub = key or ""
        self._dkim_key = key_pub or ""

        self._domain = domain
        self._selector = selector

        # Recoards required for the DNS server. This is enough for both
        # Domainkey and DKIM.
        self._policy_record = ""
        self._text_recoard = ""

        # Generate the Policy Records.
        if policy_strict:
            self._dkim_policy = "t=y;o=-;"
        else:
            self._dkim_policy = "t=y;o=~;"

    @property
    def dkim_pub_key(self):
        """
        Return DKIM Public Key.
        """
        if self._dkim_key_pub:
            return self._dkim_key_pub
        else:
            self._generate_key()
            return self._dkim_key_pub

    @property
    def dkim_key(self):
        """
        Return DKIM Public Key.
        """
        if self._dkim_key:
            return self._dkim_key
        else:
            self._generate_key()
            return self._dkim_key

    def _generate_key(self):
        """
        Generate the public and private key

        It uses commandline openssl tool to generate the private and
        public key.
        """

        # Command to generate private key.
        self._dkim_key = self._run_command(['openssl', 'genrsa', '1024'])

        key_file_name = os.path.join(TMP_DIR, '_key')

        with open(key_file_name, 'w') as kf:
            kf.write(self._dkim_key)

        key_file_pub_name = os.path.join(TMP_DIR, '_key.pub')

        # Command for generate public key from private key.
        self._run_command(['openssl', 'rsa', '-in',
                                                key_file_name, '-out',
                                                key_file_pub_name,
                                                '-pubout', '-outform',
                                                'PEM'
                                               ])

        # Read the generated public key from the file.
        with open(key_file_pub_name, 'r') as pub_key_file:
            self._dkim_key_pub = pub_key_file.read()

    def _run_command(self, args):
        """
        Run Shell command and return its output.
        """

        assert isinstance(args, list), "The commands should be in list format"

        try:

            process = subprocess.Popen(args,
                                       shell=False,
                                       stdout=subprocess.PIPE)

            result = process.communicate()[0]

            return result
        except:
            return None


class DNSRecord(object):
    """
    All types of dns records are being generated from here.
    """
    def __init__(self, domains, host_name=None, record_type=None,
                 mx_pref="10", email_type=None, ttl=1800):
        """
        @parm domains: Comma separated main domains.
        @parm host_name: subdomain/hostname to create the record for.
        @parm record_type: Type of the record (TXT, A, MX, ..)
        @parm mx_pref: MX record preference, when we use MX record_type.
        @parm email_type: Type email settings, MX, MXE, FWD, OX.

        eg;

        >>> record = DNSRecord('haridas.in')
        >>> .generate_text_record("pass other args")

        """

        assert domains, "Pass Valid Main Domain Name."

        self.domains = domains.split(",")[0]
        self.host_name = host_name
        self.record_type = record_type
        self.mx_pref = mx_pref
        self.email_type = email_type
        self.ttl = ttl

        # To keep the generated dkim and spf to use after api request.
        self.dkim = None
        self.spf = None

        # Top level domain, get the .com, .in from the domain name
        self.tld = self.domains.split(".")[-1]

        # Second Level Domain, get haridas from haridas.in
        self.sld = self.domains.split(".")[-2]

    def generate_text_record(self, domain_name=None, host_name=None,
                             record_name=None, record_value=None,
                             mx_pref=None, key=None, key_pub=None,
                             policy_strict=False, selector="test",
                             spf_ip_list=None,
                             spf_mechanism="ip4", spf_qualifier="-"
                            ):
        """
        Interface to External Programs.

        @parm record_name: dkim, spf
        @parm domain_name: Name of the domain for which we are creating record
                           it may be haridas.in, sub1.haridas.in, etc..

                           API will correctly pick the SLD and TLD to identify
                           the zone file and then use the complete domain name
                           to add record.
        @parm host_name: Actual subdomain name or catch all name "@" while
                         generating the dns record we required this.

        @param record_value: We are using TXT record for SPF and DKIM so, the
                            can be passed from the external API directly.or
                            from web UI. or for A record value.
        @param mx_pref: MX Record addition, This is similar to the A record
                        plus this value. Not yet implemented.

        @parm key: Pass the private key from external program for DKIM
                    operation.
        @param key_pub: Supply public key from outside.

        @param policy_strict: DKIM policy record value from outside.

        @param selector: DKIM selector name.

        @param spf_ip_list: Supply IP CIDR range if the mechanism is IP4.
                            Comma separated IPs or CIDR range of IP's.

        @param spf_mechanism: Which type of record we need to add.
                              ALL - Match all, to pass all cases, not good.
                              A   - Use A records under this domain to
                                    validate.
                              IP4 - Add IP address directly.
                              MX  - Use MX records specified in the DNS.

                              We can pass Comma sepearated string with any
                              of above options. eg;

                              'A,mx,IP4'

        @param spf_qualifier: SPF record nature to indicate whether the
                              receiver follow it strictly or nuetraly.
                              ~ : SOFTFAIL -DEBUGING the SPF record
                              ? : NUETRAL - Nuetral policy or accept all.
                              - : FAIL - Mail should be rejected if faild the
                                         SPF check.
                              + : PASS result alwas, very bad setting.

        """
        # Keep an option for the calling fun to pass the record type
        # and decide the operation flow.
        record_name = record_name or self.record_type
        domain_name = domain_name or self.domains

        assert record_name, "Provide Valid Record Name (A, TXT..)"
        assert domain_name, "Provide Valid Domain Name. No http:// part."

        if record_name in ["dkim", "DKIM"]:
            self.record_type = "TXT"

            # Check key was supplied from UI itself. It doesn't have
            # new line char.
            key_from_ui = False
            if key_pub:
                key_from_ui = True

            return self._generate_dkim(domain_name,
                                      selector=selector,
                                      key=key,
                                      key_pub=key_pub,
                                      policy_strict=policy_strict,
                                      key_from_ui=key_from_ui
                                     )

        elif record_name in ["spf", "SPF"]:
            self.record_type = "TXT"
            return self._generate_spf(domain_name, spf_ip_list,
                               spf_mechanism, spf_qualifier
                              )
        elif record_name in ['a', 'A']:
            self.record_type = "A"
            return self._generate_A_record(domain_name,
                                           record_value,
                                           host_name=host_name,
                                           mx_pref=None
                                          )
        else:
            raise NotImplemented("This options isn't implemented yet")

    def _generate_dkim(self, domain, selector="test",
                      key=None, key_pub=None, policy_strict=False,
                       key_from_ui=False,
                     ):
        """
        DKIM has two API calles with different TXT record.
        So we need to finish it in one go itself.
        """
        self.dkim = DKIM(domain, selector, key, key_pub, policy_strict)

        # Convert the multiline key into single line remove the first and
        # last line from the key.
        if key_from_ui:
            # No new line character from the UI.
            public_key = self.dkim.dkim_pub_key
        else:
            public_key = "\n".join(self.dkim.dkim_pub_key.split("\n")[1:-2])

        # conver key into single line.
        self.public_key = urllib.quote(public_key)

        # Policy_record_hostname.
        self.policy_hostname = "_domainkey.{0}.{1}".format(self.sld,
                                                           self.tld
                                                          )
        # Check for root domain name.
        self.policy_hostname = self.get_complete_domain_name(
            self.policy_hostname)

        self.policy_key_hostname = "{0}.{1}".format(selector,
                                                    self.policy_hostname
                                                   )
        # Record in DNS Compatible mode.
        self.dkim_policy_record = "{0}     IN      {1}     {2}".format(
            self.policy_hostname,
            self.record_type,
            self.dkim._dkim_policy
        )

        self.dkim_key_record = "{0}     IN      {1}     {2}".format(
            self.policy_key_hostname,
            self.record_type,
            "k=rsa;p={0}".format(self.public_key),
        )

    def _generate_spf(self, domain_name, spf_ip_list, spf_mechanism,
                      spf_qualifier
                    ):
        """
        Generate the spf with the same format as the dkim return value.
        tuple of values.

        """
        record_value = "v=spf1 "
        ip_string = ""
        mechanism_list = spf_mechanism.upper().split(',')

        if "A" in mechanism_list:
            # Constrcut the values using A record.
            ip_string = "a "

        if "MX" in mechanism_list:
            # Set space properly.
            ip_string += 'mx '

        # Check for IP4 tag is there from input arg.
        if 'IP4' or 'INCLUDE' in mechanism_list:
            # validate the iplist.
            if spf_ip_list:
                # ip4:2.3.3.2/2 ip4:3.3.3.3/2 ip4:4.4.4.4 - format this way.
                ips = spf_ip_list.split(",")

                ip_list = ["ip4:{0}".format(ip) for ip in ips]

                # Final IP string to construct record.
                ip_string += ' '.join(ip_list)
            else:
                # not a valid IPlist raise error.
                raise NotImplemented("Wrong IP string found")

        # Check for at least one of the mechanisms are there.
        if not mechanism_list:
            raise NotImplemented("Other Options into SPF are Not Valid")

        final_record = record_value + ip_string +\
                " {0}all".format(spf_qualifier)

        # SPF record compatible for DNS zone record.
        self.spf = "{0}     IN      {1}     {2}".format(
            self.get_complete_domain_name(domain_name),
            self.record_type,
            final_record,
        )

    def _generate_A_record(self, domain_name, record_value,
                           host_name=None, mx_pref=None):
        """
        Generate A record.
        """

        assert record_value, "Provide valid list or IPs or in CIDR"

        # remove SLD and TLD from the domain_name.
        self.host_name = host_name or "".join(domain_name.split(".")[:-2])

        # Set the mx_preference.
        self.mx_pref = mx_pref or self.mx_pref

        # SPF record compatible for DNS zone record.
        self.a = "{0}     IN      {1}     {2}".format(
            self.host_name,
            self.record_type,
            record_value
        )

    def get_complete_domain_name(self, domain_name):
        """
        Return the complete domain name including the root level domain.

        eg; harids.in -> haridas.in.
            sub1.haridas.in -> sub1.haridas.in.
        """
        if domain_name.split('.')[-1]:
            return domain_name
        else:
            return "{0}.".format(domain_name)


if __name__ == "__main__":
    """
    Main Entry point into the namecheap command tool.
    """
    pass
