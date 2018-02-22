#!/usr/bin/env python3
# (c) 2014 Patryk Hes
import socketserver
import sys
import time # by haelee

DNS_HEADER_LENGTH = 12
# TODO make some DNS database with IPs connected to regexs
IP = '192.168.233.128'
NSIP = '192.168.233.131'

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        socket = self.request[1]
        data = self.request[0].strip()

        # If request doesn't even contain full header, don't respond.
        if len(data) < DNS_HEADER_LENGTH:
            return

        # Try to read questions - if they're invalid, don't respond.
        try:
            all_questions = self.dns_extract_questions(data)
        except IndexError:
            return

        # Filter only those questions, which have QTYPE=A and QCLASS=IN
        # TODO this is very limiting, remove QTYPE filter in future, handle different QTYPEs
        accepted_questions = []
        response_type = 1; # 1: A, 2: NS
        for question in all_questions:
            name = str(b'.'.join(question['name']), encoding='UTF-8')
            if question['qtype'] == b'\x00\x01' and question['qclass'] == b'\x00\x01':
                accepted_questions.append(question)
                print('\033[32m{}\033[39m'.format(name))
            else:
                print('\033[31m{}\033[39m'.format(name))

            if name[-3:] == 'bad':
                response_type = 2 # 2: NS
                print('.bad domain')

        if (len (accepted_questions) == 0):
            return

        if (response_type == 1):
            response = (
                self.dns_response_a_header(data) +
                self.dns_response_questions(accepted_questions) +
                self.dns_response_answers(accepted_questions, IP)
            )
        else:
            response = (
                self.dns_response_ns_header(data) +
                self.dns_response_questions(accepted_questions) +
                self.dns_response_authorities(accepted_questions) +
                self.dns_response_answers(accepted_questions, NSIP)
            )
        time.sleep(0.5) # by haelee
        socket.sendto(response, self.client_address)

    def dns_extract_questions(self, data):
        """
        Extracts question section from DNS request data.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        questions = []
        # Get number of questions from header's QDCOUNT
        n = (data[4] << 8) + data[5]
        # Where we actually read in data? Start at beginning of question sections.
        pointer = DNS_HEADER_LENGTH
        # Read each question section
        for i in range(n):
            question = {
                'name': [],
                'qtype': '',
                'qclass': '',
            }
            length = data[pointer]
            # Read each label from QNAME part
            while length != 0:
                start = pointer + 1
                end = pointer + length + 1
                question['name'].append(data[start:end])
                pointer += length + 1
                length = data[pointer]
            # Read QTYPE
            question['qtype'] = data[pointer+1:pointer+3]
            # Read QCLASS
            question['qclass'] = data[pointer+3:pointer+5]
            # Move pointer 5 octets further (zero length octet, QTYPE, QNAME)
            pointer += 5
            questions.append(question)
        return questions

    def dns_response_a_header(self, data):
        """
        Generates DNS response header.
        See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
        """
        header = b''
        # ID - copy it from request
        header += data[:2]
        # QR     1    response
        # OPCODE 0000 standard query
        # AA     0    not authoritative
        # TC     0    not truncated
        # RD     0    recursion not desired
        # RA     0    recursion not available
        # Z      000  unused
        # RCODE  0000 no error condition
        header += b'\x80\x00'
        # QDCOUNT - question entries count, set to QDCOUNT from request
        header += data[4:6]
        # ANCOUNT - answer records count, set to QDCOUNT from request
        header += data[4:6]
        # NSCOUNT - authority records count, set to 0
        header += b'\x00\x00'
        # ARCOUNT - additional records count, set to 0
        header += b'\x00\x00'
        return header

    def dns_response_ns_header(self, data):
        """
        Generates DNS response header.
        See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
        """
        header = b''
        # ID - copy it from request
        header += data[:2]
        # QR     1    response
        # OPCODE 0000 standard query
        # AA     0    not authoritative
        # TC     0    not truncated
        # RD     0    recursion not desired
        # RA     0    recursion not available
        # Z      000  unused
        # RCODE  0000 no error condition
        header += b'\x80\x00'
        # QDCOUNT - question entries count, set to QDCOUNT from request
        header += data[4:6]
        # ANCOUNT - answer records count, set to QDCOUNT from request
        header += b'\x00\x00'
        # NSCOUNT - authority records count, set to 0
        header += data[4:6]
        # ARCOUNT - additional records count, set to 0
        header += data[4:6]
        return header

    def dns_response_questions(self, questions):
        """
        Generates DNS response questions.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        sections = b''
        for question in questions:
            section = b''
            for label in question['name']:
                # Length octet
                section += bytes([len(label)])
                section += label
            # Zero length octet
            section += b'\x00'
            section += question['qtype']
            section += question['qclass']
            sections += section
        return sections

    def dns_response_answers(self, questions, ip_address):
        records = b''

        for question in questions:
            record = b''

            # Name
            for label in question['name']:
                record += bytes([len(label)])
                record += label
            record += b'\x00'

            # Type
            record += question['qtype']

            # Class: IN
            record += b'\x00\x01'

            # TTL: 0 minutes (600 seconds)
            record += b'\x00\x00\x02\x58'

            # Data length: 4 bytes (IP address)
            record += b'\x00\x04'

            # Data: IP address
            record += b''.join(map(lambda x: bytes([int(x)]), ip_address.split('.')))

            records += record

        return records

    def dns_response_authorities(self, questions):
        records = b''

        for question in questions:
            record = b''

            name = b''
            length = 0
            for label in question['name']:
                name += bytes([len(label)])
                name += label
                length += len(label) + 1
            length += 1
            name += b'\x00'

            # Name
            record += name

            # Type: NS
            record += b'\x00\x02'

             # Class: IN
            record += b'\x00\x01'

            # TTL: 0 minutes (600 seconds)
            record += b'\x00\x00\x02\x58'

            # Data length
            record += b'\x00'
            record += bytes([length])

            # Data: Name server
            record += name

            records += record

        return records

if __name__ == '__main__':
    # Minimal configuration - allow to pass IP in configuration
    if len(sys.argv) > 1:
        IP = sys.argv[1]
    host, port = '', 53
    server = socketserver.ThreadingUDPServer((host, port), DNSHandler)
    print('\033[36mStarted DNS server.\033[39m')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)
