'''
This file contains the ASN.1 Object Templates for the RPKI objects according to the respective RFCs.
The templates are used by the asn1crypto parser to parse the RPKI objects to Python dictionaries.
'''


from asn1crypto.core import (
    BitString,
    Integer,
    OctetString,
    Sequence,
    SequenceOf,
    GeneralizedTime,
    ObjectIdentifier,
    IA5String
)

from asn1crypto.cms import Name, Time, Extensions
from asn1crypto.algos import AnyAlgorithmIdentifier


class RevokedCertificate(Sequence):
    _fields = [
        ('userCertificate', Integer),
        ('revocationDate', Time),
        ('crlEntryExtensions', Extensions, {'explicit': 0, 'optional': True})
    ]


class RevokedCertificates(SequenceOf):
    _child_spec = RevokedCertificate


class TBSCertList(Sequence):
    _fields = [
        ('version', Integer, {'optional': True}),
        ('signature', AnyAlgorithmIdentifier),
        ('issuer', Name),
        ('thisUpdate', Time),
        ('nextUpdate', Time, {'optional': True}),
        ('revokedCertificates', RevokedCertificates, {'optional': True}),
        ('crlExtensions', Extensions, {'explicit': 0, 'optional': True})

    ]


class CertificateRevocationList(Sequence):
    _fields = [
        ('tbsCertList', TBSCertList),
        ('signatureAlgorithm', AnyAlgorithmIdentifier),
        ('signatureValue', BitString),
    ]


class FileAndHash(Sequence):
    _fields = [
        ('file', IA5String),
        ('hash', BitString),
    ]


class FileAndHashes(SequenceOf):
    _child_spec = FileAndHash


class Manifest(Sequence):
    _fields = [
        ('version', Integer, {'explicit': 0, 'default': 0}),
        ('manifestNumber', Integer),
        ('thisUpdate', GeneralizedTime),
        ('nextUpdate', GeneralizedTime),
        ('fileHashAlg', ObjectIdentifier),
        ('fileList', FileAndHashes),
    ]


class ROAIPAddress(Sequence):
    _fields = [
        ('address', BitString),
        ('maxLength', Integer, {'optional': True})
    ]


class Addresses(SequenceOf):
    _child_spec = ROAIPAddress


class ROAIPAddressFamily(Sequence):
    _fields = [
        ('addressFamily', OctetString),
        ('addresses', Addresses)
    ]


class ROAIPAddressFamilies(SequenceOf):
    _child_spec = ROAIPAddressFamily


class RouteOriginAttestation(Sequence):
    _fields = [
        ('version', Integer, {'explicit': 0, 'default': 0}),
        ('as-id', Integer),
        ('ipAddrBlocks', ROAIPAddressFamilies)
    ]
