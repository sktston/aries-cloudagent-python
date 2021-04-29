"""
Contains the functions needed to produce and verify a json-ld signature.

This file was ported from
https://github.com/transmute-industries/Ed25519Signature2018/blob/master/
    src/createVerifyData/index.js
"""

import datetime
import hashlib

from pyld import jsonld

<<<<<<< HEAD
from .error import DroppedAttributeError, MissingVerificationMethodError
=======
from .error import (
    DroppedAttributeError,
    MissingVerificationMethodError,
    SignatureTypeError,
)
>>>>>>> main


def _canonize(data):
    return jsonld.normalize(
        data, {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )


def _sha256(data):
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _canonize_signature_options(signatureOptions):
    _signatureOptions = {**signatureOptions, "@context": "https://w3id.org/security/v2"}
    _signatureOptions.pop("jws", None)
    _signatureOptions.pop("signatureValue", None)
    _signatureOptions.pop("proofValue", None)
    return _canonize(_signatureOptions)


def _canonize_document(doc):
    _doc = {**doc}
    _doc.pop("proof", None)
    return _canonize(_doc)


<<<<<<< HEAD
def create_verify_data(data, signature_options):
    """Encapsulate the process of constructing the string used during sign and verify."""

    if "creator" in signature_options:
        signature_options["verificationMethod"] = signature_options["creator"]

    if not signature_options.get("verificationMethod"):
        raise MissingVerificationMethodError(
            "signature_options.verificationMethod is required"
        )
=======
def _created_at():
    """Creation Timestamp."""

    stamp = datetime.datetime.now(datetime.timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def create_verify_data(data, signature_options):
    """Encapsulate the process of constructing the string used during sign and verify."""

    type_ = signature_options.get("type", "Ed25519Signature2018")
    if type_ and type_ != "Ed25519Signature2018":
        raise SignatureTypeError(f"invalid signature type {type_}.")
>>>>>>> main

    signature_options["verificationMethod"] = signature_options.get(
        "creator", signature_options.get("verificationMethod")
    )

    if not signature_options.get("verificationMethod"):
        raise MissingVerificationMethodError(
            "signature_options.verificationMethod is required"
        )

    signature_options["created"] = signature_options.get("created", _created_at())
    [expanded] = jsonld.expand(data)
    framed = jsonld.compact(
        expanded, "https://w3id.org/security/v2", {"skipExpansion": True}
    )

    # Detect any dropped attributes during the expand/contract step.
<<<<<<< HEAD
    if len(data) != len(framed):
        raise DroppedAttributeError("Extra Attribute Detected")
    if (
        "proof" in data
        and "proof" in framed
        and len(data["proof"]) != len(framed["proof"])
    ):
        raise DroppedAttributeError("Extra Attribute Detected")
    if (
        "credentialSubject" in data
        and "https://www.w3.org/2018/credentials#credentialSubject" in framed
        and len(data["credentialSubject"])
        != len(framed["https://www.w3.org/2018/credentials#credentialSubject"])
    ):
        raise DroppedAttributeError("Extra Attribute Detected")
=======
    if len(data) > len(framed):
        # > check indicates dropped attrs < is a different error
        # attempt to collect error report data
        for_diff = jsonld.compact(expanded, data.get("@context"))
        dropped = set(data.keys()) - set(for_diff.keys())
        raise DroppedAttributeError(
            f"{dropped} attributes dropped. "
            "Provide definitions in context to correct."
        )
    # Check proof for dropped attributes
    attr = [
        ("proof", "proof"),
        ("credentialSubject", "https://www.w3.org/2018/credentials#credentialSubject"),
    ]
    data_context = data.get("@context")
    for mapping in attr:
        data_attribute = data.get(mapping[0], {})
        frame_attribute = framed.get(mapping[1], {})
        if len(data_attribute) > len(frame_attribute):
            for_diff = jsonld.compact(expanded, data_context)
            for_diff_attribute = for_diff.get(mapping[1], {})
            dropped = set(data_attribute.keys()) - set(for_diff_attribute.keys())
            raise DroppedAttributeError(
                f"in {mapping[0]}, {dropped} attributes dropped. "
                "Provide definitions in context to correct."
            )
>>>>>>> main

    canonized_signature_options = _canonize_signature_options(signature_options)
    hash_of_canonized_signature_options = _sha256(canonized_signature_options)
    canonized_document = _canonize_document(framed)
    hash_of_canonized_document = _sha256(canonized_document)

    return (framed, hash_of_canonized_signature_options + hash_of_canonized_document)
