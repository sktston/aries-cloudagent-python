"""jsonld admin routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import Schema, fields
from marshmallow.utils import INCLUDE
from pydid.doc.verification_method import VerificationMethod

from ...admin.request_context import AdminRequestContext
from ...config.base import InjectionError
from ...resolver.base import ResolverError
from ...resolver.did_resolver import DIDResolver
from ...wallet.error import WalletError
from ..models.openapi import OpenAPISchema
from .credential import sign_credential, verify_credential
from .error import (
<<<<<<< HEAD
    BadJWSHeaderError,
    DroppedAttributeError,
=======
    BaseJSONLDMessagingError,
    InvalidVerificationMethod,
>>>>>>> main
    MissingVerificationMethodError,
)


class SignRequestSchema(OpenAPISchema):
    """Request schema for signing a jsonld doc."""

    verkey = fields.Str(required=True, description="Verkey to use for signing")
    doc = fields.Nested(
        Schema.from_dict(
            {
                "credential": fields.Dict(
                    required=True,
                    description="Credential to sign",
                ),
                "options": fields.Nested(
                    Schema.from_dict(
                        {
                            "creator": fields.Str(required=False),
                            "verificationMethod": fields.Str(required=False),
                            "proofPurpose": fields.Str(required=False),
                        }
                    ),
                    required=True,
                ),
            }
        ),
        required=True,
    )


class SignResponseSchema(OpenAPISchema):
    """Response schema for a signed jsonld doc."""

    signed_doc = fields.Dict(description="Signed document", required=False)
    error = fields.Str(description="Error text", required=False)


@docs(tags=["jsonld"], summary="Sign a JSON-LD structure and return it")
@request_schema(SignRequestSchema())
@response_schema(SignResponseSchema(), 200, description="")
async def sign(request: web.BaseRequest):
    """
    Request handler for signing a jsonld doc.

    Args:
        request: aiohttp request object

    """
    response = {}
    body = await request.json()
    doc = body.get("doc")
    try:
        context: AdminRequestContext = request["context"]
        async with context.session() as session:
<<<<<<< HEAD
            wallet = session.inject(BaseWallet, required=False)
            if not wallet:
                raise web.HTTPForbidden(reason="No wallet available")
            document_with_proof = await sign_credential(
                credential, signature_options, verkey, wallet
=======
            doc_with_proof = await sign_credential(
                session, doc.get("credential"), doc.get("options"), body.get("verkey")
>>>>>>> main
            )
            response["signed_doc"] = doc_with_proof
    except (BaseJSONLDMessagingError) as err:
        response["error"] = str(err)
    except (WalletError, InjectionError):
        raise web.HTTPForbidden(reason="No wallet available")
    return web.json_response(response)

<<<<<<< HEAD
        response["signed_doc"] = document_with_proof
    except (DroppedAttributeError, MissingVerificationMethodError) as err:
        response["error"] = str(err)
=======
>>>>>>> main

class DocSchema(OpenAPISchema):
    """Verifiable doc schema."""

    class Meta:
        """Keep unknown values."""

        unknown = INCLUDE

    proof = fields.Nested(
        Schema.from_dict(
            {
                "creator": fields.Str(required=False),
                "verificationMethod": fields.Str(required=False),
                "proofPurpose": fields.Str(required=False),
            }
        )
    )


class VerifyRequestSchema(OpenAPISchema):
    """Request schema for signing a jsonld doc."""

    verkey = fields.Str(
        required=False, description="Verkey to use for doc verification"
    )
    doc = fields.Dict(
        required=True,
        description="Credential to verify",
    )


class VerifyResponseSchema(OpenAPISchema):
    """Response schema for verification result."""

    valid = fields.Bool(required=True)
    error = fields.Str(description="Error text", required=False)


@docs(tags=["jsonld"], summary="Verify a JSON-LD structure.")
@request_schema(VerifyRequestSchema())
@response_schema(VerifyResponseSchema(), 200, description="")
async def verify(request: web.BaseRequest):
    """
    Request handler for signing a jsonld doc.

    Args:
        request: aiohttp request object

    """
    response = {"valid": False}
    try:
        context: AdminRequestContext = request["context"]
        profile = context.profile
        body = await request.json()
        verkey = body.get("verkey")
        doc = body.get("doc")
        async with context.session() as session:
<<<<<<< HEAD
            wallet = session.inject(BaseWallet, required=False)
            if not wallet:
                raise web.HTTPForbidden(reason="No wallet available")
            valid = await verify_credential(doc, verkey, wallet)

        response["valid"] = valid
    except (BadJWSHeaderError, DroppedAttributeError) as e:
        response["error"] = str(e)
=======
            if verkey is None:
                resolver = session.inject(DIDResolver)
                ver_meth_expanded = await resolver.dereference(
                    profile, doc["proof"]["verificationMethod"]
                )

                if ver_meth_expanded is None:
                    raise MissingVerificationMethodError(
                        f"Verification method "
                        f"{doc['proof']['verificationMethod']} not found."
                    )
>>>>>>> main

                if not isinstance(ver_meth_expanded, VerificationMethod):
                    raise InvalidVerificationMethod(
                        "verificationMethod does not identify a valid verification method"
                    )

                verkey = ver_meth_expanded.material

            valid = await verify_credential(session, doc, verkey)

        response["valid"] = valid
    except (
        BaseJSONLDMessagingError,
        ResolverError,
    ) as error:
        response["error"] = str(error)
    except (WalletError, InjectionError):
        raise web.HTTPForbidden(reason="No wallet available")
    return web.json_response(response)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes([web.post("/jsonld/sign", sign), web.post("/jsonld/verify", verify)])


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "jsonld",
            "description": "Sign and verify json-ld data",
            "externalDocs": {
                "description": "Specification",
                "url": "https://tools.ietf.org/html/rfc7515",
            },
        }
    )
