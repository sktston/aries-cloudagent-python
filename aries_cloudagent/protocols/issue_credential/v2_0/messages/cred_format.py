"""Issue-credential protocol message attachment format."""

from collections import namedtuple
from enum import Enum
from typing import Sequence, Union
from uuid import uuid4

<<<<<<< HEAD
from marshmallow import EXCLUDE, fields, validate
=======
from marshmallow import EXCLUDE, fields
>>>>>>> main

from .....messaging.decorators.attach_decorator import AttachDecorator
from .....messaging.models.base import BaseModel, BaseModelSchema
from .....messaging.valid import UUIDFour

from ..models.detail.dif import V20CredExRecordDIF
from ..models.detail.indy import V20CredExRecordIndy

# aries prefix, cred ex detail record class
FormatSpec = namedtuple("FormatSpec", "aries detail")


class V20CredFormat(BaseModel):
    """Issue-credential protocol message attachment format."""

    class Meta:
        """Issue-credential protocol message attachment format metadata."""

        schema_class = "V20CredFormatSchema"

    class Format(Enum):
        """Attachment format."""

        INDY = FormatSpec("hlindy/", V20CredExRecordIndy)
        DIF = FormatSpec("dif/", V20CredExRecordDIF)

        @classmethod
        def get(cls, label: Union[str, "V20CredFormat.Format"]):
            """Get format enum for label."""
            if isinstance(label, str):
                for fmt in V20CredFormat.Format:
                    if label.startswith(fmt.aries) or label == fmt.api:
                        return fmt
            elif isinstance(label, V20CredFormat.Format):
                return label

            return None

        @property
        def api(self) -> str:
            """Admin API specifier."""
            return self.name.lower()

        @property
        def aries(self) -> str:
            """Aries specifier prefix."""
            return self.value.aries

        @property
        def detail(self) -> str:
            """Accessor for credential exchange detail class."""
            return self.value.detail

        def get_attachment_data(
            self,
            formats: Sequence["V20CredFormat"],
            attachments: Sequence[AttachDecorator],
        ):
            """Find attachment of current format, decode and return its content."""
            for fmt in formats:
                if V20CredFormat.Format.get(fmt.format) is self:
                    attach_id = fmt.attach_id
                    break
            else:
                return None

            for atch in attachments:
                if atch.ident == attach_id:
                    return atch.content

            return None

    def __init__(
        self,
        *,
        attach_id: str = None,
        format_: str = None,
    ):
        """Initialize issue-credential protocol message attachment format."""
        self.attach_id = attach_id or uuid4()
        self.format_ = format_

    @property
    def format(self) -> str:
        """Return format."""
        return self.format_


class V20CredFormatSchema(BaseModelSchema):
    """Issue-credential protocol message attachment format schema."""

    class Meta:
        """Issue-credential protocol message attachment format schema metadata."""

        model_class = V20CredFormat
        unknown = EXCLUDE

    attach_id = fields.Str(
        required=True,
        allow_none=False,
        description="Attachment identifier",
        example=UUIDFour.EXAMPLE,
    )
    format_ = fields.Str(
        required=True,
        allow_none=False,
        description="Attachment format specifier",
        data_key="format",
<<<<<<< HEAD
        validate=validate.Regexp("^(hlindy/.*@v2.0)|(dif/.*@v1.0)$"),
=======
>>>>>>> main
        example="dif/credential-manifest@v1.0",
    )
