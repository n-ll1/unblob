from os import getenv
import io
import struct
from typing import Optional

from structlog import get_logger

from ...extractors import Command
from ...file_utils import InvalidInputFormat, iterate_patterns, Endian
from ...models import (
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

logger = get_logger()

class NoTSHKeyFile(Exception):
    pass


class TSHHandler(StructHandler):
    NAME = "tsh"

    PATTERNS = [
        HexString(
            """
            // 4 bytes magic: TSH_
            54 53 48 5F
            // 8 bytes Encrypted File Length
            [8]
            // 32 bytes Unencrypted SHA 256 hash
            [32]
            """
        )
    ]

    C_DEFINITIONS = r"""

        typedef struct tsh_file_header {
            char magic[4];                  /* TSH_ */
            uint64_t enc_file_len;          /* Length of the encrypted file in bytes */
            uint8_t unenc_file_hash[32];    /* The SHA256 hash of the decrypted file */
            char filename[];                /* The name of the encrypted file */
        } tsh_file_header_t;
    """

    HEADER_STRUCT = "tsh_file_header_t"

    tsh_key_file = getenv("TSH_KEY_FILE")

    if tsh_key_file is None:
        logger.warn("Failed to find the TSH_KEY_FILE environment vairable. Won't attempt extraction of TSH files")
        EXTRACTOR = None
    else:
        EXTRACTOR = Command("extract_TSH_archive", f"-k{tsh_key_file}", "-d{outdir}", "{inpath}")

    DOC = HandlerDoc(
        name="TSH",
        description="TSH is an encrypted archive file format. "
                "You must set the `TSH_KEY_FILE` environment viariable to the path of the TSH key file",
        handler_type=HandlerType.ARCHIVE,
        vendor=None,
        references=[
            Reference(
                title="TSH Source Code",
                url="https://github.com/n-ll1/configs/tree/development/firmware/tsh_archiver",
            ),
        ],
        limitations=["Requires the TSH_KEY_FILE variable to be configured"],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset, io.SEEK_SET)
        header = self.parse_header(file, Endian.LITTLE)
        # Header length + file length
        end_offset = start_offset + len(header) + header.enc_file_len
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
