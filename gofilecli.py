"""
gofile.io python client, provides both CLI and library functionnality.
"""
import logging
import os
import sys
import re
import ssl
import json
from argparse import ArgumentParser, Namespace
from http.client import HTTPSConnection, HTTPException
from collections import namedtuple


logger = logging.getLogger(__name__)


def _init_logger(level : int):
    """
    Initialize the module logger for CLI.

    Args:
        level (int): Level of verbosity between 0 and 2 (inclusive).
                     Maps in order to WARNING, INFO, DEBUG.
                     Integers > 2 behave identically to 2.

    Raises:
        ValueError: If a negative number was provided.
    """
    logging.basicConfig()
    if level == 0:
        logger.setLevel(logging.WARNING)
    elif level == 1:
        logger.setLevel(logging.INFO)
    elif level >= 2:
        logger.setLevel(logging.DEBUG)
    else:
        raise ValueError(f"{level} is not a valid verbosity level.")


def validate_url(url_candidate : str) -> str | None:
    """
    Accepts a potentiel gofile.io URL and returns the associated content ID
    if the URL is valid.

    Args:
        url_candidate (str): The string to validate and parse.

    Returns:
        str | None: The content code (if it exists).
    """
    gofile_pattern = re.compile(r"^https?://gofile.io/d/(?P<content_id>[a-zA-Z0-9]{6})$")
    match = gofile_pattern.match(url_candidate)
    if match is None:
        return None
    return match.group("content_id")


class GofileException(Exception):
    """Raised by the modules components"""

class GofileNetworkException(GofileException):
    """Raised when a network error occurs"""

class GofileAPIException(GofileException):
    """Raised when the API protocol returns an error"""

class API:
    """Wrapper for API calls."""

    GOFILE_API_HOST = 'api.gofile.io'
    GOFILE_UPLOAD_HOST = '{server}.gofile.io'

    ENCODING = 'utf-8'

    def __init__(self,
                 token : str | None = None,
                 ssl_context : ssl.SSLContext | None = None) -> None:
        """
        Create an API wrapper.

        Args:
            access_token (str | None, optional): The account token to use for API calls that require it. Defaults to None.
            ssl_context (ssl.SSLContext | None, optional): Optional SSL context to use for the connections. Defaults to None.
        """
        self.token = token
        if ssl_context is not None:
            logger.warning("Using user provided SSL context.")
            self._ssl_context = ssl_context
        else:
            self._ssl_context = ssl.create_default_context()
        self._api_connection = HTTPSConnection(self.GOFILE_API_HOST,
                                               context = self._ssl_context)

    def close(self) -> None:
        """Close the underlying connections."""
        logger.debug("Closing connection to %s", self.GOFILE_API_HOST)
        self._api_connection.close()

    def get_upload_server(self) -> str:
        """
        Ask the API for the best server available for file uploading.
        Wrapper for '/getServer'.

        Returns:
            str: The name of the best server (for example : 'store1').

        Raises:
            GofileNetworkException: In case of bad return code or network related exception.
            GofileAPIException: In case of bad API status or data related exception.
        """
        try:
            logger.info("Querying the best upload server available.")
            self._api_connection.request('GET',
                                         '/getServer',
                                         headers = {'Host' : self.GOFILE_API_HOST,
                                                    'Accept' : 'application/json'})
            response = self._api_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s.", response.status)
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s.", response.status)
            r_body = response.read().decode(self.ENCODING)
            r_data = json.loads(r_body)
            logger.debug("Data received : %s", r_data)
            if r_data['status'] == 'ok':
                return r_data['data']['server']
            raise GofileAPIException(f"API status not ok : {r_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s.", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s.", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            self.close()

    def upload_file(self,
                    file_path : str | None = None,
                    file_content : tuple[bytes, str] | None = None,
                    folder_id : str | None = None,
                    upload_server : str | None = None):
        """
        Upload the provided file to the chosen destination.
        The file to upload can be read from a path,
        or the binary content can be supplied directly with a filename.
        If no gofile destination folder is provided, a new one will be created.
        If no upload server is chosen, one will be selected automatically.
        Without a token, the file will be uploaded anonymously to a guest account.
        Wrapper for '/uploadFile'

        Args:
            file_path (str | None, optional): Path for the file to upload (exclusive with file_content). Defaults to None.
            file_content (tuple[bytes, str] | None, optional): Content of the file and filename (exclusive with file_path). Defaults to None.
            folder_id (str | None, optional): ID of the gofile destination folder. Defaults to None.
            upload_server (str | None, optional): Name of the upload server to use. Defaults to None.

        Raises:
            ValueError: When both or none of file_data and file_path are given.
            GofileNetworkException: In case of bad return code or network related exception.
            GofileAPIException: In case of bad API status or data related exception.

        Returns:
            _type_: _description_
        """
        if folder_id is not None and self.token is None:
            logger.warning("Unable to use the provided folderId, token is needed.")
            folder_id = None
        if file_path is not None and file_content is not None:
            logger.error("Ambiguous arguments file_path and file_content are mutually exclusive.")
            raise ValueError("Both file_path and file_content are present when only one is needed.")
        if file_path is None and file_content is None:
            logger.error("At least one of fil_path or file_content must be given.")
            raise ValueError("At least one of fil_path or file_content must be given.")
        if file_path is not None:
            logger.info("Reading file %s", file_path)
            with open(file_path, 'rb') as file:
                file_data = file.read()
            file_name = os.path.basename(file_path)
        else:
            file_data = file_content[0]
            file_name = file_content[1]

        boundary = "-------PYTHON-GOFILECLI-BOUNDARY"

        def generate_formdata(token : str | None,
                              folder_id : str | None,
                              file_data : bytes,
                              file_name : str,
                              boundary : str):
            formdata = ""
            if token is not None:
                formdata += f'--{boundary}\r\nContent-Disposition: form-data; name="token"\r\n\r\n{token}\r\n'
            if folder_id is not None:
                formdata += f'--{boundary}\r\nContent-Disposition: form-data; name="folderId"\r\n\r\n{folder_id}\r\n'
            formdata += f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{file_name}"\r\n'
            formdata += 'Content-Type: application/octet-stream\r\n\r\n'
            return formdata.encode(self.ENCODING) + file_data + f"\r\n--{boundary}--\r\n".encode(self.ENCODING)

        body = generate_formdata(self.token, folder_id, file_data, file_name, boundary)

        try:
            if upload_server is None:
                upload_server = self.get_upload_server()
            logger.info("Starting upload of %s bytes to %s.",
                        len(body),
                        self.GOFILE_UPLOAD_HOST.format(server = upload_server))
            upload_connection = HTTPSConnection(self.GOFILE_UPLOAD_HOST.format(server = upload_server),
                                                context = self._ssl_context)
            upload_connection.request('POST',
                                      '/uploadFile',
                                      body,
                                      {'Host' : self.GOFILE_UPLOAD_HOST.format(server = upload_server),
                                       'Content-Length' : f"{len(body)}",
                                       'Content-Type' : f"multipart/form-data; boundary={boundary}"})
            response = upload_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s.", response.status)
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s.", response.status)
            response_data = json.loads(response.read().decode(self.ENCODING))
            logger.debug("Data received : %s", response_data)
            if response_data['status'] == 'ok':
                return UploadResult(response_data['data']['code'],
                                    response_data['data']['downloadPage'],
                                    response_data['data']['fileId'],
                                    response_data['data']['fileName'],
                                    response_data['data']['md5'],
                                    response_data['data']['parentFolder'])
            raise GofileAPIException(f"API status not ok : {response_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s.", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s.", decode_error)
            raise GofileAPIException() from decode_error

UploadResult = namedtuple("UploadResult",
                          ["code",
                           "download_page",
                           "file_id",
                           "filename",
                           "md5",
                           "parent_folder"]) 


def cli_download(args : Namespace):
    """Download one or multiple gofile items"""


def main() -> int:
    """Main function for CLI functionnality"""
    parser_command = ArgumentParser(prog = "gofilecli",
                                    description = "gofile.io python client",
                                    epilog = '')

    parser_command.add_argument("-v", "--verbose",
                                action = "count",
                                default = 0,
                                type = int,
                                help = "Increase the verbosity (up to two times)")
    
    parser_command.add_argument("-t", "--token",
                                type = str,
                                help = "Account token to use")

    parser_subcommands = parser_command.add_subparsers(title = "command",
                                                       description = "The action to perform",
                                                       required = True)

    parser_download = parser_subcommands.add_parser("download",
                                                    description = "Download gofile items to local storage",
                                                    help = "")

    # Set the handler for the download subcommand
    parser_download.set_defaults(func = cli_download)

    parser_download.add_argument("items",
                                 nargs = "+",
                                 help = "Items to download, can be a complete URL or raw content ID")
    
    parser_download.add_argument("-d", "--destination",
                                 help = "Target directory for the downloaded files/folders, defaults to current working directory",
                                 default = os.getcwd())
    
    parser_download.add_argument("-f", "--flatten",
                                 help = "Download the remote files without reproducing the folder hierarchy")
    
    args = parser_command.parse_args(sys.argv)
    
    _init_logger(args.verbose)

    # Call the handler function for the selected subcommand
    args.func(args)
    

if __name__ == "__main__":
    sys.exit(main())
