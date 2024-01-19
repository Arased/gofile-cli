"""
gofile.io python client, provides both CLI and library functionnality
"""
import logging
import os
import sys
import re
import ssl
import json
import hashlib
from dataclasses import dataclass
from collections import namedtuple
from enum import Enum
from argparse import ArgumentParser, Namespace
from http.client import HTTPSConnection, HTTPException, HTTPResponse
from urllib import parse


logger = logging.getLogger(__name__)


class Formatter(logging.Formatter):
    """Basic formatter subclass that adds color"""

    GREY = "\x1b[38;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    RED_BOLD = "\x1b[31;1m"
    BLUE = "\x1b[34;20m"
    RESET = "\x1b[0m"

    FORMATS = {
        logging.DEBUG: BLUE,
        logging.INFO: GREY,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: RED_BOLD
    }

    def format(self, record):
        return self.FORMATS[record.levelno] + super().format(record) + self.RESET


def _init_logger(level : int):
    """
    Initialize the module logger for CLI

    Args:
        level (int): Level of verbosity between 0 and 2 (inclusive)
                     Maps in order to WARNING, INFO, DEBUG
                     Integers > 2 behave identically to 2

    Raises:
        ValueError: If a negative number was provided
    """
    if level == 0:
        logger.setLevel(logging.WARNING)
    elif level == 1:
        logger.setLevel(logging.INFO)
    elif level >= 2:
        logger.setLevel(logging.DEBUG)
    else:
        raise ValueError(f"{level} is not a valid verbosity level")
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)
    handler.setFormatter(Formatter("%(levelname)s : %(message)s"))
    logger.addHandler(handler)


def parse_url(url_candidate : str) -> str | None:
    """
    Accepts a potential gofile.io URL and returns the associated content ID
    if the URL is valid

    Args:
        url_candidate (str): The string to validate and parse

    Returns:
        str | None: The content code (if it exists)
    """
    gofile_path_pattern = re.compile(r"^/d/(?P<content_code>[a-zA-Z0-9]{6})$")
    try:
        url = parse.urlparse(url_candidate)
    except ValueError:
        return None
    if url.netloc == 'gofile.io':
        match = gofile_path_pattern.match(url.path)
        if match is None:
            return None
    else:
        return None
    return match.group("content_code")


class GofileException(Exception):
    """Raised by the modules components"""

class GofileNetworkException(GofileException):
    """Raised when a network error occurs"""

class GofileAPIException(GofileException):
    """Raised when the API protocol returns an error"""


UploadResult = namedtuple("UploadResult",
                          ["code",
                           "download_page",
                           "file_id",
                           "filename",
                           "md5",
                           "parent_folder"])


class ExistPolicy(Enum):
    """Actions when destination file exist"""
    OVERWRITE = "overwrite"  # Always overwrite
    SKIP = "skip"  # Always skip
    RESUME = "resume"  # Download remainder, skip if complete


class ContentType(Enum):
    """Shortcut for gofile content types"""
    FOLDER = "folder"
    FILE = "file"


@dataclass
class Content:
    """Represent any gofile object"""
    content_id : str
    name : str
    parent : str | None
    type : ContentType
    create_time : int


@dataclass(init = False)
class File(Content):
    """Represent a gofile file"""

    def __init__(self,
                 content_id : str,
                 name : str,
                 parent : str,
                 create_time : int,
                 download_count : int,
                 size : int,
                 link : str,
                 md5 : str,
                 mime_type : str,
                 server : str) -> None:
        super().__init__(content_id = content_id,
                         name = name,
                         parent = parent,
                         create_time = create_time,
                         type = ContentType.FILE)
        self.download_count = download_count
        self.size = size
        self.link = link
        self.md5 = md5
        self.mime_type = mime_type
        self.server = server


@dataclass(init = False)
class Folder(Content):
    """
    Represent a gofile folder
    When a folder object was not directly returned from API.get_content
    the children attribute might be None.
    """

    def __init__(self,
                 content_id : str,
                 name : str,
                 parent : str | None,
                 create_time : int,
                 is_owner : bool,
                 is_public : bool,
                 code : str,
                 children : list[Content] | None) -> None:
        super().__init__(content_id = content_id,
                         name = name,
                         parent = parent,
                         create_time = create_time,
                         type = ContentType.FOLDER)
        self.is_owner = is_owner
        self.is_public = is_public
        self.is_root = parent is None
        self.code = code
        self.children = children


@dataclass
class Account:
    """Represent a gofile account"""
    credit : int
    currency : str
    currency_sign : str
    email : str
    files_count : int
    files_count_limit : int
    account_id : str
    premium_type : str
    root_folder : str
    statistics : dict
    tier : str
    token : str
    total_30ddl_traffic : int
    total_30ddl_traffic_limit : int
    total_size : int
    total_size_limit : int


class API:
    """Wrapper for API calls"""

    GOFILE_API_HOST = 'api.gofile.io'
    GOFILE_UPLOAD_HOST = '{server}.gofile.io'
    GOFILE_DOWNLOAD_HOST = GOFILE_UPLOAD_HOST

    ENCODING = 'utf-8'

    def __init__(self,
                 token : str | None = None,
                 ssl_context : ssl.SSLContext | None = None) -> None:
        """
        Create an API wrapper

        Args:
            access_token (str | None, optional): The account token to use for API calls that require it. Defaults to None
            ssl_context (ssl.SSLContext | None, optional): Optional SSL context to use for the connections. Defaults to None
        """
        self.token : str = token
        if ssl_context is not None:
            logger.warning("Using user provided SSL context")
            self._ssl_context = ssl_context
        else:
            self._ssl_context = ssl.create_default_context()
        self._api_connection = HTTPSConnection(self.GOFILE_API_HOST,
                                               context = self._ssl_context)

    def close(self) -> None:
        """Close the underlying connections"""
        logger.debug("Closing connection to %s", self.GOFILE_API_HOST)
        self._api_connection.close()

    def get_upload_server(self) -> str:
        """
        Ask the API for the best server available for file uploading
        Wrapper for '/getServer'

        Returns:
            str: The name of the best server (for example : 'store1')

        Raises:
            GofileNetworkException: In case of bad return code or network related exception
            GofileAPIException: In case of bad API status or data related exception
        """
        try:
            logger.info("Querying the best upload server available")
            self._api_connection.request('GET',
                                         '/getServer',
                                         headers = {'Host' : self.GOFILE_API_HOST,
                                                    'Accept' : 'application/json'})
            response = self._api_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s", response.status)
            r_body = response.read().decode(self.ENCODING)
            r_data = json.loads(r_body)
            logger.debug("Data received : %s", r_data)
            if r_data['status'] == 'ok':
                return r_data['data']['server']
            raise GofileAPIException(f"API status not ok : {r_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            self.close()

    def upload_file(self,
                    file_path : str | None = None,
                    file_content : tuple[bytes, str] | None = None,
                    folder : str | Folder | None = None,
                    upload_server : str | None = None) -> UploadResult:
        """
        Upload the provided file to the chosen destination
        The file to upload can be read from a path,
        or the binary content can be supplied directly with a filename
        If no gofile destination folder is provided, a new one will be created
        If no upload server is chosen, one will be selected automatically
        Without a token, the file will be uploaded anonymously to a guest account
        Wrapper for '/uploadFile'

        Args:
            file_path (str | None, optional): Path for the file to upload (exclusive with file_content).
                Defaults to None
            file_content (tuple[bytes, str] | None, optional): Content of the file and filename (exclusive with file_path).
                Defaults to None
            folder (str | Folder | None, optional): ID of the gofile destination folder or Folder object.
                Defaults to None
            upload_server (str | None, optional): Name of the upload server to use. Defaults to None

        Raises:
            ValueError: When both or none of file_data and file_path are given
            GofileNetworkException: In case of bad return code or network related exception
            GofileAPIException: In case of bad API status or data related exception

        Returns:
            UploadResult: Named tuple with "code", "download_page", "file_id", "filename", "md5", "parent_folder"
        """
        if folder is not None and self.token is None:
            logger.warning("Unable to use the provided folderId, token is needed")
            folder = None
        if file_path is not None and file_content is not None:
            logger.error("Ambiguous arguments file_path and file_content are mutually exclusive")
            raise ValueError("Both file_path and file_content are present when only one is needed")
        if file_path is None and file_content is None:
            logger.error("At least one of fil_path or file_content must be given")
            raise ValueError("At least one of fil_path or file_content must be given")
        if file_path is not None:
            logger.info("Reading file %s", file_path)
            with open(file_path, 'rb') as file:
                file_data = file.read()
            file_name = os.path.basename(file_path)
        else:
            file_data, file_name = file_content
        if folder is not None and isinstance(folder, Folder):
            folder = folder.content_id

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

        body = generate_formdata(self.token, folder, file_data, file_name, boundary)

        try:
            if upload_server is None:
                upload_server = self.get_upload_server()
            if folder is not None:
                logger.info("Uploading to folder %s", folder)
            logger.info("Starting upload of %s bytes to %s",
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
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s", response.status)
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
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            logger.debug("Closing connection to %s",
                         self.GOFILE_UPLOAD_HOST.format(server = upload_server))
            upload_connection.close()

    def get_content(self, content_id : str) -> Folder:
        """
        Get content information on the content id provided
        If the content id does not point to a folder an exception is raised

        Args:
            content_id (str): The content id string or code pointing to a gofile folder

        Raises:
            ValueError: If this method is called witout a token
            GofileAPIException: When the response could not be parsed or the content was not a folder
            GofileNetworkException: In case of bad return code or network related exception

        Returns:
            Folder: Object describing the content id and its children
        """
        if self.token is None:
            logger.error("A token is needed for this operation")
            raise ValueError("A token is needed for this operation")
        try:
            logger.info("Querying information on content ID : %s", content_id)
            query = parse.urlencode({'contentId' : content_id,
                                     'token' : self.token})
            logger.debug("Sending query %s", query)
            self._api_connection.request('GET',
                                         f'/getContent?{query}',
                                         headers = {'Host' : self.GOFILE_API_HOST,
                                                    'Accept' : 'application/json'})
            response = self._api_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s", response.status)
            r_body = response.read().decode(self.ENCODING)
            r_data = json.loads(r_body)
            logger.debug("Data received : %s", r_data)
            if r_data['status'] == 'ok':
                if r_data['data'] == 'not-a-folder':
                    raise GofileAPIException(f"Content ID {content_id} is not a folder")
                if r_data['data']['type'] == ContentType.FOLDER.value:
                    children = []
                    for child in [r_data['data']['contents'][child_id]
                                  for child_id in r_data['data']['childs']]:
                        if child['type'] == ContentType.FOLDER.value:
                            children.append(Folder(content_id = child['id'],
                                                   name = child['name'],
                                                   parent = child['parentFolder'],
                                                   create_time = child['createTime'],
                                                   is_owner = r_data['data']['isOwner']
                                                    if 'isOwner' in r_data['data'] else False,
                                                   is_public = child['public'],
                                                   code = child['code'],
                                                   children = None))
                        elif child['type'] == ContentType.FILE.value:
                            children.append(File(content_id = child['id'],
                                                 name = child['name'],
                                                 parent = child['parentFolder'],
                                                 create_time = child['createTime'],
                                                 download_count = child['downloadCount'],
                                                 size = child['size'],
                                                 link = child['link'],
                                                 md5 = child['md5'],
                                                 mime_type = child['mimetype'],
                                                 server = child['serverChoosen']))
                        else:
                            raise GofileAPIException(f"Content type not known {child['type']}")
                    return Folder(content_id = r_data['data']['id'],
                                  name = r_data['data']['name'],
                                  parent = r_data['data'].get('parentFolder', None),
                                  create_time = r_data['data']['createTime'],
                                  is_owner = r_data['data']['isOwner']
                                    if 'isOwner' in r_data['data'] else False,
                                  is_public = r_data['data']['public'],
                                  code = r_data['data']['code'],
                                  children = children)
                raise GofileAPIException(f"Content type not known {r_data['data']['type']}")
            raise GofileAPIException(f"API status not ok : {r_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            self.close()

    def create_folder(self, parent : str | Folder, name : str) -> Folder:
        """
        Create a folder in a gofile hierarchy

        Args:
            parent (str | Folder): The parent folder content id or Folder object
            name (str): The new folder name

        Raises:
            ValueError: If this method is called witout a token
            GofileAPIException: When the response could not be parsed
            GofileNetworkException: In case of bad return code or network related exception

        Returns:
            Folder: Object containing the newly created folder informations
        """
        if self.token is None:
            logger.error("A token is needed for this operation")
            raise ValueError("A token is needed for this operation")
        if isinstance(parent, Folder):
            parent = parent.content_id
        try:
            logger.info("Creating folder %s under folder id %s", name, parent)
            query = json.dumps({'parentFolderId' : parent,
                                'folderName' : name,
                                'token': self.token})
            logger.debug("Sending query %s", query)
            self._api_connection.request('PUT',
                                         '/createFolder',
                                         body = query,
                                         headers = {'Host' : self.GOFILE_API_HOST,
                                                    'Accept' : 'application/json',
                                                    'Content-Type' : "application/json"})
            response = self._api_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s", response.status)
            r_body = response.read().decode(self.ENCODING)
            r_data = json.loads(r_body)
            logger.debug("Data received : %s", r_data)
            if r_data['status'] == 'ok':
                return Folder(content_id = r_data['data']['id'],
                              name = r_data['data']['name'],
                              parent = r_data['data']['parentFolder'],
                              create_time = r_data['data']['createTime'],
                              is_owner = True, # By definition
                              is_public = False, # Default setting
                              code = r_data['data']['code'],
                              children = r_data['data']['childs'])
            raise GofileAPIException(f"API status not ok : {r_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            self.close()

    def set_option(self, content : str | Content, option : str, value : str) -> None:
        """
        Set an option on a specific content id to a specific value
        option can be one of : "public", "password", "description", "expire", "tags" or "directLink"
        the value must then adhere to the following :
        For "public", can be "true" or "false". The content id must be a folder
        For "password", must be the password. The content id must be a folder
        For "description", must be the description. The content id must be a folder
        For "expire", must be the expiration date in the form of unix timestamp. The content id must be a folder
        For "tags", must be a comma seperated list of tags. The content id must be a folder
        For "directLink", can be "true" or "false". The content id must be a file

        Args:
            content (str | Content): The content id or the Content object of the item to modify
            option (str): The option name
            value (str): The new value for the option

        Raises:
            ValueError: If this method is called witout a token
                        Or option is not one of the allowed values
            GofileAPIException: When the response could not be parsed
            GofileNetworkException: In case of bad return code or network related exception
        """
        if self.token is None:
            logger.error("A token is needed for this operation")
            raise ValueError("A token is needed for this operation")
        if option not in ("public", "password", "description", "expire", "tags", "directLink"):
            logger.error("The option string provided is invalid,\n\
                must be one of : public, password, description, expire, tags, directLink")
            raise ValueError("Invlid option string")
        if isinstance(content, Content):
            content = content.content_id
        try:
            logger.info("Seting option %s to %s for item %s", option, value, content)
            query = json.dumps({'contentId' : content,
                                'option' : option,
                                'value' : value,
                                'token': self.token})
            logger.debug("Sending query %s", query)
            self._api_connection.request('PUT',
                                         '/setOption',
                                         body = query,
                                         headers = {'Host' : self.GOFILE_API_HOST,
                                                    'Accept' : 'application/json',
                                                    'Content-Type' : "application/json"})
            response = self._api_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s", response.status)
            r_body = response.read().decode(self.ENCODING)
            r_data = json.loads(r_body)
            logger.debug("Data received : %s", r_data)
            if r_data['status'] == 'ok':
                return
            raise GofileAPIException(f"API status not ok : {r_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            self.close()

    def copy_content(self, destination : str | Folder, *sources : str | Content) -> None:
        """
        Copy content to a different folder

        Args:
            destination (str | Folder): The destination folder id or Folder object
            sources (str | Content): One or more file ids or Content objects to copy 

        Raises:
            ValueError: If this method is called witout a token
            GofileAPIException: When the response could not be parsed
            GofileNetworkException: In case of bad return code or network related exception
        """
        if self.token is None:
            logger.error("A token is needed for this operation")
            raise ValueError("A token is needed for this operation")
        if isinstance(destination, Folder):
            destination = destination.content_id
        sources = (source.content_id if isinstance(source, Content) else source
                   for source in sources)
        try:
            logger.info("Copying objects %s to %s", sources, destination)
            query = json.dumps({'folderIdDest' : destination,
                                'contentsId' : ','.join(sources),
                                'token': self.token})
            logger.debug("Sending query %s", query)
            self._api_connection.request('PUT',
                                         '/copyContent',
                                         body = query,
                                         headers = {'Host' : self.GOFILE_API_HOST,
                                                    'Accept' : 'application/json',
                                                    'Content-Type' : "application/json"})
            response = self._api_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s", response.status)
            r_body = response.read().decode(self.ENCODING)
            r_data = json.loads(r_body)
            logger.debug("Data received : %s", r_data)
            if r_data['status'] == 'ok':
                return
            raise GofileAPIException(f"API status not ok : {r_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            self.close()

    def delete_content(self, *contents : str | Content) -> dict[str, str]:
        """
        Delete the specified content ids

        Args:
            contents (str | Content): Content ids or Content objects to delete
        Raises:
            ValueError: If this method is called witout a token
            GofileAPIException: When the response could not be parsed
            GofileNetworkException: In case of bad return code or network related exception

        Returns:
            dict[str, str]: Input content ids as keys and operation result for each element
        """
        if self.token is None:
            logger.error("A token is needed for this operation")
            raise ValueError("A token is needed for this operation")
        contents = (content.content_id if isinstance(content, Content) else content
                   for content in contents)
        try:
            logger.info("Deleting objects %s", contents)
            query = json.dumps({'contentsId' : ','.join(contents),
                                'token': self.token})
            logger.debug("Sending query %s", query)
            self._api_connection.request('DELETE',
                                         '/deleteContent',
                                         body = query,
                                         headers = {'Host' : self.GOFILE_API_HOST,
                                                    'Accept' : 'application/json',
                                                    'Content-Type' : "application/json"})
            response = self._api_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s", response.status)
            r_body = response.read().decode(self.ENCODING)
            r_data = json.loads(r_body)
            logger.debug("Data received : %s", r_data)
            if r_data['status'] == 'ok':
                return r_data['data']
            raise GofileAPIException(f"API status not ok : {r_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            self.close()

    def get_account_details(self) -> Account:
        """
        Retrieve the current account details

        Raises:
            ValueError: If this method is called witout a token
            GofileAPIException: When the response could not be parsed
            GofileNetworkException: In case of bad return code or network related exception

        Returns:
            Account: Dataclass containing all the retrieved information
        """
        if self.token is None:
            logger.error("A token is needed for this operation")
            raise ValueError("A token is needed for this operation")
        try:
            logger.info("Querying account details")
            query = parse.urlencode({'token': self.token},
                                    quote_via = parse.quote)
            self._api_connection.request('GET',
                                         f'/getAccountDetails?{query}',
                                         headers = {'Host' : self.GOFILE_API_HOST,
                                                    'Accept' : 'application/json',
                                                    'Content-Type' : "application/x-www-form-urlencoded"})
            response = self._api_connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            logger.debug("Got response code %s", response.status)
            r_body = response.read().decode(self.ENCODING)
            r_data = json.loads(r_body)
            logger.debug("Data received : %s", r_data)
            if r_data['status'] == 'ok':
                return Account(credit = r_data['data']['credit'],
                               currency = r_data['data']['currency'],
                               currency_sign = r_data['data']['currencySign'],
                               email = r_data['data']['email'],
                               files_count = r_data['data']['filesCount'],
                               files_count_limit = r_data['data']['filesCountLimit'],
                               account_id = r_data['data']['id'],
                               premium_type = r_data['data']['premiumType'],
                               root_folder = r_data['data']['rootFolder'],
                               statistics = r_data['data']['statistics'],
                               tier = r_data['data']['tier'],
                               token = r_data['data']['token'],
                               total_30ddl_traffic = r_data['data']['total30DDLTraffic'],
                               total_30ddl_traffic_limit = r_data['data']['total30DDLTrafficLimit'],
                               total_size = r_data['data']['totalSize'],
                               total_size_limit = r_data['data']['totalSizeLimit'])
            raise GofileAPIException(f"API status not ok : {r_data['status']}")
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as decode_error:
            logger.error("API error, the response message could not be decoded, %s", decode_error)
            raise GofileAPIException() from decode_error
        finally:
            self.close()


class Helper:
    """Implement higher level functions than the raw API"""
    # TODO move exist_policy arguments to helper instance variable
    # TODO add callbacks as helper instance variables

    def __init__(self, api : API,
                 exist_policy : str | ExistPolicy = ExistPolicy.OVERWRITE) -> None:
        self.api : API = api
        if self.api.token is None:
            logger.warning("The api object does not have a token. functionnality will be limited")
        self.account : Account = None
        self.root : Folder = None
        self.exist_policy = exist_policy if isinstance(exist_policy, ExistPolicy)\
            else ExistPolicy(exist_policy)

    def init_account(self) -> None:
        """Query the account details. API token is required"""
        if self.api.token is None:
            logger.error("Unable to complete the operation, an API token is needed")
            raise ValueError("An API token is needed for this operation")
        self.account = self.api.get_account_details()

    def init_root_folder(self) -> None:
        """Query the folder structure recursively. API token is required"""
        if self.api.token is None:
            logger.error("Unable to complete the operation, an API token is needed")
            raise ValueError("An API token is needed for this operation")
        if self.account is  None:
            self.init_account()
        self.root = self.api.get_content(self.account.root_folder)
        logger.info("Initializing root folder hierarchy")
        self.init_hierarchy(self.root)

    def init_hierarchy(self, folder : Folder) -> None:
        """
        Populate the children of a folder recursively

        Args:
            folder (Folder): The root folder of the hierarchy

        Raises:
            ValueError: If no API token is set
        """
        if self.api.token is None:
            logger.error("Unable to complete the operation, an API token is needed")
            raise ValueError("An API token is needed for this operation")
        if folder.children is None:
            # Get the current folder children
            folder.children = self.api.get_content(folder.content_id).children
        if len(folder.children) == 0:
            return # Nothing to do
        for child in folder.children:
            if child.type == ContentType.FOLDER:
                self.init_hierarchy(child)

    @staticmethod
    def _get_size(response : HTTPResponse) -> tuple[int, int]:
        """
        Parse headers to determine payload size

        Args:
            response (HTTPResponse): The response object to get the headers from

        Raises:
            ValueError: If the headers are invalid or not present

        Returns:
            tuple[int, int]: Tuple in the form (size, start-byte)
        """
        content_length = response.getheader("Content-Length")
        content_range = response.getheader("Content-Range")
        size, start, size_r = None, None, None
        if content_length is not None:
            size = int(content_length)
        if content_range is not None:
            pattern = re.compile(r"^(?P<unit>[a-zA-Z]+) (?P<range>(?P<start>[0-9]+)-(?P<end>[0-9]+)|\*)/(?P<size>[0-9]+|\*)$")
            m = pattern.match(content_range)
            if m is None:
                raise ValueError("Invalid Content-Range header")
            if m.group("unit") != "bytes":
                raise ValueError("Only bytes sizes are supported")
            if m.group("size") != "*":
                size_r = int(m.group("size"))
            if m.group("range") != "*":
                start = int(m.group("start"))
        if size is not None:
            return (size, start if start is not None else 0)
        if size_r is not None:
            return (size_r, start if start is not None else 0)
        raise ValueError("No size could be obtained")
    
    @staticmethod
    def _compute_md5(source : str | os.PathLike) -> str:
        """
        return MD5 hash in hexadecimal form

        Args:
            source (str | os.PathLike): Path to file to hash

        Raises:
            OSError: In case of read error

        Returns:
            str: The hex form of the md5 hash
        """
        size = os.path.getsize(source)
        with open(source, "rb") as file:
            if size < 1000000:
                return hashlib.md5(file.read()).hexdigest()
            read = 0
            md5_hash = hashlib.md5()
            while read < size:
                if size - read < 1000000:
                    md5_hash.update(file.read())
                    return md5_hash.hexdigest()
                data = file.read(1000000)
                read += len(data)
                md5_hash.update(data)
            return md5_hash.hexdigest()

    def _download(self,
                  file : File,
                  destination : str | os.PathLike,
                  exist_size : int = 0) -> None:
        """
        Actually perform the download

        Args:
            file (File): File to download
            destination (str | os.PathLike): Destination file
            exist_size (int, optional): SIze of file already on disk. Defaults to 0.

        Raises:
            GofileNetworkException: In case of network failure
            OSError: When unable to write to disk
        """
        try:
            host = API.GOFILE_DOWNLOAD_HOST.format(server = file.server)
            logger.debug("Initiating connection to %s", host)
            connection = HTTPSConnection(host)
            headers = {'Host' : host,
                       'Cookie' : f'accountToken={self.api.token}'}
            if exist_size > 0 and file.size - exist_size > 0:
                logger.warning("Trying to resume download at byte %s", exist_size)
                headers['Range'] = f"bytes={exist_size}-"
            connection.request("GET",
                                parse.urlparse(file.link).path,
                                headers = headers)
            response = connection.getresponse()
            if not 200 <= response.status <= 299:
                logger.error("HTTP error, the server replied with code %s", response.status)
                logger.debug("Data received : %s", response.read())
                raise GofileNetworkException(f"HTTP Error code {response.status}")
            with open(destination, "ab") as dest_file:
                size, start = self._get_size(response)
                dest_file.seek(start)
                logger.info("Downloading %s bytes to %s", size, file.name)
                buffer = bytearray(size) if size < 1000000 else bytearray(1000000)
                written = 0
                while written < size:
                    n_read = response.readinto(buffer)
                    n_written = dest_file.write(buffer)
                    if n_read > n_written:
                        logger.error("Unable to write to file %s", destination)
                        raise OSError("Unable to write to file")
                    written += n_written
                    if 0 < size - written < len(buffer):
                        buffer = bytearray(size - written)
        except (HTTPException, ConnectionError, TimeoutError) as network_error:
            logger.error("Network error, %s", network_error)
            raise GofileNetworkException() from network_error
        finally:
            logger.debug("Closing connection to %s", host)
            connection.close()

    def download(self,
                 file : File,
                 destination : str | os.PathLike,
                 md5 : bool = True,
                 partfile : bool = False) -> None:
        """
        Download a file to local storage
        To change the filename of the downloaded file,
        change the name attribute of the argument File object
        
        Notes for exist_policy:
        "overwrite" always overwrite and starts every download from the first byte
        "skip" always skips if the final filename is present and starts from the first byte otherwise
        "resume" skips completed downloads and resumes partial ones, if partfiles are used, only
            the partfile size is checked and the download is skipped entirely if the final file is
            present

        Args:
            file (File): The file object to download
            destination (str | os.PathLike): Local path to destination directory
            md5 (bool, optional): Chack the md5 sum of downloaded files. Defaults to True.
            partifle (bool, optional): Mark unfinished downloads with .part suffix. Defaults to False.

        Raises:
            FileExistsError: If destination is a file
            GofileNetworkException: In case of natwork error
            OSError: If the data could not be written to the local storage
        """
        if os.path.isfile(destination):
            logger.error("Destination %s is a file", destination)
            raise FileExistsError("Destination is a file")
        os.makedirs(destination, exist_ok = True)
        destination = os.path.join(destination, file.name)
        exist_size = 0
        # Check if should skip
        if os.path.isfile(destination) \
            and (self.exist_policy == ExistPolicy.SKIP \
                 or self.exist_policy == ExistPolicy.RESUME and partfile):
            logger.warning("File %s already exists, skipping", file.name)
            return
        if partfile:
            destination += ".part"
        # Check if should resume
        if os.path.isfile(destination) and self.exist_policy == ExistPolicy.RESUME:
            exist_size = os.path.getsize(destination)
            if exist_size == file.size:
                logger.warning("File %s already exists, skipping", file.name)
                return
            logger.warning("File %s already exists, resuming from byte %s", file.name, exist_size)
        self._download(file, destination, exist_size)
        if md5:
            md5_hash = self._compute_md5(destination)
            if md5_hash != file.md5:
                logger.error("MD5 hash not equal")
                logger.debug("%s != %s", file.md5, md5_hash)
                raise GofileException("MD5 hash not equal")
        if partfile:
            os.rename(destination, destination.removesuffix(".part"))
        logger.info("File %s downloaded successfully",
                    os.path.basename(destination).removesuffix(".part"))

    def traverse_hierarchy(self,
                           folder : Folder,
                           basename : str | None = None,
                           use_codes : bool = False) -> list[tuple[str, File]]:
        """
        Recursively generate the list of files in a hierachy
        Each tuple in the return list contains a path built from the folder names and a File object
        Because GoFile allows different folders with the same name, two fils might have an identical
        path while residing in two different GoFile folders.

        Args:
            folder (Folder): The root folder of the hierarchy
            basename (str | None, optional): A base path prefix to append before each paths.
                Defaults to None.
            use_codes (bool, optional): Use the folder codes instead of names, prevents overlaps.
                Defaults to False.

        Returns:
            list[tuple[str, File]]: List of tuple (path, File object)
        """
        if basename is None:
            basename = ""
        res = []
        if folder.children is None:
            self.init_hierarchy(folder)
        for child in folder.children:
            if child.type == ContentType.FILE:
                res.append((basename, child))
            elif use_codes:
                res += self.traverse_hierarchy(child, os.path.join(basename, child.code))
            else:
                res += self.traverse_hierarchy(child, os.path.join(basename, child.name))
        return res

    def download_folder(self,
                        folder : str | Folder,
                        destination : str | os.PathLike,
                        flatten : bool = False,
                        md5 : bool = False,
                        partfile : bool = False) -> None:
        """
        Download a folder content and its children content recursively

        Args:
            folder (str | Folder): The root folder to download
            destination (str | os.PathLike): The destination folder
            flatten (bool, optional): Do not reproduce the folder structure. Defaults to False.
            md5 (bool, optional): Chack the md5 sum of downloaded files. Defaults to False.

        Raises:
            ValueError: If the destination is not a valid folder
        """
        if os.path.isfile(destination):
            logger.error("The destination points to an already existing file")
            raise ValueError("Destination can not be a file")
        os.makedirs(destination, exist_ok = True)
        if not isinstance(folder, Folder):
            folder = self.api.get_content(folder)
        to_download = self.traverse_hierarchy(folder, folder.name)
        for suffix, file in to_download:
            self.download(file,
                          destination if flatten else os.path.join(destination, suffix),
                          md5,
                          partfile)
        logger.info("Folder %s downloaded successfully", folder.name)


def cli_download(args : Namespace) -> int:
    """Download one or multiple gofile items"""
    items = []
    for item in args.items:
        content_id = parse_url(item)
        if content_id is None: # url parsing failed, assume the item is a valid id
            content_id  = item
        items.append(content_id)
    if args.token is None:
        logger.error("A token is required for this operation")
        return 1
    api = API(args.token)
    helper = Helper(api,
                    ExistPolicy.OVERWRITE if args.overwrite else ExistPolicy.RESUME)
    logger.info("Downloading %s items", len(items))
    for item in items:
        helper.download_folder(item,
                               args.destination,
                               args.flatten,
                               args.md5,
                               args.partfile)
    return 0


def main() -> int:
    """Main function for CLI functionnality"""
    parser_command = ArgumentParser(description = "gofile.io python client",
                                    epilog = '')

    parser_command.add_argument("-v", "--verbose",
                                action = "count",
                                default = 0,
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
                                 help = "Items to download, can be a complete URL or a folder content ID")

    parser_download.add_argument("-d", "--destination",
                                 help = "Target directory for the downloaded files/folders, defaults to current working directory",
                                 default = os.getcwd())

    parser_download.add_argument("-f", "--flatten",
                                 help = "Download the remote files without reproducing the folder hierarchy")

    parser_download.add_argument("-p", "--partfile",
                                 action = "store_true",
                                 help = "Add '.part' to the end of incomplete files")

    parser_download.add_argument("-o", "--overwrite",
                                 action = "store_true",
                                 help = "Always overwrite and start incomplete download from scratch")

    parser_download.add_argument("--md5",
                                 action = "store_true",
                                 help = "Verify the md5 checksum after download")

    parser_download.add_argument("-b", "--batch",
                                 help = "Read a text file and download one item for each line")

    args = parser_command.parse_args()

    _init_logger(args.verbose)

    # Call the handler function for the selected subcommand
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
