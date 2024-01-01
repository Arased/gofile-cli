"""
gofile.io python client, provides both CLI and library functionnality.
"""
import logging
import os
import sys
from argparse import ArgumentParser, Namespace


logger = logging.getLogger(__name__)


def _init_logger(level : int):
    """
    Initialize the module logger for CLI

    Args:
        level (int): Level of verbosity between 0 and 2 (inclusive).
                     Maps in order to WARNING, INFO, DEBUG.
                     Integers > 2 behave identically to 2.
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
