gofilecli is both a cli application and a library for interacting with the gofile.io api.

[Installation]

Clone the project and execute
'''pip install .'''
inside the project directory

[Usage]

As a CLI application, launch
'''gofilecli --help'''
to see all the available options and their usage

As a library the module defines two main clesses:
API, represent the api connection and implements the basic api endpoints as methods
Helper, wraps around an API instance and provide higher level functionnality
and some not directly related to the API (such as file download)
