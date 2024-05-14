import uuid
import re
import os

def extract_asset_version(input_string):
    # Define a regular expression pattern to match the asset_version value
    pattern = r"asset_version=(\d+)"

    # Use re.search to find the first match in the input string
    match = re.search(pattern, input_string)

    # Check if a match was found and extract the value
    if match:
        asset_version_value = match.group(1)
        return asset_version_value
    else:
        return None  # Return None if asset version value is not found


def generate_comment(asset_version_url, logger):
    comment = (
        "\n"
        "**********************************************************************************\n"
        "Hello, Finite State is uploading your scan!. \n"
        "Please, click on next link ({asset_version_url}) to see the progress of the analysis over your file.\n"
        "[Finite State](https://platform.finitestate.io/) \n"
        "**********************************************************************************\n"
        "\n"
    )
    formatted_comment = comment.format(asset_version_url=asset_version_url)
    logger.info(formatted_comment)
    return formatted_comment
    
