def capitalize_first_letter(string):
    """Capitalize the first letter of the string.

    Args:
        string(str): string to capitalize

    """
    if len(string) == 1:
        return string.upper()
    return string[0].upper() + string[1:]


def capitalize_key_for_list(array):
    """ Capitalize keys of dictionary in list

    Args:
        array(list): list to capitalize
    """
    capitalized = []
    for i in array:
        if isinstance(i, dict):
            capitalized.append(capitalize_key(i))
        elif isinstance(i, list):
            capitalized.append(capitalize_key_for_list(i))
        else:
            capitalized.append(i)
    return capitalized


def capitalize_key(dictionary):
    """Recursively capitalize the first letter of the dictionary keys.

    Args:
        dictionary(dict): dictionary that capitalizes keys

    """
    capitalized = {}
    for k, v in dictionary.items():
        if isinstance(v, dict):
            capitalized[capitalize_first_letter(k)] = capitalize_key(v)
        elif isinstance(v, list):
            capitalized[capitalize_first_letter(k)] = \
                capitalize_key_for_list(v)
        else:
            capitalized[capitalize_first_letter(k)] = v
    return capitalized
