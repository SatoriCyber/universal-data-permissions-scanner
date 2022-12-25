from typing import Callable


def paginate_response_list(method: Callable, key_to_append_list: str, **kwargs):
    """
    Paginate through a list of items from the AWS Management Console.

    method: The method to call on the client to get a page of items.
    key_to_append_list: the key in the response dictionary to append
    kwargs: Additional keyword arguments to pass to the method.

    Returns a list of all the items in the list.
    """

    # Initialize the pagination variables
    marker = None
    items = []

    # Loop until there are no more items to paginate
    while True:
        # Get a page of items
        if marker:
            kwargs["Marker"] = marker
        response = method(**kwargs)

        # Append the items to the list
        items += response[key_to_append_list]

        # If there are more items, get the marker for the next page
        if response["IsTruncated"]:
            marker = response["Marker"]
        else:
            break

    return items
