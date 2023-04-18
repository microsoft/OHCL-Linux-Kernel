import argparse

# Common, reusable.
arg_parser_common = argparse.ArgumentParser(add_help=False)
arg_parser_common.add_argument('-v', '--verbose', action='count',
                               default=0, required=False,
                               help="Verbose output.")


# Top level.
def create_arg_parser(*args, **kwargs):
    try:
        kwargs["parents"].append(arg_parser_common)
    except:  # noqa: E722
        kwargs["parents"] = [arg_parser_common]
    return argparse.ArgumentParser(*args, **kwargs)
