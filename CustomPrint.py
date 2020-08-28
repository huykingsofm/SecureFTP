from DefinedError import InvalidArgument

class CustomPrint(object):
    def __init__(self, prefix, print_type_array, verbosities):
        self.print_type_array = print_type_array
        self.verbosities = verbosities
        for verbosity in verbosities:
            if verbosity not in print_type_array:
                raise InvalidArgument("Allowed verbosity must be in the list")

        self.prefix = prefix

    def __call__(self, data, print_type):
        if print_type not in self.print_type_array:
            raise InvalidArgument(f"Print type must be one of {self.print_type_array}, but get {print_type} in {data}")
        
        if print_type not in self.verbosities:
            return

        if self.prefix:
            data = f"{print_type} from {self.prefix}: {data}"
        print(data)

class StandardPrint(CustomPrint):
    def __init__(self, prefix, verbosities):
        super().__init__(prefix, ["error", "warning", "notification"], verbosities)